### Title
Unauthenticated Thundering Herd DoS via Unbounded Concurrent `getNodes()` Requests Exhausting Database

### Summary
`NetworkController.getNodes()` accepts unauthenticated gRPC requests with no application-level rate limiting, no caching of results, and no request deduplication. Every call independently executes multiple database queries against the address book and node stake tables. An attacker opening many connections and flooding the endpoint can exhaust the database connection pool, making address book data unavailable to legitimate consensus network nodes.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) directly delegates every incoming request to `networkService::getNodes` with no guard:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java:33-38
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)   // ← no rate limit, no cache, no dedup
            .map(this::toNodeAddress)
            .onErrorMap(ProtoUtil::toStatusRuntimeException)
            .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

`NetworkServiceImpl.getNodes()` (lines 55–77) then fires **at minimum three independent DB queries per call** before any paging begins:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java:61-66
long addressBookTimestamp = addressBookRepository
        .findLatestTimestamp(fileId.getId())          // DB query 1
        .orElseThrow(() -> new EntityNotFoundException(fileId));
long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp()  // DB query 2
        .orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp); // DB query 3
```

Then paging issues additional queries per page via `addressBookEntryRepository.findByConsensusTimestampAndNodeId()` (line 85–86).

**Root cause / failed assumption:**

`AddressBookProperties` defines `cacheExpiry` (default 2 s) and `cacheSize` (default 50) fields, indicating caching was intended:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java:20-23
private Duration cacheExpiry = Duration.ofSeconds(2);
@Min(0)
private long cacheSize = 50L;
```

However, `NetworkServiceImpl.getNodes()` never uses these fields — there is no `@Cacheable` annotation, no Caffeine/Guava cache, and no result sharing between concurrent identical requests. The properties are consumed only for `pageDelay` and `pageSize`. The assumption that caching would protect the database is broken.

**Only existing server-side guard:**

```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java:14
private int maxConcurrentCallsPerConnection = 5;
```

This limits concurrent calls **per connection**, not total connections or total requests globally. An attacker opens `N` connections and gets `5N` concurrent DB-hitting calls. No `maxConnections`, no `maxConnectionAge`, no IP-based throttle, and no authentication are configured at the application layer.

The optional GCP infrastructure `maxRatePerEndpoint: 250` (charts/hedera-mirror-grpc/values.yaml:69) is not an application control, requires GCP gateway deployment, and 250 req/s × 3+ DB queries each is still a significant load.

### Impact Explanation

Each `getNodes()` call issues 3+ synchronous DB queries plus paging queries. With thousands of concurrent connections (each allowed 5 calls), the database connection pool is exhausted and query latency spikes. The address book endpoint is the bootstrap mechanism by which Hedera consensus nodes discover their peers. Sustained unavailability of this endpoint prevents nodes from obtaining current address book data, which can disrupt peer discovery and network participation. Severity: **High** (availability impact on critical network infrastructure data, no authentication barrier).

### Likelihood Explanation

The gRPC port (5600) is publicly exposed per the service definition and Helm chart. No credentials, tokens, or TLS client certificates are required. The attack requires only a standard gRPC client library and the ability to open many TCP connections — trivially achievable from a single machine or a small botnet. The attack is repeatable and stateless (no session to maintain). The `AddressBookQuery` proto message is minimal (just a `FileID` and optional `limit`), so request construction is trivial.

### Recommendation

1. **Implement the intended caching**: Apply `@Cacheable` (Spring Cache + Caffeine) on `NetworkServiceImpl.getNodes()` using the already-defined `cacheExpiry` and `cacheSize` properties, so identical requests within the TTL window share a single DB result.
2. **Add a global gRPC rate limiter**: Implement a `ServerInterceptor` (analogous to the web3 `ThrottleManagerImpl`) that enforces a global requests-per-second ceiling for the `NetworkService/getNodes` method, returning `RESOURCE_EXHAUSTED` when exceeded.
3. **Limit total connections**: Configure `NettyServerBuilder.maxConnectionAge()` and consider a total connection cap to prevent connection-multiplication attacks.
4. **Enforce infrastructure controls unconditionally**: Make the GCP `maxRatePerEndpoint` (or equivalent) a required deployment constraint, not an optional one.

### Proof of Concept

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor
# proto stubs for com.hedera.mirror.api.proto.NetworkService

def flood(stub):
    req = AddressBookQuery(file_id=FileID(file_num=102))
    try:
        list(stub.getNodes(req))  # each call triggers 3+ DB queries
    except:
        pass

channels = [grpc.insecure_channel("mirror-node-grpc:5600") for _ in range(500)]
stubs   = [NetworkServiceStub(ch) for ch in channels]

with ThreadPoolExecutor(max_workers=2500) as ex:
    while True:  # sustain indefinitely
        for stub in stubs:
            for _ in range(5):   # maxConcurrentCallsPerConnection = 5
                ex.submit(flood, stub)
# Result: 500 connections × 5 concurrent = 2500 simultaneous DB query sets
# → DB connection pool exhausted → legitimate getNodes() calls time out
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-43)
```java
    public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L55-77)
```java
    public Flux<AddressBookEntry> getNodes(AddressBookFilter filter) {
        var fileId = filter.getFileId();
        if (!getValidFileIds().contains(fileId)) {
            throw new IllegalArgumentException(INVALID_FILE_ID);
        }

        long addressBookTimestamp = addressBookRepository
                .findLatestTimestamp(fileId.getId())
                .orElseThrow(() -> new EntityNotFoundException(fileId));
        long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp().orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
        var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp);
        var context = new AddressBookContext(addressBookTimestamp, nodeStakeMap);

        return Flux.defer(() -> page(context))
                .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                        .jitter(0.5)
                        .withFixedDelay(addressBookProperties.getPageDelay())
                        .withScheduler(Schedulers.boundedElastic()))
                .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Querying for address book: {}", filter))
                .doOnComplete(() -> log.info("Retrieved {} nodes from the address book", context.getCount()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L79-107)
```java
    private Flux<AddressBookEntry> page(AddressBookContext context) {
        return transactionOperations.execute(t -> {
            var addressBookTimestamp = context.getAddressBookTimestamp();
            var nodeStakeMap = context.getNodeStakeMap();
            var nextNodeId = context.getNextNodeId();
            var pageSize = addressBookProperties.getPageSize();
            var nodes = addressBookEntryRepository.findByConsensusTimestampAndNodeId(
                    addressBookTimestamp, nextNodeId, pageSize);
            var endpoints = new AtomicInteger(0);

            nodes.forEach(node -> {
                // Override node stake
                node.setStake(nodeStakeMap.getOrDefault(node.getNodeId(), 0L));
                // This hack ensures that the nested serviceEndpoints is loaded eagerly and voids lazy init exceptions
                endpoints.addAndGet(node.getServiceEndpoints().size());
            });

            if (nodes.size() < pageSize) {
                context.completed();
            }

            log.info(
                    "Retrieved {} address book entries and {} endpoints for timestamp {} and node ID {}",
                    nodes.size(),
                    endpoints,
                    addressBookTimestamp,
                    nextNodeId);
            return Flux.fromIterable(nodes);
        });
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L18-37)
```java
    @DurationMin(millis = 500L)
    @NotNull
    private Duration cacheExpiry = Duration.ofSeconds(2);

    @Min(0)
    private long cacheSize = 50L;

    @DurationMin(minutes = 1L)
    @NotNull
    private Duration nodeStakeCacheExpiry = Duration.ofHours(24);

    @Min(0)
    private long nodeStakeCacheSize = 5L;

    @DurationMin(millis = 100L)
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
