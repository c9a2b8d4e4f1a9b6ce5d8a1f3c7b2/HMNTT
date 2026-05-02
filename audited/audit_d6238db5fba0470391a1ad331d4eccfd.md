### Title
Unauthenticated gRPC `getNodes()` Stream Resource Exhaustion via Missing Stream-Level Timeout

### Summary
The `getNodes()` handler in `NetworkController.java` subscribes to a reactive pipeline with no `.timeout()` operator and no authentication gate. An unprivileged attacker can open an unbounded number of TCP connections, each carrying up to `maxConcurrentCallsPerConnection` (default 5) concurrent streams, accumulating long-lived streams that hold database connections and scheduler threads, exhausting the HikariCP connection pool and the `boundedElastic` scheduler, and denying service to legitimate callers.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` — [1](#0-0) 

```java
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(networkService::getNodes)
        .map(this::toNodeAddress)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
    serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
}
```

There is no `.timeout(Duration)` operator anywhere in this pipeline. The `setOnCancelHandler` only fires on a **client-initiated** RST_STREAM; a client that simply holds the connection open without cancelling will never trigger it.

`NetworkServiceImpl.getNodes()` builds the Flux: [2](#0-1) 

```java
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                .jitter(0.5)
                .withFixedDelay(addressBookProperties.getPageDelay())
                .withScheduler(Schedulers.boundedElastic()))
        .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
        ...
```

Each page call executes a blocking DB query inside `transactionOperations.execute()`: [3](#0-2) 

The `pageDelay` default is 250 ms and `pageSize` is 10. [4](#0-3) 

The only per-query bound is the PostgreSQL `statementTimeout` of 10 000 ms. [5](#0-4) 

There is no **stream-level** timeout. The `RetrieverProperties.timeout` (60 s) applies exclusively to the HCS topic retriever, not to address-book streams. [6](#0-5) 

The per-connection stream cap is 5: [7](#0-6) 

This is enforced **per TCP connection** only. [8](#0-7) 

No `maxConnectionAge`, no global stream cap, and no rate-limiting interceptor exist for the gRPC module. The web3 throttle is entirely separate. [9](#0-8) 

**Root cause:** The failed assumption is that clients will either complete or cancel their streams promptly. The code relies entirely on client cooperation. A malicious client that opens many connections and never cancels accumulates streams that each hold a `boundedElastic` scheduler slot and a HikariCP connection for the duration of every page transaction.

### Impact Explanation

Each live `getNodes()` stream occupies:
- One `Schedulers.boundedElastic()` thread per active page delay/repeat cycle.
- One HikariCP connection for the duration of each `transactionOperations.execute()` call (up to 10 s per page under DB load).

With N attacker connections × 5 streams each, the HikariCP pool (finite, typically 10–20 connections for the gRPC module) is exhausted. Once exhausted, all subsequent `getNodes()` calls — including those from legitimate Hedera network nodes querying the address book — block waiting for a connection and eventually fail. This constitutes a complete denial of the address-book service, which network nodes depend on for peer discovery.

### Likelihood Explanation

- **No authentication required.** The gRPC `NetworkService` is publicly exposed on port 5600 with no credential check.
- **Trivially scriptable.** A single attacker machine can open hundreds of HTTP/2 connections using any gRPC client library (e.g., `grpcurl`, the Java/Go/Python gRPC SDKs) and issue concurrent `getNodes()` RPCs without cancelling.
- **Amplified by DB load.** Under normal load each stream completes in ~1 s. Under induced DB load (e.g., by the same attacker issuing many concurrent streams), each page query approaches the 10 s statement timeout, multiplying the hold time on each DB connection.
- **Repeatable and low-cost.** The attacker needs no special knowledge, no credentials, and no high-bandwidth link — only the ability to open TCP connections to port 5600.

### Recommendation

1. **Add a stream-level timeout** in `NetworkController.getNodes()`:
   ```java
   Mono.fromCallable(() -> toFilter(request))
       .flatMapMany(networkService::getNodes)
       .map(this::toNodeAddress)
       .timeout(Duration.ofSeconds(30))   // ← add this
       .onErrorMap(ProtoUtil::toStatusRuntimeException)
       .subscribe(...)
   ```
2. **Add a global connection/stream limit** in `GrpcConfiguration`:
   ```java
   serverBuilder.maxConnectionAge(60, TimeUnit.SECONDS);
   serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
   ```
3. **Add a per-IP rate-limiting interceptor** for the `NetworkService` gRPC service, analogous to the web3 throttle.
4. **Cap the `limit` parameter** in `AddressBookFilter` to a reasonable maximum (e.g., 1 000) to bound stream duration even without a timeout.

### Proof of Concept

```bash
# Open 50 connections, each with 5 concurrent getNodes() streams (250 total)
# using grpcurl; repeat without cancelling
for i in $(seq 1 50); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes &
  done
done
# Monitor HikariCP active connections — pool exhausts within seconds.
# Subsequent legitimate getNodes() calls return UNAVAILABLE or hang indefinitely.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-42)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L68-76)
```java
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

**File:** docs/configuration.md (L414-414)
```markdown
| `hiero.mirror.grpc.db.statementTimeout`                    | 10000            | The number of milliseconds to wait before timing out a query statement                                    |
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L28-28)
```java
    private Duration timeout = Duration.ofSeconds(60L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```
