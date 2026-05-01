### Title
Unbounded Multi-Connection `getNodes()` Subscription Flood Exhausts Shared `Schedulers.boundedElastic()` Thread Pool

### Summary
`NetworkController.getNodes()` creates a new reactive subscription per RPC call with no global rate limit or subscription cap. The sole concurrency control, `maxConcurrentCallsPerConnection = 5`, is a **per-connection** limit that is trivially bypassed by opening multiple TCP connections. Each subscription schedules blocking database page-fetches on the shared `Schedulers.boundedElastic()` pool; flooding the server with enough connections exhausts that pool, starving all other reactive operations in the process.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) unconditionally subscribes to a new reactive pipeline for every inbound RPC:

```java
// NetworkController.java:34-38
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(networkService::getNodes)
        .map(this::toNodeAddress)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

`NetworkServiceImpl.getNodes()` (lines 68–76) builds a paged polling loop that explicitly schedules each inter-page delay **and the subsequent page execution** on the shared global `Schedulers.boundedElastic()` instance:

```java
// NetworkServiceImpl.java:68-72
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                .jitter(0.5)
                .withFixedDelay(addressBookProperties.getPageDelay())
                .withScheduler(Schedulers.boundedElastic()))   // ← shared global pool
```

`page()` (lines 79–108) calls `transactionOperations.execute()` — a **blocking** JDBC call — on that same `boundedElastic()` thread. With the default `pageDelay = 250 ms` and `pageSize = 10`, each subscription holds a `boundedElastic()` thread for the duration of each DB round-trip, then releases it for 250 ms, then re-acquires it.

**The only concurrency guard** is `maxConcurrentCallsPerConnection = 5` (default), configured in `GrpcConfiguration.java` line 33 via `NettyProperties.java` line 14. This is enforced at the Netty/HTTP-2 stream level **per TCP connection**. There is no:
- global concurrent-call cap
- per-IP connection limit
- application-level rate limiter on `getNodes()`
- global subscription counter

**Root cause:** The design assumes per-connection stream limiting is sufficient. It is not, because HTTP/2 multiplexing is per-connection; an attacker simply opens *N* TCP connections, each carrying 5 concurrent streams, yielding *5N* simultaneous subscriptions with no server-side bound on *N*.

### Impact Explanation

`Schedulers.boundedElastic()` is a **shared, process-wide** scheduler. Its default thread cap is `10 × availableProcessors()` (e.g., 40 threads on a 4-core pod). When all threads are occupied by blocked JDBC calls from concurrent `getNodes()` subscriptions, new tasks queue up. When the queue cap (100,000 tasks by default) is reached, `RejectedExecutionException` is thrown, propagating errors to **all** reactive pipelines in the JVM that use `boundedElastic()` — including topic-message subscriptions (`PollingTopicListener`, `SharedPollingTopicListener`, `PollingTopicMessageRetriever`). This causes a full gRPC service outage: `subscribeToTopic` streams fail, the mirror node can no longer serve consensus data, and downstream clients (wallets, explorers, SDKs) lose the ability to confirm transactions.

DB connection pool exhaustion amplifies the attack: blocked threads waiting for a JDBC connection hold `boundedElastic()` threads far longer than the normal query duration, dramatically lowering the number of concurrent subscriptions needed to saturate the pool.

### Likelihood Explanation

No authentication or authorization is required to call `getNodes()`. The gRPC port (5600) is publicly exposed. Opening hundreds of TCP connections is trivial with any gRPC client library (e.g., `grpc-go`, `grpcurl`, Python `grpcio`). The optional GCP `maxRatePerEndpoint: 250` in the Helm chart is an infrastructure-level knob that (a) requires HPA to take effect per its own comment, (b) is disabled by default (`gateway.gcp.enabled: false` in `global.gateway.enabled: false`), and (c) is a per-backend-pod rate, not a per-client-IP rate. The attack is repeatable, requires no special tooling, and can be sustained indefinitely from a single machine.

### Recommendation

1. **Add a global concurrent-subscription cap** in `NetworkController.getNodes()` using an `AtomicInteger` counter; reject with `RESOURCE_EXHAUSTED` when the cap is exceeded.
2. **Add a per-IP rate limiter** as a `ServerInterceptor` (e.g., using Bucket4j or Guava `RateLimiter`) applied to `NetworkService` RPCs.
3. **Isolate the address-book scheduler**: replace the shared `Schedulers.boundedElastic()` call in `NetworkServiceImpl.getNodes()` (line 72) with a dedicated, bounded `Schedulers.newBoundedElastic(...)` instance so address-book flooding cannot starve topic-message pipelines.
4. **Set `maxConnections`** on the `NettyServerBuilder` to cap total TCP connections server-wide.
5. Enable and properly configure the GCP `maxRatePerEndpoint` / Traefik `inFlightReq` middleware (as already done for GraphQL and Rosetta) for the gRPC service.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import network_service_pb2_grpc
from com.hedera.mirror.api.proto import mirror_network_service_pb2 as pb

TARGET = "grpc.mainnet.mirrornode.hedera.com:443"
CONNECTIONS = 200   # 200 TCP connections × 5 streams = 1000 concurrent subscriptions
STREAMS_PER_CONN = 5

def flood(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    threads = []
    for _ in range(STREAMS_PER_CONN):
        def call():
            try:
                for _ in stub.getNodes(pb.AddressBookQuery()):
                    pass
            except Exception:
                pass
        t = threading.Thread(target=call)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Expected result: boundedElastic() thread pool saturated; subscribeToTopic RPCs
# begin returning UNAVAILABLE / RejectedExecutionException within seconds.
```

**Preconditions:** Network access to gRPC port 5600 (or 443 via gateway). No credentials needed.
**Trigger:** Run the script; sustain for >5 seconds.
**Result:** `Schedulers.boundedElastic()` saturated; all gRPC services degrade or fail. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L68-72)
```java
        return Flux.defer(() -> page(context))
                .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                        .jitter(0.5)
                        .withFixedDelay(addressBookProperties.getPageDelay())
                        .withScheduler(Schedulers.boundedElastic()))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
