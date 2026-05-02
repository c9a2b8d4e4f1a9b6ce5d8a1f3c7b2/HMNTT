### Title
No Global Concurrent Call Limit Allows Multi-Connection Resource Exhaustion on gRPC Transaction Retrieval

### Summary
`grpcServerConfigurer()` in `GrpcConfiguration.java` configures only a per-connection concurrent call limit (`maxConcurrentCallsPerConnection = 5`) with no global connection count cap or global concurrent call ceiling. An unauthenticated attacker can open an unbounded number of TCP connections to port 5600, each carrying up to 5 concurrent streaming calls, multiplying total server load without restriction and exhausting the shared thread pool, database connection pool, and memory.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35, `grpcServerConfigurer()`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14:

```java
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause:** The `NettyServerBuilder` is customized with only two settings: a shared executor and a per-connection call cap. No call to `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnections(...)`, or any equivalent global semaphore is present. The `NettyProperties` class exposes only `maxConcurrentCallsPerConnection` — there is no `maxConnections` or `maxGlobalConcurrentCalls` field.

**Failed assumption:** The design assumes that limiting calls per connection is sufficient to bound total server load. This assumption fails because the number of connections is itself unbounded.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (no authentication required — the gRPC API is public).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` (or `getNodes`) streaming calls.
3. Total active calls = N × 5, all dispatched to the shared `applicationTaskExecutor`.
4. Each active call drives the `RetrieverService` to poll the database at `pollingFrequency = 2s` with `maxPageSize = 1000` rows per query.
5. With a large N, the HikariCP database connection pool is saturated, the executor queue grows unboundedly (Spring's default `ThreadPoolTaskExecutor` uses an unbounded `LinkedBlockingQueue`), and heap memory is consumed by queued tasks and buffered result sets.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` only throttles a single TCP connection; it is trivially bypassed by opening additional connections.
- The `applicationTaskExecutor` thread pool provides natural backpressure on CPU threads but does not reject or drop queued tasks — it queues them indefinitely, enabling memory exhaustion.
- The GCP `maxRatePerEndpoint: 250` in `charts/hedera-mirror-grpc/values.yaml` is an optional infrastructure-layer control that is disabled by default (`gateway.gcp.enabled: true` only when GCP gateway is deployed) and does not apply to direct pod access or non-GCP deployments.
- No IP-based rate limiting, no per-IP connection limit, and no authentication gate exists at the gRPC application layer.

### Impact Explanation
An unauthenticated attacker can cause a full denial-of-service of the transaction retrieval system:
- **Database exhaustion:** Concurrent DB queries from N×5 streaming calls saturate the HikariCP pool, causing all legitimate queries to time out (`statementTimeout = 10000ms`).
- **Memory exhaustion:** Unbounded executor queue growth leads to OOM and JVM crash.
- **Thread starvation:** Long-lived streaming subscriptions hold executor threads, starving legitimate subscribers.
- Severity: **High** — complete loss of availability for all users of the mirror node gRPC API, with no authentication barrier to exploitation.

### Likelihood Explanation
- **Precondition:** Network access to port 5600. The gRPC API is a public-facing service by design (it serves Hedera clients querying topic messages).
- **Skill required:** None beyond a basic gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or a simple loop with `ManagedChannelBuilder`).
- **Repeatability:** Fully repeatable and automatable; a single script can open hundreds of connections in seconds.
- **Detection difficulty:** Low — the attack looks like many legitimate subscribers until resource exhaustion occurs.

### Recommendation
1. **Add a global connection limit** to the `NettyServerBuilder` in `grpcServerConfigurer()`:
   ```java
   serverBuilder.maxConnectionAge(Duration.ofMinutes(10), TimeUnit.MILLISECONDS);
   serverBuilder.maxConnectionIdle(Duration.ofMinutes(5), TimeUnit.MILLISECONDS);
   ```
   And add a `maxConnections` field to `NettyProperties` mapped to `serverBuilder`'s connection limit (via a `ServerTransportFilter` or a Netty channel option).
2. **Add a global concurrent call semaphore** via a gRPC `ServerInterceptor` that tracks total active calls across all connections and returns `RESOURCE_EXHAUSTED` when a configurable ceiling is reached.
3. **Bound the executor queue** by configuring `spring.task.execution.pool.queue-capacity` to a finite value so that excess tasks are rejected rather than queued indefinitely.
4. **Add per-IP connection rate limiting** at the application layer (e.g., via a `ServerTransportFilter` tracking connections per remote address).
5. Expose `maxConnections` and `maxGlobalConcurrentCalls` as configurable properties in `NettyProperties` alongside the existing `maxConcurrentCallsPerConnection`.

### Proof of Concept
```bash
# Open 200 connections, each with 5 concurrent subscribeTopic streaming calls
# (1000 total concurrent calls) using grpcurl in parallel

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Monitor server: DB connections will saturate, executor queue will grow,
# and legitimate clients will receive UNAVAILABLE or timeout errors.
wait
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```
