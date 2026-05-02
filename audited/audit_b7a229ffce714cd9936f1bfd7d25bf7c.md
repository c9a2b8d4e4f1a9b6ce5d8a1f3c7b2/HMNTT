### Title
Unbounded gRPC Connection Acceptance with Shared Thread Pool Enables Executor Exhaustion DoS

### Summary
`grpcServerConfigurer()` in `GrpcConfiguration.java` assigns the Spring Boot `applicationTaskExecutor` as the sole executor for all gRPC RPC handlers and sets `maxConcurrentCallsPerConnection = 5`, but imposes no limit on the total number of accepted connections. Because Spring Boot's default `ThreadPoolTaskExecutor` has a core pool size of 8 with an unbounded queue, an unprivileged attacker opening as few as 2 connections with 5 slow DB-backed streams each can saturate all 8 core threads, causing all subsequent gRPC RPC dispatches — including gRPC health-check RPCs — to queue indefinitely. This degrades gRPC service availability and can cause monitoring systems relying on gRPC health checks to report the server as unreachable.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35:
```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14:
```java
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause — three failed assumptions:**

1. **No connection limit is configured.** `grpcServerConfigurer` never calls `serverBuilder.maxConnectionsTotal()` or any equivalent. Netty gRPC's default is `Integer.MAX_VALUE` accepted connections.

2. **The `applicationTaskExecutor` is Spring Boot's default `ThreadPoolTaskExecutor`.** With no override in any `application.yml` (confirmed: no `spring.task.execution.*` properties exist in the repository), the defaults are: `core-size = 8`, `max-size = Integer.MAX_VALUE`, `queue-capacity = Integer.MAX_VALUE`. Because the queue is unbounded, Java's `ThreadPoolExecutor` never creates threads beyond `corePoolSize` (8). The effective thread ceiling is **8 threads**.

3. **All gRPC RPC handlers share this single executor.** Every `subscribeTopic`, `getNodes`, `getFeeEstimate`, and any registered gRPC health-check RPC is dispatched to the same 8-thread pool.

**Exploit flow:**

- Attacker opens ≥ 2 connections, each issuing 5 concurrent `subscribeTopic` calls for a topic with a large historical backlog.
- Each stream drives the `TopicMessageRetriever`, which polls the database in a loop. With `db.statementTimeout = 10000ms` (10 s) and `retriever.pollingFrequency = 2s`, each active stream holds an executor thread for the duration of the poll cycle.
- 2 connections × 5 streams = 10 concurrent RPC tasks → 8 threads active, 2 queued. Any additional connections deepen the queue.
- All new gRPC RPC dispatches (including health-check RPCs) are appended to the unbounded queue behind the attacker's tasks.
- The attacker sustains the attack by keeping streams alive (no authentication, no per-IP connection limit, no gRPC-layer rate limiting exists for the gRPC module).

**Why existing checks are insufficient:**

- `maxConcurrentCallsPerConnection = 5` limits concurrency *per connection* but does not bound the *total* number of connections or the aggregate thread consumption across all connections.
- `db.statementTimeout = 10000ms` and `retriever.timeout = 60s` bound individual query and stream lifetimes, but the attacker simply re-opens streams after timeout, maintaining continuous pressure.
- No gRPC-layer authentication, rate limiting, or per-IP connection throttle exists (unlike the web3 module which has `ThrottleConfiguration` with `Bucket4j`).

### Impact Explanation

All gRPC RPC handler dispatch is serialized through the 8-thread `applicationTaskExecutor`. Once saturated, new legitimate subscriptions and any gRPC health-check RPCs (e.g., `grpc.health.v1.Health/Check` if registered by spring-grpc autoconfiguration) queue indefinitely. Monitoring systems that probe the gRPC port directly will time out and report the server as unhealthy or unreachable, triggering false partition alerts. Legitimate clients receive no responses until attacker streams expire. This is a complete gRPC-layer denial of service achievable with minimal resources.

### Likelihood Explanation

The attack requires no credentials, no special protocol knowledge beyond standard gRPC, and no privileged network position. The `subscribeTopic` API is publicly documented and accessible via `grpcurl`. The attacker needs only 2 TCP connections to saturate the default thread pool. The attack is trivially repeatable and automatable. The absence of any connection-count limit, IP-based throttle, or gRPC-layer rate limiter means there is no server-side mechanism to detect or block the pattern.

### Recommendation

1. **Set a total connection limit:** Add `serverBuilder.maxConnectionsTotal(N)` in `grpcServerConfigurer()` with a value appropriate for expected legitimate load.
2. **Isolate the gRPC executor:** Replace `applicationTaskExecutor` with a dedicated, bounded `ThreadPoolExecutor` (e.g., `Executors.newFixedThreadPool(N)`) so gRPC handler threads cannot starve other Spring components, and configure it with a bounded queue and rejection policy.
3. **Add keepalive and connection-age limits:** Configure `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnectionIdle(...)`, and `serverBuilder.keepAliveTimeout(...)` in `NettyProperties` to bound the lifetime of idle or long-lived attacker connections.
4. **Add per-connection or per-IP rate limiting** at the gRPC interceptor layer, analogous to the `ThrottleConfiguration` used in the web3 module.

### Proof of Concept

```bash
# Install grpcurl. No credentials required.
# Open 2 connections, each with 5 concurrent subscribeTopic streams
# targeting a topic with a large historical message backlog.

for i in $(seq 1 5); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}, "limit": 0}' \
    <grpc-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

for i in $(seq 1 5); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}, "limit": 0}' \
    <grpc-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Now attempt a legitimate call — it will queue behind the 10 attacker streams
# and receive no response until attacker streams time out (up to 60s each).
grpcurl -plaintext \
  -d '{"file_id": {"fileNum": 102}, "limit": 1}' \
  <grpc-host>:5600 \
  com.hedera.mirror.api.proto.NetworkService/getNodes
# Expected: hangs or times out
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```
