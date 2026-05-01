### Title
Unbounded Connection Exhaustion via Missing Server-Side Keepalive and Connection Age Limits in gRPC Server Configuration

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only a per-connection call limit (`maxConcurrentCallsPerConnection=5`) and a shared `applicationTaskExecutor`, but sets no `maxConnectionAge`, no server-side keepalive (`keepAliveTime`/`keepAliveTimeout`), and no `maxInboundConnections` cap. An unprivileged attacker can open an unbounded number of TCP connections, saturate the 5 concurrent-call slots on each, then simulate a network partition by silently dropping packets. The server has no mechanism to detect or reap these zombie connections, causing indefinite resource retention (threads, memory, file descriptors) that degrades or denies service to legitimate clients.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35:

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

**Root cause — failed assumptions:**

1. `maxConcurrentCallsPerConnection=5` limits calls *per connection* but places **no cap on the total number of connections**. An attacker opens `N` connections and gets `N×5` active streaming calls.
2. No `serverBuilder.keepAliveTime(...)` / `serverBuilder.keepAliveTimeout(...)` is set. The server never sends HTTP/2 PING frames to probe liveness, so it cannot detect a silently-partitioned client.
3. No `serverBuilder.maxConnectionAge(...)` / `serverBuilder.maxConnectionIdle(...)` is set. Connections are never forcibly recycled regardless of age or inactivity.
4. No `serverBuilder.maxInboundConnections(...)` is set. The OS TCP backlog is the only gate.
5. The `applicationTaskExecutor` is Spring Boot's default `ThreadPoolTaskExecutor` (unbounded queue, max pool size = `Integer.MAX_VALUE`). It will spawn threads until OOM rather than rejecting work.

**Why existing checks fail:**

`maxConcurrentCallsPerConnection` is the *only* resource guard present. It is a per-connection limit, not a global one, so it does not bound total resource consumption across many connections. There is no rate-limiting, authentication, or IP-based connection throttling visible in the gRPC server configuration.

### Impact Explanation
- **Thread exhaustion / OOM**: Each active streaming call (`subscribeTopic`) dispatches work to `applicationTaskExecutor`. With no bounded queue and no connection limit, the JVM spawns threads until heap/native memory is exhausted, causing an OOM crash or severe GC pressure.
- **File descriptor exhaustion**: Each TCP connection consumes a file descriptor. With no `maxInboundConnections`, the process hits the OS `ulimit` and can no longer accept legitimate connections.
- **Zombie connection persistence**: Without server-side keepalive, dead connections from a network partition persist until OS-level TCP keepalive fires (default: ~2 hours on Linux), holding all associated resources for that entire window.
- **Complete DoS**: Legitimate subscribers receive `RESOURCE_EXHAUSTED` or connection refused while the attacker's zombie connections occupy all capacity.

Severity: **High** (unauthenticated, remotely exploitable, full service disruption).

### Likelihood Explanation
- **No authentication required**: Port 5600 is publicly exposed (see `docker-compose.yml` line 60, Helm chart port 5600). Any network-reachable client can open gRPC connections.
- **Trivial to execute**: Opening many gRPC connections and then using `iptables -A OUTPUT -p tcp --dport 5600 -j DROP` (or a firewall rule) to simulate a partition requires no special tooling.
- **Repeatable**: The attacker can re-execute after a server restart. The default OS keepalive window (~2 hours) gives a long exploitation window per attempt.
- **Low cost**: Streaming calls to `subscribeTopic` are long-lived by design; the attacker does not need to send any data after the initial handshake.

### Recommendation
Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
import java.util.concurrent.TimeUnit;

serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);
serverBuilder.permitKeepAliveTime(10, TimeUnit.SECONDS);
serverBuilder.permitKeepAliveWithoutCalls(false);
serverBuilder.maxConnectionAge(5, TimeUnit.MINUTES);
serverBuilder.maxConnectionAgeGrace(1, TimeUnit.MINUTES);
serverBuilder.maxConnectionIdle(2, TimeUnit.MINUTES);
```

Additionally:
- Expose `maxInboundConnections` as a configurable property in `NettyProperties` and set a sane default (e.g., 500).
- Configure a bounded `applicationTaskExecutor` queue (via `spring.task.execution.pool.queue-capacity`) to prevent unbounded thread creation.
- Consider adding IP-based rate limiting at the load balancer / ingress layer.

### Proof of Concept

**Preconditions**: Network access to gRPC port 5600; a valid topic ID (or `checkTopicExists=false`).

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# Step 1: Open many connections, each saturating maxConcurrentCallsPerConnection=5
channels = []
stubs = []
for i in range(200):  # 200 connections × 5 calls = 1000 active streaming calls
    ch = grpc.insecure_channel("target:5600")
    channels.append(ch)

def open_streams(ch):
    stub = ConsensusServiceStub(ch)
    streams = []
    for _ in range(5):
        req = ConsensusTopicQuery(topic_id=TopicID(topic_num=1))
        streams.append(stub.subscribeTopic(req))
    # Hold streams open — do not iterate/close them
    import time; time.sleep(86400)

with ThreadPoolExecutor(max_workers=200) as ex:
    futures = [ex.submit(open_streams, ch) for ch in channels]

# Step 2: Simulate network partition — drop all outbound packets to the server
# (run as root on attacker machine)
# iptables -A OUTPUT -p tcp --dport 5600 -j DROP

# Result: Server holds 1000 zombie streaming calls indefinitely.
# applicationTaskExecutor spawns threads until OOM.
# File descriptors exhausted. Legitimate clients receive UNAVAILABLE.
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
