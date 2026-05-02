### Title
Unbounded TCP Connection Acceptance in `grpcServerConfigurer()` Enables Boss-Thread Exhaustion DoS

### Summary
`grpcServerConfigurer()` configures the `NettyServerBuilder` with only `maxConcurrentCallsPerConnection(5)`, which limits concurrent RPC calls per connection but places no bound on the total number of accepted TCP connections, their lifetime, or their idle duration. An unprivileged attacker can open thousands of TCP connections without sending any gRPC frames, flooding the Netty boss `NioEventLoop` with `channelActive`/`channelInactive` lifecycle events and starving legitimate clients of connection slots. During a network partition, pre-existing half-open connections accumulate (no `maxConnectionIdle` to reap them), compounding the resource pressure when the flood begins.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–14:

```java
public class NettyProperties {
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**Root cause:** `NettyServerBuilder` exposes `maxConnectionAge()`, `maxConnectionAgeGrace()`, and `maxConnectionIdle()` to bound connection lifetime and idle reaping, and Netty itself supports a maximum-connections channel option. None of these are set. The only guard applied — `maxConcurrentCallsPerConnection(5)` — restricts the number of in-flight RPC streams *per already-accepted connection*; it does not prevent accepting an unlimited number of new TCP connections.

**Exploit flow:**

1. Attacker opens a large number of TCP connections to port 5600 in rapid succession (no gRPC handshake required — a bare TCP `connect()` is sufficient to trigger `channelActive` on the boss thread).
2. Netty's single boss `NioEventLoop` processes each `OP_ACCEPT` event, allocates a `NioSocketChannel`, fires `channelRegistered` + `channelActive` through the pipeline, and hands the channel to a worker. At high connection rates this loop becomes CPU-bound.
3. Attacker immediately closes each connection (RST or FIN), generating a matching `channelInactive` + `channelUnregistered` event back on the boss thread.
4. The boss thread event queue depth grows; new `OP_ACCEPT` events are delayed. Legitimate clients experience connection timeouts.
5. During a network partition, existing legitimate connections enter a half-open TCP state. Without `maxConnectionIdle`, the server never closes them. File descriptors accumulate. When the attacker's flood begins, the boss thread is simultaneously processing zombie-connection cleanup (when OS keepalive eventually fires) and the new-connection flood, accelerating saturation.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection(5)` — guards RPC call count per connection, not connection count. An attacker sending zero RPC frames is completely unaffected.
- GCP backend policy `maxRatePerEndpoint: 250` (`charts/hedera-mirror-grpc/values.yaml`, line 69) — this is a *request* (gRPC call) rate limit, not a TCP connection rate limit. A flood of bare TCP connections with no gRPC frames bypasses it entirely.
- `sessionAffinity: type: CLIENT_IP` (line 71) — routes all connections from the same source IP to the same pod, concentrating rather than distributing the attack.

### Impact Explanation

The Netty boss thread is a single-threaded `NioEventLoop`; there is no parallelism for the `accept()` path. Saturating it with connection lifecycle events directly prevents new legitimate connections from being accepted. Existing streaming subscriptions (topic message delivery) are unaffected until their connections are also disrupted, but no new subscriber can connect. This is a complete denial-of-service for the gRPC API surface with no authentication or privilege required.

### Likelihood Explanation

Any host with TCP reachability to port 5600 can execute this attack. No gRPC knowledge, credentials, or application-layer interaction is needed — a loop of `connect()`/`close()` syscalls suffices. Standard tools (`hping3`, `wrk`, custom scripts) can sustain tens of thousands of connection events per second from a single machine. The attack is repeatable and stateless from the attacker's perspective.

### Recommendation

Add the following to `grpcServerConfigurer()` via `NettyServerBuilder`:

```java
serverBuilder.maxConnectionAge(30, TimeUnit.SECONDS);
serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
serverBuilder.maxConnectionIdle(15, TimeUnit.SECONDS);
```

Expose `maxConnectionAge`, `maxConnectionAgeGrace`, and `maxConnectionIdle` as configurable fields in `NettyProperties` alongside `maxConcurrentCallsPerConnection`. Additionally, configure a Netty `ChannelOption.MAX_MESSAGES_PER_READ` or use a `io.netty.handler.ipfilter.RuleBasedIpFilter` / connection-count `ChannelHandler` to enforce a per-IP connection ceiling. At the infrastructure layer, add a GCP backend policy `maxConnectionsPerEndpoint` (separate from `maxRatePerEndpoint`) to enforce a TCP-level connection cap before traffic reaches the pod.

### Proof of Concept

```bash
# Requires: bash, /dev/tcp or netcat, or Python
# Target: grpc pod port 5600 (direct, bypassing GCP LB to avoid request-rate limit)

python3 - <<'EOF'
import socket, threading, time

TARGET = ("grpc-pod-ip", 5600)
THREADS = 500
RATE    = 1000  # connections per second per thread

def flood():
    while True:
        try:
            s = socket.socket()
            s.settimeout(0.1)
            s.connect(TARGET)
            s.close()          # immediate RST — generates channelInactive on boss thread
        except:
            pass

for _ in range(THREADS):
    threading.Thread(target=flood, daemon=True).start()

time.sleep(30)   # sustain for 30 seconds
EOF

# Expected result: legitimate gRPC clients receive DEADLINE_EXCEEDED or
# connection refused during the flood window; no gRPC frames are sent by attacker.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-14)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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
