### Title
Missing RST_STREAM Rate Limit in `grpcServerConfigurer()` Enables HTTP/2 Rapid Reset DoS Against Gossip Subscriptions

### Summary
The `grpcServerConfigurer()` method in `GrpcConfiguration.java` configures the Netty gRPC server with only `maxConcurrentCallsPerConnection` (set to 5) and a custom executor. No `maxRstFramesPerWindow` or equivalent RST_STREAM rate limit is applied. An unprivileged external attacker can exploit this by rapidly opening HTTP/2 streams and immediately sending RST_STREAM frames, forcing the server to process continuous stream setup/teardown cycles, exhausting CPU and I/O resources, and preventing stable gossip subscription delivery.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15:

```java
public class NettyProperties {
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**Root cause:** The `NettyServerBuilder` exposes `maxRstFramesPerWindow(int maxRstFrames, Duration window)` specifically to mitigate CVE-2023-44487 (HTTP/2 Rapid Reset). This is never called. The only protection configured is `maxConcurrentCallsPerConnection = 5`, which limits *simultaneously active* streams — it does not limit the *rate* at which streams are opened and immediately reset. Each RST_STREAM cycle is processed by the server (HEADERS frame parsed, stream state allocated, RST_STREAM processed, stream torn down) regardless of whether any concurrent call limit is reached, because the stream is reset before it counts as an active concurrent call.

**Failed assumption:** The developer assumed `maxConcurrentCallsPerConnection` would bound server-side work per connection. It does not bound the rate of stream creation/destruction events.

### Impact Explanation
The gRPC service is exposed on port 5600 as HTTP/2 cleartext (`h2c`, confirmed by `traefik.ingress.kubernetes.io/service.serversscheme: h2c`). The service delivers consensus topic subscription streams (gossip). Under a sustained RST_STREAM flood:
- Server Netty I/O threads are consumed processing HEADERS + RST_STREAM frame pairs at high frequency
- Stream state objects are allocated and freed in tight loops, causing GC pressure
- Legitimate `subscribeToTopic` streaming RPCs cannot be established or are starved of I/O thread time
- Gossip subscription delivery is interrupted or completely blocked for all connected clients

Severity: **High** — complete denial of the primary service function (streaming gossip delivery) achievable from a single attacker machine with multiple connections.

### Likelihood Explanation
Preconditions: none beyond network access to port 5600. No authentication is required. The attack is a well-known, publicly documented technique (CVE-2023-44487, October 2023). Tooling to perform HTTP/2 RST_STREAM floods is publicly available. A single attacker machine can open dozens of connections and issue thousands of RST_STREAM frames per second. Even if grpc-java's library-level default (200 RST/30s per connection) applies, an attacker with 50 connections saturates 10,000 RST events per 30 seconds with no per-IP or global cap configured at the application layer.

### Recommendation
In `grpcServerConfigurer()`, add an explicit RST_STREAM rate limit via `NettyServerBuilder`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    serverBuilder.maxRstFramesPerWindow(
        nettyProperties.getMaxRstFramesPerWindow(),   // e.g. 200
        nettyProperties.getRstFramesWindow()          // e.g. Duration.ofSeconds(30)
    );
};
```

Add `maxRstFramesPerWindow` and `rstFramesWindow` fields to `NettyProperties` with safe defaults (e.g., 200 frames per 30 seconds). Additionally, consider deploying a connection-rate limit at the ingress (Traefik) layer to cap the number of HTTP/2 connections per source IP.

### Proof of Concept
**Preconditions:** Network access to the gRPC port (5600).

**Steps:**
1. Using an HTTP/2-capable client (e.g., `h2load`, a custom Python script with `h2` library, or `grpc-bench`), open 50 parallel HTTP/2 connections to the mirror node gRPC endpoint.
2. On each connection, in a tight loop:
   - Send a `HEADERS` frame initiating a `subscribeToTopic` RPC (stream ID N)
   - Immediately send `RST_STREAM` for stream ID N with error code `CANCEL` (0x8)
   - Increment stream ID by 2 and repeat
3. Sustain this for 30 seconds across all 50 connections (~thousands of RST events/second total).
4. Simultaneously, attempt a legitimate `subscribeToTopic` subscription from a separate client.

**Expected result:** The legitimate subscription either fails to establish, experiences severe latency, or receives no messages — demonstrating that gossip delivery is disrupted. Server-side metrics (`hiero_mirror_grpc_subscribers`, JVM CPU, GC pause time) will show abnormal values during the attack window.