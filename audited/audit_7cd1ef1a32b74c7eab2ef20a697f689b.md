### Title
Missing HTTP/2 RST_STREAM Rate Limiting Leaves gRPC Server Vulnerable to Rapid Reset DoS (CVE-2023-44487)

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the `NettyServerBuilder` with only `maxConcurrentCallsPerConnection(5)` and an executor, but never calls `maxRstFramesPerWindow()`. This leaves the server with no rate limit on HTTP/2 RST_STREAM frames, allowing any unauthenticated external client to rapidly open and cancel streams in a tight loop, exhausting server-side resources and causing legitimate topic subscription and smart contract query streams to be dropped.

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

**Root cause:** `NettyServerBuilder.maxRstFramesPerWindow(int maxRstFrames, int secondsPerWindow)` — the API added in grpc-java 1.59.1 specifically to mitigate CVE-2023-44487 — is never called. A codebase-wide search for `maxRstFrames`, `maxRstPeriod`, and `CVE-2023-44487` returns zero matches, confirming no mitigation exists anywhere in the project.

**Failed assumption:** The developer assumed `maxConcurrentCallsPerConnection = 5` would bound resource consumption. It does not. That setting limits the number of *simultaneously active* streams, but the rapid reset attack works by cycling streams: open 5 → immediately RST_STREAM all 5 → open 5 more → repeat. Each cycle forces the server to allocate stream state, dispatch to the handler thread pool, and then process the cancellation. The *rate* of these cycles is completely unbounded.

**Exploit flow:**
1. Attacker establishes an HTTP/2 connection to port 5600 (no authentication required).
2. Attacker sends 5 HEADERS frames (opening 5 streams, hitting the concurrent limit).
3. Attacker immediately sends 5 RST_STREAM frames cancelling all 5.
4. Server processes 10 frame events, cleans up stream state, and is now ready for more.
5. Attacker repeats steps 2–4 in a tight loop at wire speed (thousands of cycles/second).
6. Server CPU and I/O event-loop threads are saturated processing open/cancel bookkeeping.
7. Legitimate `subscribeTopic` and contract-query streams are starved and dropped.

### Impact Explanation
The gRPC server at port 5600 is the sole interface for `ConsensusService/subscribeTopic` and related mirror-node query streams. A sustained rapid-reset flood exhausts Netty's I/O event loop and the `applicationTaskExecutor` thread pool, causing all in-flight streams to time out or be dropped. Smart contract query results delivered via topic subscriptions are lost. Because the mirror node is a read-only query layer with no funds at direct risk, this is a medium-severity availability impact: no funds are stolen, but the service becomes unavailable to all clients for the duration of the attack.

### Likelihood Explanation
The attack requires zero privileges — the gRPC port is publicly accessible by design. CVE-2023-44487 is fully documented, and open-source tooling (e.g., `h2load`, custom HTTP/2 clients) can trivially generate rapid-reset floods. The attack is repeatable and can be sustained indefinitely from a single machine or amplified from multiple sources. The only barrier is network reachability to port 5600.

### Recommendation
In `grpcServerConfigurer()`, add a call to `maxRstFramesPerWindow()` on the `NettyServerBuilder`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    serverBuilder.maxRstFramesPerWindow(
        nettyProperties.getMaxRstFramesPerWindow(),   // e.g. 200
        nettyProperties.getRstFramesWindowSeconds()); // e.g. 30
};
```

Add the two new fields to `NettyProperties`:
```java
private int maxRstFramesPerWindow = 200;
private int rstFramesWindowSeconds = 30;
```

These values match the defaults recommended in the grpc-java CVE advisory. Also add the corresponding `hiero.mirror.grpc.netty.maxRstFramesPerWindow` and `hiero.mirror.grpc.netty.rstFramesWindowSeconds` entries to `docs/configuration.md`.

### Proof of Concept
```bash
# Requires h2load (from nghttp2) or a custom HTTP/2 client
# Connect to the gRPC port and flood with rapid-reset streams

h2load -n 1000000 -c 1 -m 5 \
  --header=":method: POST" \
  --header=":path: /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic" \
  --header=":scheme: http" \
  --header="content-type: application/grpc" \
  --data=/dev/null \
  http://<grpc-host>:5600

# Alternatively, using a Python HTTP/2 client (hyperframe + hpack):
# 1. Open TCP connection to port 5600
# 2. Send HTTP/2 client preface + SETTINGS
# 3. In a tight loop:
#    a. Send HEADERS frame (stream_id=N, END_HEADERS)
#    b. Immediately send RST_STREAM frame (stream_id=N, error_code=CANCEL)
#    c. Increment stream_id by 2 and repeat
# 4. Observe server CPU spike and legitimate client streams being dropped
```