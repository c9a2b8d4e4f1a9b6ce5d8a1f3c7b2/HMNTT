### Title
HTTP/2 SETTINGS Frame Flood DoS via Unconfigured Rate Limit in `grpcServerConfigurer()`

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only an executor and `maxConcurrentCallsPerConnection`, leaving no HTTP/2 connection-level protections such as a SETTINGS frame rate limit, `maxConnectionIdle`, or `maxConnectionAge`. Because HTTP/2 SETTINGS frames are connection-level (not stream-level), the sole configured guard (`maxConcurrentCallsPerConnection = 5`) does not apply to them. An unauthenticated attacker can open a valid HTTP/2 connection to port 5600 and flood the server with SETTINGS frames, each of which the Netty I/O thread must parse and acknowledge, exhausting CPU and degrading throughput for legitimate `subscribeTopic` callers.

### Finding Description
**Code path:**
- `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35
- `grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15

`grpcServerConfigurer()` applies exactly two settings to the `NettyServerBuilder`:
```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // default 5
```
`NettyProperties` exposes only `maxConcurrentCallsPerConnection`; there is no field for `maxConnectionIdle`, `maxConnectionAge`, `keepAliveTimeout`, `flowControlWindow`, or any HTTP/2 SETTINGS frame rate limit. A grep across the entire `grpc/` module confirms zero calls to any of those `NettyServerBuilder` methods.

**Root cause:** RFC 7540 requires the receiver of every SETTINGS frame to emit a SETTINGS_ACK. Netty's HTTP/2 codec processes SETTINGS frames synchronously in the I/O event loop with no built-in rate limiter. Because the application never calls `NettyServerBuilder` methods that would bound connection lifetime or frame rates, an attacker can drive unbounded SETTINGS-frame processing on a single long-lived connection.

**Why the existing check fails:** `maxConcurrentCallsPerConnection` governs HTTP/2 *stream* creation (i.e., new RPC calls). SETTINGS frames are connection-level control frames (stream ID 0) and are processed entirely outside the stream-count gate. Setting it to 5 has zero effect on SETTINGS frame throughput.

### Impact Explanation
Each SETTINGS frame forces the Netty I/O thread to: deserialize the frame, apply any parameter changes to the connection state, and write a SETTINGS_ACK back to the client. With multiple attacker connections each sending thousands of SETTINGS frames per second, the I/O thread pool saturates. Legitimate `subscribeTopic` streaming RPCs stall waiting for I/O scheduling, causing clients to miss or delay transaction-confirmation events. In a sustained attack with enough connections, the gRPC service becomes effectively unavailable to all subscribers.

### Likelihood Explanation
- **No authentication required**: gRPC port 5600 accepts unauthenticated HTTP/2 connections from any network peer.
- **Trivial tooling**: Any HTTP/2 client library (e.g., `h2load`, `nghttp2`, custom Python `h2` script) can send raw SETTINGS frames in a tight loop.
- **Single attacker sufficient**: One machine with a modest connection count (e.g., 50 connections × 5,000 SETTINGS/s each) can saturate a typical JVM I/O thread pool.
- **Highly repeatable**: The attack requires no state, no credentials, and no prior knowledge of the application beyond the open port.

### Recommendation
Add the following hardening calls inside the `grpcServerConfigurer()` lambda:

```java
serverBuilder.maxConnectionIdle(30, TimeUnit.SECONDS);
serverBuilder.maxConnectionAge(60, TimeUnit.SECONDS);
serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(5, TimeUnit.SECONDS);
serverBuilder.permitKeepAliveWithoutCalls(false);
```

Expose corresponding fields in `NettyProperties` so operators can tune them. Additionally, consider placing a connection-rate-limiting reverse proxy (e.g., Envoy with `http2_protocol_options.max_inbound_window_update_frames_per_data_frame_sent`) in front of port 5600, and enforce per-IP connection limits at the infrastructure layer (GCP BackendPolicy `maxRatePerEndpoint` already exists for request rate but not for raw connection/frame rate).

### Proof of Concept
```python
# Requires: pip install h2 hyper
import socket, h2.connection, h2.config, h2.events, time

HOST, PORT = "<mirror-node-ip>", 5600

sock = socket.create_connection((HOST, PORT))
config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send(65535))

# Flood: send empty SETTINGS frames as fast as possible
# Server must respond to each with SETTINGS_ACK
for _ in range(100_000):
    conn.update_settings({})          # sends a SETTINGS frame
    sock.sendall(conn.data_to_send(65535))
    # drain ACKs loosely to keep the connection alive
    data = sock.recv(65535)
    if data:
        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send(65535))

# Repeat across N parallel connections to amplify CPU load
```
Run this from multiple hosts or threads. Monitor the mirror node's CPU (`process_cpu_usage` Prometheus metric) and observe `subscribeTopic` latency climbing as the I/O threads are consumed by SETTINGS-ACK generation.