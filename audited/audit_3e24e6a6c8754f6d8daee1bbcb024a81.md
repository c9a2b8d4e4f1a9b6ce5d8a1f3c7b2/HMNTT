### Title
Unbounded TCP Connection Acceptance Enables File Descriptor Exhaustion DoS in gRPC Server

### Summary
`grpcServerConfigurer()` configures the Netty gRPC server with only a per-connection RPC call limit (`maxConcurrentCallsPerConnection = 5`) but sets no limit on the total number of accepted TCP connections, no idle connection timeout (`maxConnectionIdle`), and no maximum connection lifetime (`maxConnectionAge`). An unprivileged attacker can open and hold thousands of idle TCP connections, each consuming a file descriptor, until the JVM process exhausts its file descriptor quota and can no longer accept connections from legitimate users.

### Finding Description
**Code location:** `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35; `grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–14.

`grpcServerConfigurer()` applies exactly two settings to the `NettyServerBuilder`:

```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // = 5
```

`NettyProperties` exposes only `maxConcurrentCallsPerConnection`; no `maxConnectionAge`, `maxConnectionIdle`, or equivalent field exists. A grep across all Java sources confirms none of these `NettyServerBuilder` methods are called anywhere in the gRPC module.

`maxConcurrentCallsPerConnection` limits the number of active HTTP/2 streams (RPC calls) multiplexed over a single TCP connection. It does **not** limit how many TCP connections the server accepts. Each accepted TCP connection — even one that never sends a single RPC — occupies one file descriptor in the JVM process. Without `maxConnectionIdle`, idle connections are never reaped. Without `maxConnectionAge`, connections live indefinitely.

**Exploit flow:**
1. Attacker opens a TCP connection to port 5600 and completes the TLS/HTTP2 handshake (no authentication required — the service is public).
2. Attacker sends no RPC frames; the connection sits idle.
3. Attacker repeats in a loop from one or more hosts.
4. Each connection holds one file descriptor. The JVM process has a finite fd limit (typically 65 536 in containerised deployments).
5. Once the limit is reached, `accept()` calls fail with `EMFILE`; the server can no longer accept connections from legitimate users.

**Why the existing check is insufficient:** `maxConcurrentCallsPerConnection = 5` only throttles RPC multiplexing within a connection. It provides zero protection against connection-count exhaustion because the attacker never needs to issue any RPC call.

### Impact Explanation
Legitimate clients receive connection-refused or timeout errors for all new gRPC subscriptions (topic message streaming, address book queries). The mirror node's gRPC API becomes unavailable until the attacker releases connections or the process is restarted. The Prometheus alert `GrpcHighFileDescriptors` (threshold: 80%) is reactive and fires only after significant exhaustion has already occurred; it does not prevent the condition.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed via the Kubernetes ingress/gateway. No authentication is required to establish a TCP/HTTP2 connection. The attack requires only a standard TCP client (e.g., `grpc-go`, `grpcurl`, or raw socket code) and can be executed from a single host with modest resources. It is trivially repeatable and scriptable.

### Recommendation
Add the following to `grpcServerConfigurer()`:

```java
serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle(), TimeUnit.MILLISECONDS);
serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge(), TimeUnit.MILLISECONDS);
serverBuilder.maxConnectionAgeGrace(nettyProperties.getMaxConnectionAgeGrace(), TimeUnit.MILLISECONDS);
```

Add corresponding fields to `NettyProperties` with safe defaults (e.g., `maxConnectionIdle = 5m`, `maxConnectionAge = 30m`). Additionally, consider calling `serverBuilder.maxInboundMetadataSize()` to bound header memory per connection. At the infrastructure layer, configure the GCP BackendPolicy or Traefik middleware with a per-source-IP connection rate limit.

### Proof of Concept
```python
import grpc
import time

channel_list = []
# Open 70 000 idle connections (adjust to target fd limit)
for i in range(70_000):
    ch = grpc.insecure_channel("mirror-node-grpc-host:5600")
    channel_list.append(ch)
    # Force TCP handshake without sending any RPC
    try:
        grpc.channel_ready_future(ch).result(timeout=2)
    except Exception:
        pass

print(f"Opened {len(channel_list)} connections. Server should now reject new connections.")
time.sleep(3600)  # Hold connections open
```

After the fd limit is reached, any new `grpc.insecure_channel(...).result()` from a legitimate client will time out or receive a connection error, confirming the DoS condition. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-14)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** charts/hedera-mirror-grpc/values.yaml (L221-231)
```yaml
  GrpcHighFileDescriptors:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} file descriptor usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror gRPC API file descriptor usage exceeds 80%"
    enabled: true
    expr: sum(process_files_open_files{application="grpc"}) by (namespace, pod) / sum(process_files_max_files{application="grpc"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```
