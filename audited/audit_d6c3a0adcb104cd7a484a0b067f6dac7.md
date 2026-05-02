### Title
Unbounded Persistent gRPC Connections Enable Resource Exhaustion DoS via Missing Connection Age/Idle Limits

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only a per-connection call limit (`maxConcurrentCallsPerConnection = 5`) but sets no bound on connection lifetime (`maxConnectionAge`), idle timeout (`maxConnectionIdle`), or total connection count. Any unprivileged external client can open and hold an unlimited number of HTTP/2 connections indefinitely, accumulating per-connection server-side state (channel objects, pipeline handlers, HTTP/2 flow-control tables, per-stream metadata) until the JVM exhausts heap or the OS exhausts file descriptors, crashing the service.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 27–35:
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

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15:
```java
public class NettyProperties {
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**Root cause:** The `NettyServerBuilder` is never called with:
- `maxConnectionAge(duration, unit)` — forces periodic connection recycling
- `maxConnectionIdle(duration, unit)` — closes connections with no active streams
- `maxConnectionAgeGrace(duration, unit)` — grace period for in-flight RPCs on aged connections

A repository-wide search confirms none of these are set anywhere in the gRPC server configuration. The only protection applied is `maxConcurrentCallsPerConnection(5)`, which limits concurrent RPC calls *per connection* but places no bound on the number of connections themselves or their lifetime.

**Exploit flow:**
1. Attacker opens N HTTP/2 connections to port 5600 (the public gRPC port).
2. On each connection the attacker sends a valid `subscribeTopic` request (a long-lived streaming RPC), consuming one of the 5 allowed call slots and keeping the connection alive.
3. Alternatively, the attacker opens connections and sends no RPCs at all — without `maxConnectionIdle`, the server never reclaims idle connections.
4. Each live connection holds: a Netty `Channel` + pipeline, HTTP/2 connection-level flow-control state, per-stream state, and associated JVM objects.
5. With no upper bound on connections, the attacker repeats until the JVM heap is exhausted or the OS file-descriptor limit is hit.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` limits calls *within* a connection; it does not limit how many connections exist simultaneously.
- The nginx `keepalive 16` directive in `docker-compose.yml` governs the proxy's *outbound* connection pool to the backend — it does not cap inbound client connections to the proxy or to a directly exposed gRPC port.
- No `maxInboundConnections` or equivalent is set on the `NettyServerBuilder`.

### Impact Explanation
An attacker can drive the gRPC service to OOM or file-descriptor exhaustion without authentication. The gRPC module serves live topic subscriptions used by downstream financial applications monitoring the Hedera network. A crash or sustained degradation during peak activity (e.g., high-volume token transfers) interrupts real-time consensus data delivery, preventing clients from observing transaction finality. The Grafana alert rule `GrpcHighMemory` (threshold: JVM memory > 80%) confirms the operators already treat memory pressure on this service as critical.

### Likelihood Explanation
No authentication or special privilege is required — the gRPC port is publicly accessible by design. The attack requires only a standard gRPC client (e.g., `grpcurl`, any HTTP/2 client) and a loop opening connections. It is trivially scriptable, repeatable, and can be executed from a single host or distributed across multiple IPs to evade simple IP-rate-limiting at the network edge. The attack is low-cost and high-impact.

### Recommendation
Add the following to `grpcServerConfigurer()`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge().toSeconds(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionAgeGrace(nettyProperties.getMaxConnectionAgeGrace().toSeconds(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle().toSeconds(), TimeUnit.SECONDS);
};
```

Add the corresponding fields to `NettyProperties` with safe defaults (e.g., `maxConnectionAge = 300s`, `maxConnectionAgeGrace = 30s`, `maxConnectionIdle = 60s`). Additionally, consider calling `serverBuilder.maxInboundConnections(n)` (available in newer grpc-java versions) to hard-cap total simultaneous connections.

### Proof of Concept
```bash
# Open 500 persistent idle connections to the gRPC server
for i in $(seq 1 500); do
  grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
    <server>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Monitor server JVM heap — will climb continuously with no recovery
# until OOM kill or file-descriptor exhaustion
watch -n5 'curl -s http://<server>:8080/actuator/metrics/jvm.memory.used | jq .measurements'
```

Each background process holds an HTTP/2 connection open. With no `maxConnectionIdle` or `maxConnectionAge`, the server never reclaims these connections. Repeating the loop exhausts server resources.