### Title
Unbounded Connection Multiplier Bypasses Per-Connection Concurrency Limit, Enabling Resource-Exhaustion DoS

### Summary
`grpcServerConfigurer()` configures only `maxConcurrentCallsPerConnection = 5` with no corresponding global connection limit, maximum connection age, or per-IP throttle at the application layer. An unprivileged attacker can open an arbitrary number of TCP/HTTP-2 connections — each carrying 5 active streams — multiplying the effective concurrency without bound and exhausting the shared `applicationTaskExecutor` thread pool and HikariCP database connection pool, denying service to legitimate subscribers.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // = 5
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14:
```java
private int maxConcurrentCallsPerConnection = 5;
```

**Root cause / failed assumption:** The developer assumed that capping streams per connection to 5 would bound total server load. This assumption fails because Netty's `maxConcurrentCallsPerConnection` is scoped strictly to a single HTTP/2 connection. No call is ever made to `maxConnectionAge`, `maxConnectionIdle`, `maxInboundConnections`, or any equivalent global cap — confirmed by a full-codebase grep returning zero matches for those identifiers in Java sources. The `applicationTaskExecutor` (Spring Boot's shared thread pool, unconfigured in `grpc/src/main/resources/`) and the HikariCP pool are therefore shared across all connections without any global ceiling.

**Exploit flow:**
1. Attacker opens *N* simultaneous TCP connections to port 5600 (no authentication required — this is a public mirror-node API).
2. On each connection the attacker issues 5 concurrent `subscribeToTopic` streaming RPCs (the per-connection limit is exactly met, so no connection is refused).
3. Total active server-side calls = N × 5. With N = 1,000 connections the attacker holds 5,000 concurrent streaming calls.
4. Each streaming call occupies a thread from `applicationTaskExecutor` and, during historical-message retrieval, a HikariCP database connection.
5. The thread pool and DB pool saturate; new legitimate requests queue indefinitely or are rejected with `RESOURCE_EXHAUSTED`.

**Why existing checks fail:**
- The only rate-limiting present is `maxRatePerEndpoint: 250` in the GCP backend policy (`charts/hedera-mirror-grpc/values.yaml` line 69), which is infrastructure-optional (requires GCP Gateway deployment, `gcp.enabled: true`), not enforced by the application itself, and counts request rate — not concurrent open connections.
- No IP-based connection throttle, no `maxConnections`, no `maxConnectionAge`/`maxConnectionIdle` are set anywhere in the Java application.

### Impact Explanation
Exhausting the executor thread pool blocks all gRPC handlers server-wide. Exhausting HikariCP connections causes every DB-backed call (topic message retrieval, address book queries) to time out. Legitimate clients receive `RESOURCE_EXHAUSTED` or hang until `retriever.timeout` (default 60 s) expires. The mirror node's gRPC API becomes effectively unavailable for the duration of the attack. Severity: **High** (complete availability loss of the public gRPC endpoint with no authentication barrier).

### Likelihood Explanation
The attack requires no credentials, no special tooling, and no prior knowledge beyond the public port number. Any HTTP/2 client library (e.g., `grpcurl`, standard gRPC stubs) can open hundreds of connections in a loop. The attack is trivially scriptable, repeatable, and can be sustained indefinitely. A single attacker machine with modest bandwidth is sufficient; a distributed attack is not required.

### Recommendation
Apply multiple complementary controls directly in `grpcServerConfigurer()`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // Add global guards:
    serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionAgeGrace(nettyProperties.getMaxConnectionAgeGrace(), TimeUnit.SECONDS);
};
```

Additionally:
- Add a `maxConnections` (total inbound connection cap) via a Netty `ChannelOption` or a custom `ServerTransportFilter`.
- Expose `maxConnectionAge`, `maxConnectionIdle`, and a `maxTotalConnections` field in `NettyProperties` with safe defaults (e.g., age = 300 s, idle = 60 s, total = 500).
- Enforce the GCP `maxRatePerEndpoint` (or equivalent) unconditionally at the ingress layer regardless of cloud provider.

### Proof of Concept
```bash
# Open 500 connections each with 5 concurrent subscribeToTopic streams (2500 total)
for i in $(seq 1 500); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
# Observe: legitimate grpcurl calls now return RESOURCE_EXHAUSTED or hang
```

No authentication, no special privileges, and no prior account required. The server accepts all 2,500 streams because each individual connection stays within its 5-stream quota.