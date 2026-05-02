### Title
Missing Connection Lifecycle Limits in NettyServerBuilder Enables Rapid Connection Cycling DoS

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures `NettyServerBuilder` with only `maxConcurrentCallsPerConnection` and an executor, omitting all connection lifecycle controls (`maxConnectionAge`, `maxConnectionIdle`, `keepAliveTimeout`). An unprivileged attacker can rapidly open HTTP/2 connections, initiate a `subscribeTopic` streaming RPC (triggering DB queries and reactive stream allocation), then immediately tear down the connection — cycling this at high rate to exhaust server-side resources with no authentication required.

### Finding Description
**Exact code path:**
`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`NettyProperties` exposes only one tunable — `maxConcurrentCallsPerConnection` (default: 5). No `maxConnectionAge`, `maxConnectionAgeGrace`, `maxConnectionIdle`, `keepAliveTime`, or `keepAliveTimeout` are set anywhere in the gRPC module.

**Root cause:** The server imposes no bound on how many total simultaneous connections can exist, no maximum connection lifetime, and no idle-connection eviction. The failed assumption is that `maxConcurrentCallsPerConnection=5` is sufficient protection — it limits calls *within* a connection but does nothing to limit the *number* of connections or the rate at which they are opened and closed.

**Exploit flow:**
1. Attacker opens N parallel TCP connections to port 5600 (no TLS required in the default docker-compose deployment).
2. On each connection, attacker sends a `ConsensusService/subscribeTopic` request for a valid topic ID. This causes the server to: allocate an HTTP/2 stream, run a topic-existence DB query, initialize a Reactor `Flux` pipeline, and register a Redis/poll listener subscription.
3. Attacker immediately sends a TCP RST or HTTP/2 GOAWAY frame, tearing down the connection.
4. The server must cancel the reactive stream, release the DB connection back to the pool, and clean up the listener registration — all under lock/synchronization.
5. Attacker repeats from step 1 in a tight loop across many source IPs or a single IP.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection=5` caps streams per connection; it does not cap the number of connections.
- The GCP backend policy `maxRatePerEndpoint: 250` (in `charts/hedera-mirror-grpc/values.yaml` line 69) is a request-rate limit, not a connection-rate limit, and only applies when the GCP gateway is enabled — it is absent in the docker-compose deployment.
- The web3 throttle (`ThrottleConfiguration`) is entirely separate and does not apply to the gRPC service.
- No IP-level connection rate limiting exists at the application layer.

### Impact Explanation
Each rapid connect/subscribe/disconnect cycle forces the server to: (a) allocate and then immediately free a thread-pool slot, (b) open and return a PostgreSQL connection from the pool (default pool is small), (c) initialize and cancel a Reactor `Flux` with backpressure state, and (d) register/deregister a Redis pub-sub listener. At sufficient rate this exhausts the DB connection pool (starving legitimate subscribers), saturates the `applicationTaskExecutor` thread pool, and causes cascading `RESOURCE_EXHAUSTED` gRPC errors for all clients. Severity: **High** — full denial of service of the topic-subscription API with no authentication required.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed. No authentication is required to call `subscribeTopic`. A single attacker with a modest machine can open thousands of TCP connections per second. The attack is trivially scriptable with any gRPC client library (e.g., `grpcurl`, the Java SDK, or a raw HTTP/2 client). It is repeatable and stateless from the attacker's perspective.

### Recommendation
Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
serverBuilder.maxConnectionAge(30, TimeUnit.SECONDS);
serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
serverBuilder.maxConnectionIdle(10, TimeUnit.SECONDS);
serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(5, TimeUnit.SECONDS);
```

Expose these as configurable fields in `NettyProperties` (alongside `maxConcurrentCallsPerConnection`). Additionally, add a `maxConnections` limit to `NettyServerBuilder` and consider an IP-level connection-rate filter (e.g., via a Netty `ChannelHandler` or an ingress-level policy) that applies regardless of deployment topology.

### Proof of Concept
```bash
# Requires: grpcurl, a valid topic ID (e.g., 0.0.1234), server at localhost:5600

for i in $(seq 1 500); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1234}}' \
    -max-time 0.1 \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait

# Expected result: server DB connection pool exhausted, subsequent legitimate
# subscribeTopic calls return RESOURCE_EXHAUSTED or hang indefinitely.
# Observable via: server logs showing "connection validation failed" or
# Prometheus metric hiero_mirror_grpc_subscribers dropping to 0 while
# GrpcHighDBConnections alert fires.
```