### Title
Missing Server-Side Keepalive Probing Allows Zombie Connections to Exhaust gRPC Server Resources Indefinitely

### Summary
`grpcServerConfigurer()` in `GrpcConfiguration.java` configures the `NettyServerBuilder` with only `maxConcurrentCallsPerConnection` and a custom executor — no `keepAliveTime`, `keepAliveTimeout`, `maxConnectionIdle`, or `maxConnectionAge` is set. Because Netty gRPC defaults `keepAliveTime` to `Long.MAX_VALUE` (probing disabled) and `maxConnectionIdle` to `Long.MAX_VALUE` (infinite), the server never proactively detects or evicts dead TCP connections. An unprivileged attacker can silently drop a TCP connection after opening streaming calls, leaving zombie connections that hold server resources until the OS TCP retransmission timeout (~15 minutes on Linux defaults) expires.

### Finding Description
**Exact code location:** `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 27–35.

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // NO keepAliveTime, keepAliveTimeout, maxConnectionIdle, maxConnectionAge
};
```

`NettyProperties` exposes only `maxConcurrentCallsPerConnection = 5` (per-connection, not global). A grep across all `grpc/**/*.java` confirms zero occurrences of `keepAlive`, `maxConnectionIdle`, `maxConnectionAge`, or `permitKeepAlive`.

**Root cause / failed assumption:** The code assumes TCP will reliably signal connection death. It does not — a client behind a stateful firewall or using `iptables -j DROP` can silently discard packets, leaving the server's TCP stack in `ESTABLISHED` state with no data flowing. Without server-side keepalive probing (`keepAliveTime`) or an idle-connection reaper (`maxConnectionIdle`), the server has no mechanism to detect or close these connections.

**Exploit flow:**
1. Attacker opens a TCP connection to port 5600.
2. Attacker initiates 5 concurrent `subscribeTopic` streaming RPCs (filling `maxConcurrentCallsPerConnection`).
3. Attacker applies `iptables -I OUTPUT -p tcp --dport 5600 -j DROP` (or equivalent) — the TCP connection is now silently dead from the server's perspective.
4. The server holds the connection in `ESTABLISHED` state, retaining all 5 call slots, associated Reactor/Flux subscription state, and any database cursor/connection held by the retriever.
5. Attacker repeats from step 1 with new connections. Each new connection consumes another 5 call slots plus memory and DB resources.
6. After ~15 minutes (Linux TCP retransmission timeout), the OS finally closes each zombie connection — but by then the attacker has opened many more.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` is a **per-connection** cap, not a global one. It does not bound total resource consumption across many connections.
- No `maxConnections` is configured anywhere in the grpc Java code.
- The nginx `grpc_read_timeout 600s` only applies to deployments fronted by the provided nginx proxy; direct access to port 5600 bypasses it entirely.

### Impact Explanation
Each zombie connection holds: (a) Netty channel state and buffers, (b) up to 5 Reactor `Flux` subscription chains, (c) potentially one or more database connections/cursors from the retriever polling loop. Accumulating hundreds of zombie connections exhausts the `applicationTaskExecutor` thread pool, database connection pool, and JVM heap, causing legitimate `subscribeTopic` calls to be rejected or time out. This is a denial-of-service against the gRPC topic subscription service — the primary real-time data delivery path for Hedera mirror node consumers.

### Likelihood Explanation
No authentication or rate limiting is required to open gRPC connections to port 5600. The attack requires only a TCP client and the ability to silently drop outbound packets (trivially done with `iptables` on any Linux host, or by using a cloud security group to block return traffic). It is fully repeatable and scriptable. The 15-minute zombie window per connection means a low-rate attacker (one new connection every few seconds) can accumulate thousands of zombie connections over time without triggering obvious traffic-volume alerts.

### Recommendation
Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);       // server probes every 30s
serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);    // close if no pong in 10s
serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);    // evict idle connections
serverBuilder.maxConnectionAge(1, TimeUnit.HOURS);       // bound connection lifetime
serverBuilder.maxConnectionAgeGrace(30, TimeUnit.SECONDS);
```

Expose these as configurable fields in `NettyProperties` (alongside `maxConcurrentCallsPerConnection`) so operators can tune them. Also consider adding a global `maxConnections` limit via `NettyServerBuilder` to bound total concurrent connections regardless of per-connection call counts.

### Proof of Concept
```bash
# Terminal 1: open 5 streaming calls on one connection (grpcurl keeps the stream open)
for i in $(seq 1 5); do
  grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
    localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Terminal 2: silently drop return packets so the server sees a live connection
iptables -I OUTPUT -p tcp --dport 5600 -j DROP

# The server now holds 5 zombie call slots on this connection indefinitely.
# Repeat in a loop to accumulate zombie connections and exhaust server resources.
# Verify with: ss -tnp | grep 5600   (connections remain ESTABLISHED on server)
```