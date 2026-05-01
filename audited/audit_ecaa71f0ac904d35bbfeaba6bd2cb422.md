### Title
Missing Server-Side gRPC Keepalive and Connection Lifetime Limits Enable Indefinite Resource Retention Across Network Partitions

### Summary
`grpcServerConfigurer()` in `GrpcConfiguration.java` configures the Netty gRPC server with only a thread executor and a per-connection call cap, omitting all server-side liveness detection (`keepAliveTime`, `keepAliveTimeout`) and connection lifetime controls (`maxConnectionAge`, `maxConnectionIdle`). When a network partition occurs — or is deliberately induced by an attacker dropping packets without sending TCP RST — the server has no application-layer mechanism to detect dead connections and will hold all associated resources (HTTP/2 stream state, Reactive subscriptions, Redis/polling listener subscriptions) indefinitely. Any unprivileged user can trigger this condition against the public `subscribeTopic` streaming endpoint.

### Finding Description
**Exact code location:** `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35.

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // NO keepAliveTime / keepAliveTimeout
    // NO maxConnectionAge / maxConnectionIdle
};
```

`NettyServerBuilder` exposes `keepAliveTime(long, TimeUnit)`, `keepAliveTimeout(long, TimeUnit)`, `maxConnectionAge(long, TimeUnit)`, and `maxConnectionIdle(long, TimeUnit)`, none of which are invoked here. `NettyProperties` only carries `maxConcurrentCallsPerConnection = 5` — no keepalive or lifetime fields exist.

**Root cause / failed assumption:** The design assumes that TCP-layer teardown will eventually reclaim dead connections. In practice, default OS TCP keepalive fires after ~2 hours (and is not guaranteed in cloud/container environments). Without gRPC-level HTTP/2 PING-based liveness probing, the server never sends a PING frame to verify the peer is alive, so a silently-partitioned connection is indistinguishable from a slow-but-live one.

**Exploit flow:**
1. Attacker opens M TCP connections to port 5600 (no authentication required on the public mirror node API).
2. On each connection, attacker initiates up to 5 `subscribeTopic` server-streaming calls (the per-connection cap).
3. Attacker uses `iptables -A OUTPUT -p tcp --dport 5600 -j DROP` (or equivalent) to silently discard all outbound packets — no RST is sent, so the server's TCP stack sees the connection as alive.
4. The server's Netty event loop never receives a FIN or RST; without a PING timeout, it never closes the stream.
5. Each call retains: an HTTP/2 stream slot in Netty, a Reactive `Flux` subscription to the Redis/polling topic listener, and associated heap objects.
6. Attacker repeats across many source IPs or ephemeral ports to accumulate zombie calls.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` caps calls *per connection* but places no bound on the number of connections, so M connections yield 5M retained call slots.
- `retriever.timeout = 60s` applies only to the historical-message retriever path; live streaming subscriptions (Redis listener) have no equivalent idle timeout.
- The nginx `grpc_read_timeout 600s` is a proxy-layer setting that resets on each received message; it does not help when the proxy-to-server leg is partitioned, and it is absent for non-`subscribeTopic` gRPC paths entirely.
- No server-side interceptor enforcing a per-call deadline was found anywhere under `grpc/src/main/java/`.

### Impact Explanation
Each zombie call holds a Reactive subscription to the shared Redis or polling topic listener, an HTTP/2 stream entry in Netty's internal stream table, and heap memory for stream metadata. Accumulating enough zombie calls exhausts the `applicationTaskExecutor` thread pool (for any synchronous work dispatched per-call), fills Netty's stream table, and causes legitimate subscribers to be rejected or starved. This is a server-side resource-exhaustion DoS requiring no credentials.

### Likelihood Explanation
The `subscribeTopic` endpoint is a public, unauthenticated API by design. Inducing a one-sided network partition from the client side requires only standard OS networking tools (`iptables`, `nftables`, or a raw socket that never sends RST). No exploit code, no credentials, and no knowledge of internal state are required. The attack is repeatable and scalable across many source addresses or ephemeral ports. The nginx `grpc_read_timeout 600s` comment in `docker-compose.yml` (line 225–226) confirms the operator is aware that these calls are long-lived, making the absence of server-side liveness enforcement a realistic operational gap.

### Recommendation
In `grpcServerConfigurer()`, add the following to the `NettyServerBuilder` lambda:

```java
serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);
serverBuilder.permitKeepAliveTime(10, TimeUnit.SECONDS);
serverBuilder.permitKeepAliveWithoutCalls(true);
serverBuilder.maxConnectionAge(1, TimeUnit.HOURS);
serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);
```

Expose `keepAliveTime`, `keepAliveTimeout`, `maxConnectionAge`, and `maxConnectionIdle` as configurable fields in `NettyProperties` so operators can tune them per environment. Additionally, consider adding a server-side `ServerInterceptor` that checks `Context.current().getDeadline()` and enforces a maximum call duration for streaming RPCs.

### Proof of Concept
```bash
# 1. Start a subscribeTopic streaming call (grpcurl, no auth needed)
grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &

# 2. Immediately drop all outbound packets to the server (simulate partition)
sudo iptables -A OUTPUT -p tcp --dport 5600 -j DROP

# 3. Observe on the server: the call remains in OPEN state indefinitely.
#    Repeat steps 1-2 from many clients / source ports to accumulate zombie calls.
#    Monitor server heap / Netty stream table growth to confirm resource retention.

# 4. Verify no PING frames are sent by the server (Wireshark / tcpdump):
sudo tcpdump -i any -n 'tcp port 5600 and tcp[13] & 0x08 != 0'
# No HTTP/2 PING frames will appear, confirming absence of keepalive probing.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L27-30)
```java
    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```
