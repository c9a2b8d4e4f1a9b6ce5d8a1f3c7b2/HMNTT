### Title
Missing Server-Side gRPC Keepalive Enforcement Allows Dead-Client Resource Exhaustion via Network Partition

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the Netty gRPC server with only `maxConcurrentCallsPerConnection` and an executor, omitting all server-side keepalive and connection-age parameters (`keepAliveTime`, `keepAliveTimeout`, `maxConnectionAge`, `maxConnectionIdle`). When a client becomes unreachable due to a network partition without sending TCP RST/FIN, the server never detects the dead connection, the gRPC cancel handler is never invoked, and the per-subscription Reactor Flux pipeline runs indefinitely — accumulating heap, scheduler tasks, and file descriptors for each dead stream.

### Finding Description

**Exact code location:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:
```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // No keepAliveTime, keepAliveTimeout, maxConnectionAge, maxConnectionIdle
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15: only field is `maxConcurrentCallsPerConnection = 5`; no keepalive fields exist anywhere in the property hierarchy.

**Root cause:** The server never sends HTTP/2 PING frames to probe client liveness. Without a PING round-trip failure, Netty never closes the transport, so the gRPC framework never fires the cancel signal.

**Exploit flow:**

1. Attacker opens N TCP connections to port 5600 (no auth required — the service is public).
2. On each connection, attacker opens up to 5 concurrent `subscribeTopic` streams (the `maxConcurrentCallsPerConnection` limit), subscribing to a high-traffic topic with no `endTime` and no `limit`.
3. In `ConsensusController.subscribeTopic()` (lines 43–53), each stream creates a live Reactor Flux pipeline: historical retriever + live listener + 1-second safety-check poller on `Schedulers.boundedElastic()`.
4. The cancel handler (`disposable::dispose`, line 51) is registered on `ServerCallStreamObserver.setOnCancelHandler` — it only fires when the gRPC layer detects stream cancellation.
5. Attacker installs `iptables -A OUTPUT -p tcp --dport 5600 -j DROP` (or equivalent) — all packets from the client are silently dropped. No RST, no FIN, no GOAWAY.
6. The server's TCP stack sees no error. Netty sees no transport error. The gRPC framework never calls the cancel handler. `disposable::dispose()` is never called.
7. Each Flux pipeline continues: `TopicMessageServiceImpl.subscribeTopic()` keeps the `subscriberCount` incremented, the safety-check `Mono.delay(1s).flatMapMany(...)` re-arms on `boundedElastic()` every second, and `topicListener.listen()` keeps the subscriber registered in the shared listener's multicast sink.
8. HTTP/2 flow control eventually stalls writes to the dead client, but the Flux pipeline itself is not back-pressure-aware end-to-end — the `SharedPollingTopicListener` uses `onBackpressureBuffer()` with `maxBufferSize = 16384` per subscriber, which fills and holds 16 384 `TopicMessage` objects per dead stream in heap.
9. With N connections × 5 streams = 5N dead Flux pipelines, heap fills with: TopicContext objects, TopicMessageFilter objects, buffered TopicMessage objects (up to 16 384 each), scheduler task queues, and Netty channel/stream state.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` limits streams per connection but places no cap on the number of connections, so N is unbounded.
- `retriever.timeout = 60s` applies only to the historical `PollingTopicMessageRetriever` (time between DB emissions); it does not apply to the live listener path and does not close the gRPC stream.
- `endTimeInterval` only fires when a subscription has an explicit `endTime`; unlimited subscriptions (`endTime == null`) return `Flux.never()` from `pastEndTime()`, so the stream never self-terminates.
- OS-level TCP keepalive defaults (2-hour idle before probing) are far too slow to be a practical mitigation.

### Impact Explanation
Each dead unlimited subscription holds up to 16 384 buffered `TopicMessage` objects in the shared listener's per-subscriber buffer, plus Flux pipeline state, scheduler tasks, and Netty channel state. With a high-traffic topic and enough dead connections, heap is exhausted, triggering OOM and crashing the JVM — denying service to all legitimate subscribers. Even below OOM, accumulated `boundedElastic` tasks degrade scheduler throughput for live subscribers. File descriptor exhaustion is a secondary impact.

Severity: **High** — complete denial of service to all gRPC consumers of the mirror node, achievable without any credentials.

### Likelihood Explanation
The attack requires only: (1) network access to port 5600 (publicly exposed in the default deployment per `docker-compose.yml`), (2) the ability to open TCP connections and subscribe to any existing topic, and (3) the ability to silently drop return-path packets (trivially done on any attacker-controlled host with `iptables DROP` or by subscribing from behind a firewall that is then taken offline). No authentication, no special privileges, no prior knowledge beyond a valid topic ID (which is publicly discoverable). The attack is repeatable and automatable.

### Recommendation
Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);
serverBuilder.maxConnectionAge(5, TimeUnit.MINUTES);
serverBuilder.maxConnectionIdle(2, TimeUnit.MINUTES);
serverBuilder.permitKeepAliveWithoutCalls(false);
```

Expose these as configurable fields in `NettyProperties` (alongside `maxConcurrentCallsPerConnection`). With `keepAliveTime=30s` and `keepAliveTimeout=10s`, a dead client is detected within ~40 seconds, the transport is closed, the cancel handler fires, `disposable::dispose()` is called, and the Flux pipeline is torn down. `maxConnectionAge` and `maxConnectionIdle` provide defense-in-depth for connections that never send data.

### Proof of Concept

```bash
# 1. Start the mirror node gRPC server (port 5600)

# 2. Open 200 connections, each with 5 unlimited subscribeTopic streams
#    (using grpcurl in background or a custom gRPC client)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":41110},"limit":0}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# 3. Simulate network partition — drop all return-path packets
iptables -A OUTPUT -p tcp --dport 5600 -j DROP

# 4. Observe: server JVM heap grows continuously
#    jcmd <pid> VM.native_memory | grep Heap
#    or watch the Grafana dashboard metric hiero_mirror_grpc_subscribers

# 5. After sufficient time (minutes to hours depending on topic traffic and heap size),
#    the JVM throws OutOfMemoryError and the gRPC service crashes.
#    Legitimate subscribers receive no further messages.
```