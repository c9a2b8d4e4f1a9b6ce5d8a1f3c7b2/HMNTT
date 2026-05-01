### Title
Unbounded Polling Context Creation via Unauthenticated gRPC Subscription Endpoint Enables DoS

### Summary
`PollingTopicMessageRetriever.retrieve()` uses `retrieverProperties.isEnabled()` as its sole application-level guard before allocating a long-lived `PollingContext` and scheduling an infinite DB polling loop. There is no per-IP rate limiting, no global subscriber cap, and no connection count limit on the gRPC server — only a per-connection call cap of 5. An unauthenticated attacker opening many connections can create an unbounded number of concurrent polling contexts, each issuing periodic database queries, exhausting the DB connection pool and causing a full gRPC service denial-of-service.

### Finding Description

**Exact code path:**

`PollingTopicMessageRetriever.retrieve()` — `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, lines 45–63:

```java
public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
    if (!retrieverProperties.isEnabled()) {   // ← sole guard; always true by default
        return Flux.empty();
    }

    PollingContext context = new PollingContext(filter, throttled);
    return Flux.defer(() -> poll(context))
            .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                    .withFixedDelay(context.getFrequency())   // 2s throttled, 20ms unthrottled
                    .withScheduler(scheduler))
            .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))  // infinite retries
            .timeout(retrieverProperties.getTimeout(), scheduler)             // 60s default
            ...
}
```

**Root cause:** `retrieverProperties.isEnabled()` is a static feature flag (default `true`), not a rate limiter or admission control gate. Once past it, a `PollingContext` is unconditionally allocated and a Reactor subscription chain is assembled that will issue `topicMessageRepository.findByFilter()` DB queries at `pollingFrequency` (2 s throttled / 20 ms unthrottled) for up to `timeout` seconds (60 s default), with `Long.MAX_VALUE` retries on errors.

**Failed assumption:** The design assumes that `maxConcurrentCallsPerConnection = 5` (`NettyProperties`, line 14; applied in `GrpcConfiguration`, line 33) is sufficient to bound resource consumption. It is not — it limits calls *per TCP connection* but places no cap on the number of connections.

**No authentication or IP-level rate limiting exists on the gRPC path.** The only registered `ServerInterceptor` (`GrpcInterceptor`) only sets an `EndpointContext` for table-usage tracking and calls `next.startCall()` unconditionally. The `subscriberCount` field in `TopicMessageServiceImpl` (line 48) is a metrics gauge only — it is never checked against a maximum.

**Exploit flow:**

1. Attacker opens `N` TCP connections to port 5600 (no connection count limit configured on `NettyServerBuilder`).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` gRPC streaming calls (the per-connection cap).
3. Each call reaches `subscribeTopic` → `topicMessageRetriever.retrieve(filter, true)` → passes `isEnabled()` → allocates a `PollingContext` with `numRepeats = Long.MAX_VALUE`.
4. Each `PollingContext` schedules a DB query every 2 seconds on the shared `boundedElastic()` scheduler.
5. With `N` connections: `5N` concurrent polling contexts → `5N / 2` DB queries per second sustained.
6. The default HikariCP pool is small (typically 10 connections). At modest `N` (e.g., 100 connections = 500 contexts = 250 DB queries/s), the pool is saturated; legitimate queries queue indefinitely or time out.
7. After the 60 s timeout, the attacker simply reconnects and repeats — there is no backoff or ban enforced.

### Impact Explanation

Exhausting the database connection pool causes all gRPC `subscribeTopic` calls — including legitimate ones — to stall waiting for a DB connection. The gRPC service becomes unresponsive. Because the mirror node's gRPC API is the primary interface for HCS (Hedera Consensus Service) topic subscriptions, clients relying on it for transaction confirmation lose visibility into network state for the duration of the attack. The attack is self-sustaining: the attacker only needs to maintain open connections, and the 60 s timeout is trivially defeated by reconnecting.

### Likelihood Explanation

**Preconditions:** None beyond network access to port 5600. No credentials, no API key, no prior knowledge of internal state.

**Tooling:** Standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`) suffice. Opening 100 connections with 5 streams each requires trivial scripting.

**Repeatability:** Fully repeatable and automatable. The attacker does not need to race any check — `isEnabled()` is always `true` in production. The attack is deterministic.

**Detection difficulty:** The `subscriberCount` gauge will spike, but there is no alerting threshold enforced in code, and by the time an operator notices, the DB pool is already exhausted.

### Recommendation

1. **Enforce a global concurrent-subscriber cap** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP connection rate limiting** via a gRPC `ServerInterceptor` (e.g., using Bucket4j, which is already a dependency in the web3 module) applied globally in `GrpcConfiguration`.
3. **Configure a server-level connection limit** on `NettyServerBuilder` (e.g., `serverBuilder.maxConnectionAge(...)` and a total connection count guard).
4. **Reduce the default `timeout`** for throttled polling contexts or add an exponential backoff on reconnect to prevent trivial timeout-and-reconnect loops.
5. **Add a `maxConnections` property** to `NettyProperties` and apply it in `GrpcConfiguration` alongside `maxConcurrentCallsPerConnection`.

### Proof of Concept

```bash
# Open 100 connections, 5 concurrent streams each = 500 polling contexts
# Requires grpcurl and a valid topic ID (or checkTopicExists=false)

for i in $(seq 1 100); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}}' \
      -H 'content-type: application/grpc' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Each background process holds a streaming call open.
# 500 polling contexts × 1 DB query per 2s = 250 DB queries/s sustained.
# Monitor DB pool exhaustion:
# SELECT count(*) FROM pg_stat_activity WHERE state = 'active';
# Observe gRPC latency spike to timeout for all new subscribers.
```