### Title
Unbounded Indefinite Polling in `PollingTopicListener.listen()` Enables Resource Exhaustion DoS

### Summary
`PollingTopicListener.listen()` creates a Flux pipeline that repeats `Long.MAX_VALUE` times with no timeout operator, no subscription count enforcement, and no termination condition when neither `endTime` nor `limit` is set. An unprivileged attacker can open many gRPC connections and subscribe to any valid topic with no `endTime`/`limit`, causing each subscription to independently issue DB queries every 500 ms indefinitely, exhausting the database connection pool and degrading service for all users.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `listen()`, lines 34–49:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)   // effectively infinite
                .jitter(0.1)
                .withFixedDelay(interval)              // default 500 ms
                .withScheduler(scheduler))
        // NO .timeout(...) operator
        .doOnNext(context::onNext)
        .doOnSubscribe(s -> log.info(...));
```

**Root cause:** No `.timeout()` operator is applied to the pipeline. `RepeatSpec.times(Long.MAX_VALUE)` is effectively infinite. Compare with `PollingTopicMessageRetriever.retrieve()` (line 59), which explicitly applies `.timeout(retrieverProperties.getTimeout(), scheduler)` — the listener has no equivalent.

**Termination conditions that can be bypassed:**

- `TopicMessageServiceImpl.subscribeTopic()` applies `flux.take(filter.getLimit())` only when `filter.hasLimit()` is true (line 83–85). `limit` defaults to `0`, meaning `hasLimit()` returns `false`.
- `takeUntilOther(pastEndTime(topicContext))` is only active when `endTime != null` (line 73). When `endTime` is null, `pastEndTime()` returns `Flux.never()` (line 124–125), so the subscription never terminates.
- `subscriberCount` (line 48) is a metric gauge only — it is never checked against a maximum; no enforcement exists.

**Exploit flow:**

1. Attacker opens `C` gRPC connections to the mirror node configured in `POLL` mode.
2. Each connection issues up to `maxConcurrentCallsPerConnection` (default 5) `subscribeTopic` calls with a valid `topicId`, no `endTime`, and no `limit`.
3. Each subscription creates its own `PollingContext` and independent polling loop.
4. Every 500 ms (default `interval`), each subscription calls `topicMessageRepository.findByFilter()` — a real DB query.
5. Total DB query rate = `C × 5 × 2 queries/second`. With `C = 100` connections: 1,000 DB queries/second from attacker alone.
6. The HikariCP connection pool is exhausted; legitimate queries time out or fail.

**Why existing checks are insufficient:**

- `maxConcurrentCallsPerConnection = 5` limits calls per TCP connection but there is no global connection limit configured in `GrpcConfiguration.java` (lines 27–35). An attacker opens many connections.
- `Schedulers.boundedElastic()` caps threads at `10 × CPU cores` but has a task queue of 100,000 — polling tasks queue up without being dropped.
- `checkTopicExists` (default `true`) requires a valid topic, but any publicly known topic ID satisfies this.

### Impact Explanation

When the listener type is `POLL`, each attacker-controlled subscription independently and indefinitely queries the database. The HikariCP pool (monitored via `hikaricp_connections_active / hikaricp_connections_max > 0.75` alert in `charts/hedera-mirror-common/alerts/rules.yaml` lines 68–90) becomes saturated. Legitimate subscribers receive no messages or connection errors. The mirror node's gRPC service becomes unavailable for all users, constituting a non-network-based DoS against the HCS (Hedera Consensus Service) subscription infrastructure.

### Likelihood Explanation

The attack requires only a valid topic ID (publicly observable on-chain) and the ability to open multiple TCP connections to the gRPC port (5600). No authentication, no privileged access, and no special knowledge is required. The attack is trivially repeatable and scriptable. The only prerequisite is that the deployment uses `POLL` listener type (`hiero.mirror.grpc.listener.type=POLL`), which is a documented and supported configuration option.

### Recommendation

1. **Add a timeout to `PollingTopicListener.listen()`** mirroring `PollingTopicMessageRetriever`: add `.timeout(listenerProperties.getMaxSubscriptionDuration(), scheduler)` to terminate stale subscriptions.
2. **Enforce a maximum subscriber count** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount.get()` against a configurable maximum and return an error if exceeded.
3. **Add a `maxSubscriptionDuration` property** to `ListenerProperties` (analogous to `RetrieverProperties.timeout`) so operators can cap how long a single subscription may live.
4. **Configure Netty `maxConnectionAge`** via `NettyServerBuilder` to force-recycle long-lived connections and prevent indefinite resource holding.

### Proof of Concept

```bash
# Precondition: mirror node running with listener.type=POLL, topic 0.0.12345 exists

# Open 100 concurrent indefinite subscriptions (no endTime, no limit)
for i in $(seq 1 100); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 12345}, "consensusStartTime": {"seconds": 0}}' \
    mirror-node:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Each subscription polls DB every 500ms forever.
# After ~20 connections: HikariCP active connections > 75% threshold.
# After ~pool_size connections: legitimate queries fail with connection timeout.
# Monitor: watch hikaricp_connections_active metric spike to pool maximum.
```