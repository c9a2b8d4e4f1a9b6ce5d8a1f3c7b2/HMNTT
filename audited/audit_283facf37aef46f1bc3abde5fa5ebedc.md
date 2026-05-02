### Title
Per-Subscriber Database Polling Loop Amplification via Unbounded `PollingTopicListener` Subscriptions

### Summary
When the gRPC listener is configured with type `POLL`, `PollingTopicListener.listen()` creates a fully independent, infinite database polling loop for every subscriber. Because there is no authentication, no global subscription cap, and the only per-connection limit (`maxConcurrentCallsPerConnection = 5`) is trivially bypassed by opening additional connections, an unprivileged attacker can multiply database query load linearly with the number of attacker-controlled subscriptions, degrading or denying fee-message delivery to legitimate consumers.

### Finding Description

**Code path:**

`CompositeTopicListener.getTopicListener()` (lines 46–58) selects `pollingTopicListener` when `listenerProperties.getType() == POLL`:

```
case POLL:
    return pollingTopicListener;
```

Every call to `CompositeTopicListener.listen(filter)` (line 40) therefore calls `PollingTopicListener.listen(filter)`.

`PollingTopicListener.listen()` (lines 34–49) constructs a **new, independent** `PollingContext` and a new reactive `Flux` that:
- calls `poll(context)` → `topicMessageRepository.findByFilter(newFilter)` (a live DB query)
- repeats with `RepeatSpec.times(Long.MAX_VALUE)` at a fixed `interval` (default **500 ms**)
- runs on its own `Schedulers.boundedElastic()` thread

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
```

There is **no `.share()`** call and no shared context — contrast with `SharedPollingTopicListener` (lines 41–52), which uses `.share()` so all subscribers ride a single polling loop. `PollingTopicListener` was explicitly left without sharing, meaning **N subscribers = N independent DB polling loops**.

**Root cause / failed assumption:** The design assumes the `POLL` type will only be used in low-subscriber environments, or that external rate-limiting infrastructure will cap connections. Neither assumption is enforced in code.

**No authentication or global subscription limit exists:**
- `ConsensusController.subscribeTopic()` (lines 43–53) accepts any unauthenticated gRPC request.
- `TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) only validates that the topic entity exists; `subscriberCount` is a metric gauge only — it is never checked against a maximum.
- `NettyProperties.maxConcurrentCallsPerConnection = 5` (line 14) limits calls **per TCP connection**, not total connections. An attacker opens M connections × 5 calls = 5M simultaneous polling loops.

### Impact Explanation
Each attacker subscription issues one `SELECT` against the `topic_message` table every 500 ms (configurable down to 50 ms via `@DurationMin(millis = 50)`). With 1 000 subscriptions the server executes **2 000 DB queries/second** solely for attacker traffic, consuming connection pool slots, CPU, and I/O. This directly degrades or blocks fee-schedule message delivery to legitimate subscribers on the same topic, and can exhaust the database connection pool entirely, causing service-wide outages for all gRPC consumers.

### Likelihood Explanation
The attack requires only a gRPC client and a valid topic ID (fee-schedule topics are publicly known system topics, e.g. `0.0.111`). No credentials, tokens, or on-chain funds are needed. The attacker can script hundreds of persistent gRPC connections with standard tooling (`grpcurl`, any gRPC library). The `POLL` listener type is a documented, supported configuration option. The attack is fully repeatable and can be sustained indefinitely at negligible cost to the attacker.

### Recommendation
1. **Enforce a global active-subscription ceiling** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable maximum, returning `RESOURCE_EXHAUSTED`.
2. **Add per-IP / per-client connection rate limiting** at the Netty/gRPC layer (e.g. via `maxConnectionsPerIp` or an external load-balancer policy).
3. **Deprecate or remove the `POLL` listener type** in favour of `SHARED_POLL`, which already solves the amplification problem by sharing a single polling loop across all subscribers.
4. If `POLL` must be retained, apply `.share()` or a `ConnectableFlux` pattern so all subscribers on the same topic share one polling loop, as `SharedPollingTopicListener` does.

### Proof of Concept

```bash
# Open 200 parallel gRPC connections, each with 5 concurrent subscribeTopic streams
# = 1 000 independent DB polling loops at 500 ms interval = 2 000 queries/second

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 111}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Monitor DB query rate:
# watch -n1 "psql -c \"SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%topic_message%'\""
# Expected: query count climbs proportionally to number of open subscriptions,
# legitimate fee-schedule subscribers experience increased latency or timeouts.
```