### Title
Unbounded Concurrent Subscription Resource Exhaustion via Throttled Historical Retrieval

### Summary
`PollingTopicMessageRetriever.retrieve()` with `throttled=true` and no limit sets `numRepeats = Long.MAX_VALUE` and only terminates when a DB page returns fewer than `maxPageSize` (1000) messages. There is no per-IP connection limit and no global subscription cap, only a per-connection call limit of 5. An unprivileged attacker can open many connections and subscriptions against a topic with a large message backlog, causing repeated scheduler thread acquisition and DB connection consumption every 2 seconds per subscription, exhausting both the `boundedElastic` thread pool and the DB connection pool and denying service to legitimate subscribers.

### Finding Description

**Code path:**

`PollingTopicMessageRetriever.retrieve()` (lines 45–63):

```java
scheduler = Schedulers.boundedElastic();  // line 41 — single shared instance, bounded thread pool

PollingContext context = new PollingContext(filter, throttled);
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .jitter(0.1)
        .withFixedDelay(context.getFrequency())   // 2s default
        .withScheduler(scheduler))
    ...
    .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))  // infinite retry
    .timeout(retrieverProperties.getTimeout(), scheduler)             // 60s inactivity only
```

When `throttled=true`:

```java
numRepeats = Long.MAX_VALUE;                          // line 99
frequency  = retrieverProperties.getPollingFrequency(); // 2s
maxPageSize = retrieverProperties.getMaxPageSize();     // 1000
```

`isComplete()` (lines 121–128):

```java
if (throttled) {
    return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
}
```

`pageSize` is reset to 0 at the start of every poll (line 73). For a topic whose backlog fills a full page (≥ 1000 messages), `isComplete()` returns `false` after every poll, so the stream never self-terminates. The `.timeout(60s)` is an **inactivity** timeout — it only fires if no item is emitted for 60 consecutive seconds. Against a topic with a large or continuously growing backlog, it never fires.

**Why the existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (`NettyProperties` line 14, `GrpcConfiguration` line 33) limits streams **per TCP connection**, not total connections or total subscriptions. There is no per-IP connection limit and no global subscription cap anywhere in the codebase.
- The `subscriberCount` gauge (line 48, `TopicMessageServiceImpl`) is metrics-only; it enforces nothing.
- `Retry.backoff(Long.MAX_VALUE, ...)` (line 58) means transient DB errors are retried indefinitely, compounding resource pressure.
- `Schedulers.boundedElastic()` (line 41) is a single shared instance for the retriever. Its default thread cap is `10 × availableProcessors`. Each active subscription acquires a thread every 2 seconds for the duration of a DB poll. With enough concurrent subscriptions the pool saturates and legitimate poll tasks queue behind attacker tasks.

### Impact Explanation

Each attacker subscription issues a `topicMessageRepository.findByFilter()` DB query every 2 seconds. With *N* concurrent attacker subscriptions, the server sustains *N/2* extra DB queries per second. The DB connection pool (typically 10–20 connections) is exhausted first; subsequent legitimate queries block or fail. Simultaneously, the shared `boundedElastic` scheduler (used for both the repeat delay and the `.timeout()` operator) fills its thread pool, delaying or starving legitimate subscriptions' poll tasks and timeout enforcement. The result is a complete or partial denial of the gRPC topic-subscription service to all other clients.

### Likelihood Explanation

No authentication or authorization is required to call `subscribeTopic`. The attacker needs only a valid topic ID with a message backlog ≥ 1000 (trivially satisfied on mainnet/testnet for any active topic, or by pre-seeding a topic). Opening hundreds of TCP connections from a single host or a small botnet is trivial. The per-connection call limit of 5 means 200 connections yield 1000 concurrent subscriptions, each polling the DB every 2 seconds — 500 DB queries/second against a pool of ~10 connections. This is fully repeatable and requires no privileged access.

### Recommendation

1. **Global and per-IP subscription limit**: Enforce a hard cap on total concurrent subscriptions (e.g., reject new subscriptions when `subscriberCount` exceeds a configurable threshold) and a per-source-IP connection/subscription limit at the Netty or load-balancer layer.
2. **Absolute stream duration limit**: Replace or supplement the inactivity `.timeout()` with a wall-clock maximum duration so that no single historical retrieval stream can run longer than a configured ceiling regardless of message flow.
3. **Separate scheduler per concern**: Use a dedicated, more tightly bounded scheduler for the retriever's repeat/delay so that attacker subscriptions cannot saturate the scheduler shared with timeout enforcement.
4. **DB query rate cap per subscription**: Introduce a token-bucket or semaphore guard around `topicMessageRepository.findByFilter()` to bound the aggregate query rate from the retriever.

### Proof of Concept

```
# Precondition: topic 0.0.X has >= 1000 messages in its backlog (any active mainnet topic)

# Open 200 TCP connections, each with 5 concurrent subscribeTopic streams (no limit, startTime=0)
# Using grpc-client or a simple loop with grpcurl:

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{
      "topicID": {"shardNum":0,"realmNum":0,"topicNum": X},
      "consensusStartTime": {"seconds":0,"nanos":0}
    }' <mirror-node>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Result: 1000 concurrent subscriptions each polling the DB every 2s
# = 500 DB queries/second against a ~10-connection pool
# Legitimate subscribeTopic calls begin timing out or returning errors within seconds
```