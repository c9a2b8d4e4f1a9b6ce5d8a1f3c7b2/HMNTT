### Title
Unbounded INFO-Level Log Flooding via Unauthenticated gRPC Topic Subscriptions in `missingMessages()`

### Summary
An unprivileged user can open an unbounded number of concurrent gRPC connections (each with up to 5 subscriptions per the default `maxConcurrentCallsPerConnection`) to a topic that experiences sequence-number gaps in its live message stream. For every such gap, `missingMessages()` unconditionally emits an INFO-level log line containing the `subscriberId` and `topicId` — once per active subscription. With N connections × 5 subscriptions × M gaps, the attacker generates N×5×M INFO log entries, flooding the logging infrastructure and drowning out fee-related and audit-critical log signals.

### Finding Description
**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`:

- `subscribeTopic()` (line 59) creates a new `TopicContext` per subscription with no global cap on concurrent subscriptions — `subscriberCount` (line 48) is a Micrometer gauge only, never used as a gate.
- `incomingMessages()` (line 120) pipes every live message through `concatMap(t -> missingMessages(topicContext, t))`.
- Inside `missingMessages()` (lines 156–175): when `numMissingMessages > 0` (i.e., `current.getSequenceNumber() - last.getSequenceNumber() - 1 > 0`), the code unconditionally calls `log.info(...)` at lines 170–175, emitting `subscriberId` and `topicId` at INFO level — **one log line per gap per active subscription**.
- Additionally, the safety-check path (line 148) fires `log.info(...)` once per subscription after a 1-second delay, regardless of topic state.

**Root cause:** There is no rate limit, subscription cap, or log-level guard (e.g., `log.isInfoEnabled()` with a per-subscriber throttle) around either INFO log statement. The only per-connection limit is `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection = 5` (documented default), which is a per-TCP-connection limit — an attacker opens many connections.

**Why existing checks fail:**
- `subscriberCount` (line 48) is a read-only gauge; it is never checked against a maximum before accepting a new subscription.
- `topicExists()` (line 94) only validates topic type, not subscription rate.
- `maxConcurrentCallsPerConnection = 5` limits calls per connection, not total connections or total subscriptions globally.

### Impact Explanation
An attacker with only network access to the gRPC port (port 5600 by default, unauthenticated) can sustain a continuous flood of INFO-level log entries. Each entry contains `subscriberId` and `topicId`. At scale (e.g., 1000 connections × 5 subscriptions × 10 gaps/minute), this produces 50,000 INFO log lines per minute. Log aggregation systems (ELK, Splunk, CloudWatch) have ingestion rate limits; flooding at INFO level pushes out lower-volume but higher-priority audit log entries (fee modifications, entity changes), directly degrading the observability posture described in the audit scope.

### Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication required to call `subscribeTopic`. Any attacker who can identify a topic with recurring sequence-number gaps (observable by subscribing briefly and watching sequence numbers) can then open many parallel connections. This requires no special knowledge beyond the topic ID and the gRPC proto interface, both of which are public. The attack is repeatable and automatable with standard gRPC client libraries.

### Recommendation
1. **Add a global subscription cap**: Check `subscriberCount` against a configurable maximum in `subscribeTopic()` before accepting a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Downgrade or rate-gate the gap-recovery INFO log**: Change lines 170–175 to `log.warn(...)` (so it can be separately rate-limited or filtered) or introduce a per-`TopicContext` counter that suppresses repeated log lines after the first N gaps.
3. **Add per-IP or per-connection subscription rate limiting** at the Netty/gRPC interceptor layer, separate from `maxConcurrentCallsPerConnection`.
4. **Guard the safety-check log** (line 148) similarly — it fires unconditionally once per subscription.

### Proof of Concept
```
# 1. Identify or create a topic with recurring sequence-number gaps (e.g., topic 0.0.12345)
# 2. Open 200 parallel gRPC connections, each with 5 subscribeToTopic streams:
for i in $(seq 1 200); do
  grpcurl -plaintext -d '{"topicID":{"topicNum":12345},"consensusStartTime":{"seconds":0}}' \
    mirror-node:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
# 3. Each time a gap occurs in the live stream, 1000 INFO lines are written:
# "[<subscriberId>] Querying topic 0.0.12345 for missing messages between sequence X and Y"
# 4. Observe log aggregator ingestion rate spike; audit log entries for fee changes are buried.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L120-120)
```java
        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L156-175)
```java
        long numMissingMessages = current.getSequenceNumber() - last.getSequenceNumber() - 1;

        // ignore duplicate message already processed by larger subscribe context
        if (numMissingMessages <= -1) {
            log.debug("Encountered duplicate missing message to be ignored, last: {}, current: {}", last, current);
            return Flux.empty();
        }

        TopicMessageFilter newFilter = topicContext.getFilter().toBuilder()
                .endTime(current.getConsensusTimestamp())
                .limit(numMissingMessages)
                .startTime(last.getConsensusTimestamp() + 1)
                .build();

        log.info(
                "[{}] Querying topic {} for missing messages between sequence {} and {}",
                newFilter.getSubscriberId(),
                topicContext.getTopicId(),
                last.getSequenceNumber(),
                current.getSequenceNumber());
```
