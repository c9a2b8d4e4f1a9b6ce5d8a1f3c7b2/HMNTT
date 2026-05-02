All code references in the claim are verified against the actual source. Here is the assessment:

---

# Audit Report

## Title
Unbounded Concurrent Subscriptions Exhaust Global `boundedElastic()` Scheduler in `PollingTopicListener`, Causing Polling Starvation

## Summary
When `PollingTopicListener` is the active listener type (`hiero.mirror.grpc.listener.type=POLL`), every subscriber's polling loop is scheduled on the JVM-wide `Schedulers.boundedElastic()` singleton. Because the only admission control is a per-connection stream cap of 5, an attacker opening many TCP connections can saturate the shared thread pool and starve legitimate subscribers of polling cycles.

## Finding Description

All cited line references are confirmed accurate against the repository source.

**`PollingTopicListener` stores the global Reactor scheduler as an instance field:** [1](#0-0) 

`Schedulers.boundedElastic()` is a static factory that returns the **same JVM-wide singleton** on every call. Every invocation of `listen()` attaches two scheduling operations to that pool: [2](#0-1) 

`poll()` issues a synchronous JDBC stream call via `Flux.fromStream()`, which blocks the scheduler thread for the full duration of the DB query on every repeat cycle: [3](#0-2) 

The only admission control is `maxConcurrentCallsPerConnection = 5`, a **per-connection** limit: [4](#0-3) 

Applied in `GrpcConfiguration`: [5](#0-4) 

This is not a global cap. An attacker opening `N` connections gets `5N` concurrent subscriptions with no further restriction.

**Shared pool amplification is confirmed.** The same `Schedulers.boundedElastic()` singleton is also consumed by:
- `SharedPollingTopicListener` (line 37): [6](#0-5) 
- `TopicMessageServiceImpl` safety-check path (line 70): [7](#0-6) 

**Important configuration caveat:** The default listener type is `REDIS`, not `POLL`: [8](#0-7) 

This vulnerability is active only when `hiero.mirror.grpc.listener.type` is explicitly set to `POLL`. Deployments using the default `REDIS` type or `SHARED_POLL` are not affected by the per-subscriber thread exhaustion path. `SHARED_POLL` is architecturally immune because `SharedPollingTopicListener` uses a single shared polling loop for all subscribers via `.share()`, regardless of subscriber count. [9](#0-8) 

## Impact Explanation
When the `boundedElastic` pool is saturated under `POLL` mode:
- Scheduled polling tasks queue behind attacker-owned tasks; legitimate subscribers' 500 ms polling intervals stretch arbitrarily.
- Messages written to the DB between two delayed polls are never delivered to starved subscribers.
- The safety-check `missingMessages` path in `TopicMessageServiceImpl` (line 70) also uses the same pool, so gap-recovery queries are equally starved, compounding message loss.
- The mirror node's live-streaming guarantee degrades; downstream SDK clients relying on HCS ordering receive stale or out-of-order data.

## Likelihood Explanation
- No authentication is required to call `subscribeTopic`.
- gRPC over HTTP/2 allows many multiplexed connections from a single client process.
- A valid `topicId` (publicly discoverable via the REST API) and a past `startTime` keep each subscription alive indefinitely.
- Default `boundedElastic` cap is `10 × CPU cores` (e.g., 40 threads on a 4-core pod). 8 connections × 5 streams = 40 subscriptions saturates a typical deployment.
- **Likelihood is conditional**: the attack only applies to deployments explicitly configured with `type: POLL`. Default `REDIS` deployments are unaffected.

## Recommendation
1. **Primary**: For `POLL` type deployments, replace `Schedulers.boundedElastic()` with a dedicated, bounded `Scheduler` (e.g., `Schedulers.newBoundedElastic(...)`) scoped to `PollingTopicListener`, sized to the expected maximum concurrent subscriptions.
2. **Global admission gate**: Add a global concurrent-subscription counter (an `AtomicInteger` or semaphore) in `TopicMessageServiceImpl.subscribeTopic()` that rejects new subscriptions when the limit is reached, independent of per-connection limits.
3. **Prefer `SHARED_POLL` or `REDIS`**: `SharedPollingTopicListener` is architecturally immune to this issue because it uses a single shared polling loop regardless of subscriber count. Operators should be discouraged from using `POLL` type in production.
4. **Non-blocking DB access**: Replace `Flux.fromStream()` (synchronous JDBC) with a non-blocking or async DB call to avoid holding scheduler threads during query execution.

## Proof of Concept
```
# Requires: grpc client (e.g., grpcurl), a known topicId, POLL listener type configured

for i in $(seq 1 10); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
# 50 concurrent subscriptions on a 4-core pod (boundedElastic cap = 40) saturates the pool.
# Legitimate subscribers receive no polling cycles; messages are delayed or dropped.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L61-61)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L37-37)
```java
        Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L41-52)
```java
        topicMessages = Flux.defer(() -> poll(context).subscribeOn(scheduler))
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "shared poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnCancel(() -> log.info("Cancelled polling"))
                .doOnError(t -> log.error("Error polling the database", t))
                .doOnSubscribe(context::onStart)
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L37-37)
```java
    private ListenerType type = ListenerType.REDIS;
```
