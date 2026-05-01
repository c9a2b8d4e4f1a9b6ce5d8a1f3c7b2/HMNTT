### Title
Unbounded gRPC Subscription Rate Enables DB Query Flooding via Narrow Time-Window Subscriptions

### Summary
`subscribeTopic()` in `TopicMessageServiceImpl` unconditionally triggers two database queries (entity existence check and historical message retrieval) for every subscription, with no per-IP rate limiting or global connection cap. An unprivileged attacker can open many connections and rapidly cycle through subscriptions using `startTime=0, endTime=1` — a window that passes all input validation, completes near-instantly, and allows the attacker to loop indefinitely, flooding the database with queries.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 59–92.

**Input validation passes for `startTime=0, endTime=1`:**

`TopicMessageFilter.java` lines 43–51:
- `isValidEndTime()`: `endTime > startTime` → `1 > 0` → ✓ passes
- `isValidStartTime()`: `startTime <= DomainUtils.now()` → `0 <= now` → ✓ passes

**Per-subscription resource allocation (lines 63–91):**

1. **Line 87 / `topicExists()`**: calls `entityRepository.findById(topicId.getId())` — a synchronous DB query on every subscription.
2. **Line 63**: `topicMessageRetriever.retrieve(filter, true)` — triggers a DB query for messages with `consensusTimestamp >= 0 AND consensusTimestamp < 1`. This range is epoch to epoch+1 nanosecond; it returns zero rows but still executes a full indexed DB query.
3. **Lines 67–70**: `Mono.delay(Duration.ofSeconds(1L))` — a 1-second reactor timer is scheduled unconditionally on `Schedulers.boundedElastic()`.

**Why `isComplete()` is only a partial mitigation:**

`TopicContext.isComplete()` (lines 203–215) evaluates `filter.getEndTime() < startTime` where `startTime = DomainUtils.now()` (nanoseconds since epoch, ~1.7 × 10¹⁸). With `endTime=1`, `1 < now` → `true` → `isComplete()` returns `true` immediately. This prevents:
- The safety-check DB query (line 68 filter: `!topicContext.isComplete()` → false)
- The live listener setup (line 109: `incomingMessages` returns `Flux.empty()`)

But it does **not** prevent the two DB queries in steps 1 and 2 above, which fire unconditionally before `isComplete()` is ever consulted.

**No global rate limiting or connection cap:**

`GrpcConfiguration.java` lines 31–34 applies only `maxConcurrentCallsPerConnection(5)` — a per-connection concurrency cap. There is no:
- Per-IP connection limit
- Global connection limit
- Subscription rate limit
- Global subscriber count cap (the `subscriberCount` AtomicLong at line 48 is a metrics gauge only, not enforced)

An attacker opens `C` connections × 5 concurrent calls = `5C` simultaneous subscriptions. Since each subscription with `endTime=1` completes near-instantly (empty result), the attacker immediately re-subscribes, sustaining a continuous flood.

### Impact Explanation

Each subscription cycle causes at minimum two database round-trips. With no rate limiting, an attacker with modest network resources can sustain thousands of DB queries per second against the mirror node's read replica. This exhausts the DB connection pool (default `maxConnections=10` for REST; gRPC shares the same backing DB), degrades query latency for legitimate subscribers, and can cause OOM pressure from accumulated `TopicContext` / `AtomicLong` / `Stopwatch` allocations and pending reactor timer tasks. The `boundedElastic` scheduler accumulates 1-second timer tasks at the subscription rate, which can saturate the scheduler queue. The impact is service degradation or denial for all mirror node consumers — no economic damage to the Hedera network itself, consistent with the Medium griefing classification.

### Likelihood Explanation

No special privileges, tokens, or accounts are required. Any client with network access to port 5600 can execute this attack. The only prerequisite is knowing a valid topic ID (or having `checkTopicExists=false` configured). The attack is trivially scriptable with any gRPC client library. The `maxConcurrentCallsPerConnection=5` limit is easily bypassed by opening additional TCP connections, which is unrestricted. The attack is repeatable indefinitely and requires no state.

### Recommendation

1. **Add per-IP connection rate limiting** at the Netty/gRPC layer (e.g., `NettyServerBuilder.maxConnectionsPerIp` or an external proxy like Envoy with rate limiting).
2. **Enforce a global or per-IP subscription rate limit** in `subscribeTopic()` using a token-bucket (similar to the `Bucket4j` pattern already used in `web3/ThrottleConfiguration.java`).
3. **Add a minimum time-window size** validation in `TopicMessageFilter.isValidEndTime()` — e.g., reject subscriptions where `endTime - startTime < threshold` to prevent trivially-completing subscriptions from being used as a cycling mechanism.
4. **Enforce a global cap on `subscriberCount`** — currently it is a metric gauge only; add a hard reject when it exceeds a configured maximum.
5. **Defer the historical retrieval** until after `isComplete()` is evaluated, so subscriptions that are already complete at construction time skip the DB query entirely.

### Proof of Concept

```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# proto-generated stub for ConsensusService
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = "0.0.12345"  # any valid topic

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    while True:
        try:
            req = consensus_pb2.ConsensusTopicQuery(
                topicID=...,   # TOPIC_ID encoded
                consensusStartTime=...,  # startTime = 0
                consensusEndTime=...,    # endTime   = 1  (nanoseconds)
            )
            # Each call triggers 2 DB queries and completes near-instantly
            list(stub.subscribeTopic(req))
        except Exception:
            pass  # reconnect and continue

# Open 200 connections, each cycling subscriptions as fast as possible
# 200 connections × 5 concurrent calls = 1000 simultaneous subscriptions
# Each completes in <10ms → ~100 subscription cycles/sec/connection
# = ~20,000 DB queries/sec sustained
with ThreadPoolExecutor(max_workers=200) as pool:
    pool.map(flood_connection, range(200))
```

**Expected result:** DB connection pool exhaustion within seconds; `hiero.mirror.grpc.subscribers` gauge spikes; legitimate subscribers experience timeouts or errors.