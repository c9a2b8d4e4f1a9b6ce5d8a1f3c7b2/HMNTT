### Title
Unbounded Historical Replay + Indefinite Live Subscription via Unconstrained `startTime=0` and Arbitrarily Large `endTime`

### Summary
An unprivileged gRPC client can set `consensusStartTime` to epoch (0) and `consensusEndTime` to a value far in the future (e.g., year 2262 or beyond), causing `subscribeTopic()` to first stream every historical message ever stored for a topic and then hold the live subscription open indefinitely. No per-connection limits, no maximum subscription duration, and no upper bound on `endTime` exist to prevent this. Multiple concurrent such connections can exhaust database connections, memory, and network bandwidth.

### Finding Description

**Code path: `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 59–92**

```
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);   // line 63
Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));      // line 64
Flux<TopicMessage> flux = historical
    .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)));  // line 72-73
if (filter.getEndTime() != null) {
    flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime()); // line 80
}
```

**Root cause 1 — `startTime = 0` is explicitly permitted.**
`TopicMessageFilter.java` line 49–51:
```java
public boolean isValidStartTime() {
    return startTime <= DomainUtils.now();   // 0 <= now() is always true
}
```
The `@Min(0)` annotation on `startTime` (line 28) also explicitly allows zero. The test at `TopicMessageServiceTest.java:207` confirms `startTime(0)` is a supported, passing value.

**Root cause 2 — `endTime` has no upper bound.**
`TopicMessageFilter.java` line 43–46:
```java
public boolean isValidEndTime() {
    return endTime == null || endTime > startTime;  // only checks ordering, no ceiling
}
```

**Root cause 3 — `pastEndTime()` never signals completion for a far-future `endTime`.**
`TopicMessageServiceImpl.java` lines 123–131:
```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
    return Flux.empty()
        .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
            .withFixedDelay(grpcProperties.getEndTimeInterval()));
}
```
`isComplete()` (lines 203–215) evaluates:
```java
return Instant.ofEpochSecond(0, filter.getEndTime())
    .plus(grpcProperties.getEndTimeInterval())
    .isBefore(Instant.now());
```
With `endTime = Long.MAX_VALUE` nanoseconds (≈ year 2262), this condition is never true in any realistic timeframe, so `pastEndTime()` emits nothing and the live Flux runs forever.

**Root cause 4 — `ConsensusController.convertTimestamp()` maps any timestamp ≥ 9223372035 seconds to `Long.MAX_VALUE`** (line 77), making it trivial to reach the maximum value from the gRPC wire format.

**Root cause 5 — No subscriber count limit.** `subscriberCount` (line 48) is only a Micrometer gauge metric; it is never checked against a ceiling to reject new connections.

### Impact Explanation
An attacker with no credentials can:
1. **Exhaust the database**: The historical Flux issues paginated queries across all messages from epoch to now for the target topic. For a high-traffic topic this can be millions of rows, consuming R2DBC connection pool slots and CPU for the entire replay duration.
2. **Hold a live subscription open for years**: After historical replay completes, the live Flux subscribes to the `TopicListener` indefinitely. Each open subscription consumes a thread/scheduler slot, a gRPC stream, and listener resources.
3. **Amplify with concurrent connections**: Because there is no per-IP or global subscriber cap, an attacker can open hundreds of such subscriptions simultaneously, multiplying the resource drain.

Severity is **Medium** (griefing / resource exhaustion with no direct economic loss to network participants), consistent with the stated scope.

### Likelihood Explanation
- **No authentication required**: The gRPC endpoint is publicly accessible.
- **Trivial to craft**: A standard gRPC client sets `consensusStartTime.seconds = 0` and `consensusEndTime.seconds = 9223372035` (or any large value).
- **Repeatable**: The attacker can reconnect immediately after any server-side disconnect and re-open the same subscription.
- **No rate limiting in the gRPC layer**: Unlike the REST/web3 modules (which have `ThrottleManager`), the gRPC module has no equivalent throttle.

### Recommendation
1. **Cap `endTime` relative to the current time**: Add a validation constraint in `TopicMessageFilter` rejecting `endTime` values more than a configurable maximum (e.g., 30 days) in the future.
2. **Enforce a maximum subscription duration**: In `pastEndTime()` or `subscribeTopic()`, add an absolute wall-clock timeout (e.g., via `Flux.timeout()`) regardless of `endTime`.
3. **Limit historical window**: Reject or page-cap requests where `endTime - startTime` exceeds a configurable threshold (e.g., 7 days of nanoseconds).
4. **Enforce a global or per-IP subscriber ceiling**: Check `subscriberCount` against a configurable maximum before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
5. **Validate `startTime` minimum age**: Consider rejecting `startTime` values older than a retention window (e.g., 90 days) to prevent full-history replays.

### Proof of Concept
```python
import grpc
from proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto.timestamp_pb2 import Timestamp
from proto.basic_types_pb2 import TopicID

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=TopicID(topicNum=1234),
    consensusStartTime=Timestamp(seconds=0, nanos=0),      # epoch — passes isValidStartTime()
    consensusEndTime=Timestamp(seconds=9223372035, nanos=0) # maps to Long.MAX_VALUE — passes isValidEndTime()
    # limit intentionally omitted (defaults to 0 = unlimited)
)

# This streams ALL historical messages then holds the live subscription open for ~292 years
for response in stub.subscribeTopic(query):
    pass  # attacker discards data; server still pays full cost
```
Repeat this in a loop across many concurrent connections to amplify resource exhaustion.