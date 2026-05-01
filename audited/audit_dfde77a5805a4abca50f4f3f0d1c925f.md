### Title
Unbounded Concurrent Subscriptions Trigger Unthrottled Safety-Check Bursts Causing DB Exhaustion

### Summary
Any unauthenticated client can open an unlimited number of gRPC topic subscriptions. One second after each subscription is established, an internal safety check unconditionally invokes `topicMessageRetriever.retrieve(filter, false)` — the unthrottled path — which issues up to 12 sequential DB queries of 5,000 rows each (60,000 rows per subscription). With no global subscription cap and only a per-TCP-connection limit of 5 concurrent calls, an attacker using many connections can flood the database connection pool and JVM heap, degrading or halting HCS message delivery for all legitimate subscribers.

### Finding Description

**Code path 1 — unthrottled page size assignment**
`PollingTopicMessageRetriever.java`, `PollingContext` constructor, lines 102–107:
```java
} else {
    RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
    numRepeats = unthrottled.getMaxPolls();          // default 12
    frequency = unthrottled.getPollingFrequency();   // default 20 ms
    maxPageSize = unthrottled.getMaxPageSize();       // default 5000
}
```
Each unthrottled `PollingContext` issues up to 12 polls × 5,000 rows = **60,000 rows** per invocation.

**Code path 2 — safety check unconditionally triggers unthrottled retrieval**
`TopicMessageServiceImpl.java`, lines 66–70:
```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```
`TopicContext.isComplete()` returns `false` whenever `filter.getEndTime() == null` (the normal case for live subscriptions). Therefore the safety check fires for **every** subscription after 1 second.

`missingMessages(topicContext, null)` (line 149) calls:
```java
return topicMessageRetriever.retrieve(gapFilter, false);   // throttled=false
```

**Code path 3 — no global subscription limit**
`TopicMessageServiceImpl.java`, line 48:
```java
private final AtomicLong subscriberCount = new AtomicLong(0L);
```
`subscriberCount` is a Micrometer gauge only; it is never checked against a maximum before accepting a new subscription.

**Code path 4 — indefinite retry amplifies the attack**
`PollingTopicMessageRetriever.java`, line 58:
```java
.retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
```
If the DB becomes overloaded and queries fail, each subscription retries indefinitely, sustaining the load rather than shedding it.

**Root cause:** The design assumes that the unthrottled path is only reached occasionally (gap recovery) and that the number of concurrent subscriptions is bounded. Neither assumption is enforced in code. The only connection-level guard is `maxConcurrentCallsPerConnection = 5` (`NettyProperties.java`, line 14), which limits calls per TCP connection but imposes no cap on the number of connections or total subscriptions.

### Impact Explanation
With N attacker connections × 5 calls each = 5N concurrent subscriptions, after 1 second all safety checks fire simultaneously. Each issues 12 × 5,000-row queries. At 100 connections (500 subscriptions): **30,000,000 rows** fetched in a ~240 ms burst, repeated whenever the attacker re-subscribes. The HikariCP pool (default size not explicitly set in the gRPC module, inheriting Spring Boot defaults) saturates; legitimate subscriber queries queue indefinitely. JVM heap pressure from materializing 5,000-row `Stream` results per query accelerates GC pauses. The Prometheus alert `GrpcHighDBConnections` fires only after 5 minutes at >75% utilization — well after service degradation has begun. HCS topic message delivery to legitimate subscribers is delayed or halted.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed with no authentication required for `subscribeTopic`. An attacker needs only a standard gRPC client (e.g., `grpcurl`, the Hedera Java SDK) and the ability to open many TCP connections — trivially achievable from a single host or a small botnet. The attack is repeatable: subscriptions auto-complete after the unthrottled `maxPolls=12` cycle, so the attacker simply reconnects to re-trigger the burst. No special knowledge of the codebase is required; the behavior is observable by timing the DB load spike ~1 second after subscription.

### Recommendation
1. **Enforce a global subscription limit**: Check `subscriberCount` against a configurable maximum in `subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Add per-IP connection rate limiting** at the Netty/ingress layer (e.g., via `maxConnectionsPerIp` or an external proxy rule).
3. **Gate the safety check on a global concurrency semaphore**: Limit how many unthrottled `retrieve(filter, false)` calls can execute simultaneously across all subscriptions.
4. **Reduce unthrottled defaults or make them equal to throttled**: The 5× page-size amplification (`5000` vs `1000`) is unnecessary for gap recovery, which typically involves small numbers of missing messages.
5. **Add a `Retry` budget cap** instead of `Long.MAX_VALUE` to prevent indefinite retry storms under DB stress.

### Proof of Concept
```
# Prerequisites: grpcurl, proto files for com.hedera.mirror.api.proto.ConsensusService
# Step 1: Open 100 connections × 5 streams each = 500 concurrent subscriptions
for i in $(seq 1 500); do
  grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
    mirror-node:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Step 2: After ~1 second, observe DB connection pool saturation
# (hikaricp_connections_active / hikaricp_connections_max approaches 1.0)
# and query latency spike for legitimate subscribers.

# Step 3: Re-run the loop every ~300ms to sustain the burst after
# unthrottled maxPolls=12 cycles complete.
```

Expected result: DB connection pool exhausted, legitimate HCS subscribers experience `DEADLINE_EXCEEDED` or stalled message streams.