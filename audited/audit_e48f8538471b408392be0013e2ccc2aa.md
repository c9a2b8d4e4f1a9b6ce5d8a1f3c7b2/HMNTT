### Title
Insufficient Jitter in `PollingTopicListener` Causes Synchronized DB Query Storms Under Concurrent Subscriber Load

### Summary
`PollingTopicListener.listen()` creates an independent per-subscriber polling loop using `RepeatSpec` with only 10% jitter (±50ms on a 500ms interval). Because there is no `retryWhen` in this listener, any DB error terminates subscriber streams, forcing all clients to reconnect simultaneously. Upon reconnection, the 100ms total jitter window is mathematically insufficient to desynchronize hundreds or thousands of concurrent subscribers, producing synchronized DB query bursts every polling cycle.

### Finding Description
**Exact code path**: `grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `listen()`, lines 38–43:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
```

**Root cause — three compounding design failures**:

1. **Per-subscriber polling**: Unlike `SharedPollingTopicListener` (which uses a single shared loop for all subscribers), `PollingTopicListener` (POLL mode) creates a completely independent `Flux` chain and DB polling loop for every subscriber. N subscribers = N concurrent DB queries every interval.

2. **No error retry**: `PollingTopicListener` has no `retryWhen` (contrast with `SharedPollingTopicListener` which has `retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))`). When a DB error occurs (e.g., during a network partition), the subscriber's stream terminates. All clients must reconnect from scratch.

3. **Insufficient jitter**: `jitter(0.1)` on a 500ms interval produces a ±50ms spread (100ms total window). For N subscribers reconnecting simultaneously, the expected inter-poll gap is `100ms / N`. At N=200 subscribers, the gap is 0.5ms — effectively a synchronized burst. Each `poll()` call executes `topicMessageRepository.findByFilter(newFilter)` with up to `maxPageSize=5000` rows.

**No total subscriber limit exists**: `GrpcConfiguration.java` line 33 only enforces `maxConcurrentCallsPerConnection=5` (default), but there is no cap on total connections or total active subscribers across connections. `ConsensusController.subscribeTopic()` has no authentication or rate-limiting gate.

**Exploit flow**:
- Attacker opens K connections × 5 subscriptions each = 5K concurrent subscribers in POLL mode
- A network partition (natural or attacker-induced via TCP RST injection) causes DB connection failures
- All subscriber `Flux` chains terminate with errors (no `retryWhen` to absorb the failure)
- Upon partition recovery, all 5K clients reconnect within a short window
- All new polling loops fire their first query at `T + 500ms ± 50ms`
- DB receives 5K queries within a 100ms window, each potentially fetching 5000 rows = up to 25M row reads in 100ms
- This repeats every 500ms ± 50ms indefinitely

### Impact Explanation
The DB is subjected to a synchronized query storm every polling interval. With `maxPageSize=5000` (default, `ListenerProperties.java` line 26) and many concurrent subscribers, each burst can saturate DB connection pools and I/O bandwidth, causing query timeouts (`db.statementTimeout=10000ms`), cascading failures to all subscribers, and potential full service unavailability. The impact is a repeating DoS against the database layer, not a one-time spike — the synchronization persists because all subscribers share the same base timing after reconnection.

### Likelihood Explanation
**Precondition**: The operator must configure `hiero.mirror.grpc.listener.type=POLL` (not the default `REDIS`). This is a non-default configuration but is a documented and supported mode. Public mirror node deployments that use POLL mode are fully exposed. The attack requires no credentials — `subscribeTopic` is unauthenticated per `ConsensusController.java`. An attacker needs only a gRPC client library and the ability to open many TCP connections, which is trivially achievable. The partition trigger can be natural (infrastructure event) or attacker-assisted (TCP RST flood against the mirror node's DB connection). The thundering herd repeats automatically on every polling cycle after reconnection, requiring no sustained attacker effort.

### Recommendation
1. **Replace `jitter(0.1)` with a larger jitter factor** (e.g., `jitter(0.5)` or higher) to spread a 500ms interval across a 500ms window instead of 100ms.
2. **Add `retryWhen` with exponential backoff** to `PollingTopicListener` (matching `SharedPollingTopicListener`'s pattern) so that DB errors do not terminate subscriber streams and force mass reconnection.
3. **Add a global subscriber count cap** enforced in `TopicMessageServiceImpl.subscribeTopic()` using the existing `subscriberCount` atomic counter (line 48) — reject new subscriptions above a configurable threshold.
4. **Consider randomizing the initial `delaySubscription`** per subscriber (e.g., `interval * random(0,1)`) rather than using the fixed `interval` for all, to break initial synchronization at subscription time.
5. **Prefer `SHARED_POLL` or `REDIS` mode** for production deployments; document that `POLL` mode is unsuitable for high-concurrency scenarios.

### Proof of Concept
```
# Precondition: mirror node configured with type=POLL, interval=500ms

# Step 1: Open 200 connections × 5 subscriptions = 1000 concurrent subscribers
for i in $(seq 1 200); do
  grpcurl -plaintext -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
    mirror-node:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Step 2: Observe DB query rate (baseline ~1000 queries/500ms = 2000 qps)

# Step 3: Simulate partition recovery — kill and restore DB connectivity simultaneously
# (e.g., iptables DROP then ACCEPT on DB port, or restart DB)
iptables -A OUTPUT -p tcp --dport 5432 -j DROP
sleep 5
iptables -D OUTPUT -p tcp --dport 5432 -j DROP

# Step 4: All 1000 subscriber streams terminate with DB errors (no retryWhen)
# Step 5: All clients reconnect within seconds; all new polling loops fire at T+500ms ± 50ms
# Step 6: DB receives ~1000 queries within 100ms window = ~10,000 qps burst
# Step 7: Burst repeats every 500ms ± 50ms indefinitely
# Observable: DB CPU/connection saturation, query timeouts, subscriber errors
```