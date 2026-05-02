### Title
Unbounded Global Concurrent Subscription Exhaustion via `PollingTopicListener.listen()`

### Summary
`PollingTopicListener.listen()` creates a new independent polling Flux per call with no global subscription cap. The only server-side limit (`maxConcurrentCallsPerConnection = 5`) is scoped per TCP connection, not globally. An unprivileged attacker opening many connections can accumulate an unbounded number of active subscriptions, exhausting the database connection pool, the `boundedElastic` scheduler thread pool, and OS file descriptors, causing legitimate subscribers to receive `RESOURCE_EXHAUSTED` errors.

### Finding Description

**Code path:**

`PollingTopicListener.listen()` (lines 34–49) unconditionally creates a new `PollingContext` and a new Reactor polling chain for every call:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java:34-48
public Flux<TopicMessage> listen(TopicMessageFilter filter) {
    PollingContext context = new PollingContext(filter);
    Duration interval = listenerProperties.getInterval();
    return Flux.defer(() -> poll(context))
            .delaySubscription(interval, scheduler)
            .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)  // repeats forever
                    .withFixedDelay(interval)
                    .withScheduler(scheduler))
            ...
}
```

Each subscription schedules a DB poll every 500 ms (default `interval`) on `Schedulers.boundedElastic()` and holds an open gRPC stream (file descriptor). There is no check against any global subscription counter before creating the chain.

**`subscriberCount` is metrics-only, never enforced:**

`TopicMessageServiceImpl` tracks `subscriberCount` (line 48) and increments/decrements it (lines 89–90), but this value is only registered as a Micrometer `Gauge` (lines 52–55). It is never read back to gate or reject new subscriptions. No `maxSubscribers` field exists in `ListenerProperties` or `GrpcProperties`.

**Per-connection limit is trivially bypassed:**

`GrpcConfiguration` (line 33) sets `maxConcurrentCallsPerConnection = 5` (default). This is a Netty-level per-TCP-connection limit. An attacker opens `N` TCP connections and gets `5 × N` concurrent streams — there is no global cap anywhere in the stack.

### Impact Explanation

Each active `PollingTopicListener` subscription:
- Fires a `topicMessageRepository.findByFilter()` DB query every 500 ms
- Holds a task slot on `Schedulers.boundedElastic()`
- Holds an open gRPC HTTP/2 stream (OS file descriptor)

With enough connections, the attacker exhausts the HikariCP database connection pool (default `maxConnections` is finite), the bounded-elastic thread pool queue, and OS file descriptors. Legitimate subscribers then receive gRPC `RESOURCE_EXHAUSTED` or connection-refused errors. The attack is sustained as long as the attacker keeps connections open, with no automatic eviction of idle/abusive subscribers.

### Likelihood Explanation

No authentication is required to call `subscribeTopic`. Any network-reachable client can open TCP connections to port 5600 and issue `subscribeTopic` RPCs. The attacker needs only a standard gRPC client (e.g., `grpcurl`) and the ability to open many TCP connections — trivially achievable from a single machine or a small botnet. The attack is repeatable and persistent.

### Recommendation

1. **Add a global concurrent subscription limit** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable `maxSubscribers` property and return `Status.RESOURCE_EXHAUSTED` if exceeded.
2. **Add a per-IP or per-client subscription limit** at the gRPC interceptor layer to prevent a single source from consuming all slots.
3. **Add `maxActiveSubscriptions` to `ListenerProperties`** (mirroring the pattern already designed for the GraphQL `ContractLogListener`) and enforce it in `listen()` or at the service layer.
4. Consider adding a connection-level rate limit or requiring authentication/API keys for long-lived streaming subscriptions.

### Proof of Concept

```bash
# Open 200 TCP connections, each with 5 concurrent subscribeTopic streams = 1000 active subscriptions
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Legitimate subscriber now receives RESOURCE_EXHAUSTED or hangs indefinitely
grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: ERROR: Code: ResourceExhausted / connection refused / DB pool timeout
```

**Preconditions:** Network access to port 5600; no authentication required.
**Trigger:** Open `ceil(DB_pool_size / 5) * 5` or more concurrent subscriptions across multiple connections.
**Result:** DB connection pool exhausted; new legitimate `subscribeTopic` calls fail with resource errors.