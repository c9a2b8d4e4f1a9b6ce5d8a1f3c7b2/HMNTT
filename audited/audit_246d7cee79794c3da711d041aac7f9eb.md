### Title
Shared `Schedulers.boundedElastic()` Thread Pool Exhaustion via Unbounded Concurrent Subscriptions

### Summary
`PollingTopicMessageRetriever` allocates a single `Schedulers.boundedElastic()` instance at construction time, shared across every call to `retrieve()`. Because there is no global limit on concurrent gRPC subscriptions and each subscription's polling loop executes a synchronous (blocking) JDBC `Stream` query on a scheduler thread, an unprivileged attacker can open enough concurrent connections to saturate the bounded elastic thread pool, queuing or starving legitimate subscribers' poll tasks.

### Finding Description
**Exact location:** `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, line 41 (constructor), lines 51–59 (`retrieve()`), lines 65–79 (`poll()`).

**Root cause:**

```java
// line 41 – single shared pool for ALL subscriptions
scheduler = Schedulers.boundedElastic();
```

`Schedulers.boundedElastic()` defaults to `10 × CPU_cores` threads (e.g. 40 on a 4-core host) with a 100 000-task queue. The scheduler is passed to two operators per subscription:

```java
.repeatWhen(RepeatSpec.create(...)
    .withFixedDelay(context.getFrequency())
    .withScheduler(scheduler))          // fires next poll on a scheduler thread
...
.timeout(retrieverProperties.getTimeout(), scheduler)
```

When `RepeatSpec` fires the fixed delay, it uses a scheduler thread to re-subscribe to `Flux.defer(() -> poll(context))`. `poll()` calls:

```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

`findByFilter` returns a synchronous JDBC `Stream`. Because no `subscribeOn` offloads this to a separate pool, the scheduler thread that fires the repeat delay is **blocked for the entire duration of the database query**. Each active subscription therefore holds a scheduler thread for every poll cycle.

**No global subscription cap exists.** `GrpcConfiguration` only sets `maxConcurrentCallsPerConnection = 5`; there is no limit on the number of connections, no per-IP rate limiting, and no authentication on `ConsensusController.subscribeTopic()`.

**Exploit flow:**

1. Attacker opens *C* TCP connections to port 5600 (no connection limit configured).
2. Each connection issues 5 concurrent `subscribeTopic` RPCs with a historical `consensusStartTime` (e.g. genesis), giving `5C` concurrent retriever instances.
3. Each retriever polls every 2 s (throttled path, `numRepeats = Long.MAX_VALUE`), blocking a scheduler thread for the DB query duration *d*.
4. Steady-state thread occupancy ≈ `5C × (d / 2s)`. With *d* = 400 ms and *C* = 40 connections: `200 × 0.2 = 40 threads` — pool fully saturated.
5. Legitimate subscribers' poll tasks queue behind attacker tasks; with enough load the 100 000-task queue fills and tasks are rejected with `RejectedExecutionException`, propagating as errors to legitimate subscribers.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` is per-connection only; attacker multiplies connections freely.
- `timeout = 60 s` is an *inter-emission* timeout, not a wall-clock session limit; attacker reconnects immediately on timeout.
- `isComplete()` for throttled subscriptions returns `true` only when the last page is smaller than `maxPageSize`; an attacker subscribing to a topic with a large historical backlog keeps the retriever alive for many minutes.
- `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` causes the retriever to restart indefinitely on errors, compounding thread pressure.

### Impact Explanation
Full saturation of the shared `boundedElastic` pool delays or drops poll tasks for all legitimate subscribers. When the 100 000-task queue overflows, `RejectedExecutionException` propagates through the reactive pipeline, terminating legitimate subscriptions with an error. This constitutes a complete non-network DoS of the historical-message retrieval path, affecting all topics served by the mirror node's gRPC API.

### Likelihood Explanation
No authentication, no connection limit, and no per-IP throttle are required. Any client with TCP access to port 5600 can execute this attack using a standard gRPC client (e.g. `grpcurl` in a loop). The attack is repeatable: after the 60 s timeout evicts attacker sessions, the attacker immediately reconnects. The resource cost to the attacker is negligible (idle streaming RPCs); the cost to the server is proportional to the number of concurrent DB queries.

### Recommendation
1. **Decouple blocking DB calls from the scheduler thread**: add `.subscribeOn(Schedulers.boundedElastic())` inside `poll()`, or wrap `findByFilter` in a non-blocking repository call, so the repeat-delay scheduler thread is not blocked.
2. **Enforce a global concurrent-subscription cap** in `TopicMessageServiceImpl` using the existing `subscriberCount` gauge — reject new subscriptions above a configurable threshold.
3. **Add per-IP or per-connection subscription rate limiting** via a gRPC `ServerInterceptor`.
4. **Use a dedicated, separately-sized scheduler** for the retriever (e.g. `Schedulers.newBoundedElastic(...)` with an explicit thread cap) so retriever exhaustion cannot affect other reactive pipelines sharing the JVM-wide default scheduler.
5. **Cap the `retryWhen` attempts** to a finite number to prevent indefinite reconnection amplifying thread pressure.

### Proof of Concept
```bash
# Open 50 connections × 5 concurrent RPCs = 250 concurrent historical retrievals
# Requires grpcurl and a topic with historical messages (e.g. topic 0.0.1)
for i in $(seq 1 50); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Legitimate subscriber — observe delayed or errored responses:
grpcurl -plaintext \
  -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: responses arrive with multi-second delays or RejectedExecutionException errors
# as the boundedElastic pool (default 10×CPU threads) is saturated by attacker sessions.
```