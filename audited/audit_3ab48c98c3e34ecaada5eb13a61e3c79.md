### Title
Unbounded gRPC Subscriptions Exhaust Global `boundedElastic` Scheduler Thread Pool via `PollingTopicListener` (DoS)

### Summary
`PollingTopicListener.listen()` assigns `Schedulers.boundedElastic()` — the **global** Reactor singleton scheduler shared across the entire JVM — to schedule per-subscription polling loops. Each active subscription executes a blocking JDBC query (`topicMessageRepository.findByFilter`) on a thread from this shared pool every 500 ms. Because there is no limit on the total number of concurrent gRPC subscriptions (only a per-connection cap of 5), an unauthenticated attacker can open arbitrarily many connections and saturate the global bounded-elastic thread pool, starving every other reactive pipeline in the application.

### Finding Description

**Exact code path:**

`PollingTopicListener.java` line 31 — the field initializer calls the static factory `Schedulers.boundedElastic()`, which returns the **global** Reactor `BoundedElasticScheduler` singleton (not a fresh instance):

```java
private final Scheduler scheduler = Schedulers.boundedElastic();  // line 31 — global singleton
```

`listen()` (lines 34–49) wires this scheduler into two operators for every new subscription:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)          // line 39
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .withFixedDelay(interval)
                .withScheduler(scheduler))               // line 43
```

When `RepeatSpec.withFixedDelay().withScheduler()` fires after each interval, it re-subscribes the upstream `Flux.defer(() -> poll(context))` **on a thread borrowed from the bounded-elastic pool**. `poll()` (lines 51–62) then executes:

```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));  // line 61
```

`findByFilter` is a synchronous Spring Data JPA / JDBC call that returns a `Stream<TopicMessage>`. The borrowed thread is **blocked** for the entire duration of the database query before it is returned to the pool.

**Why existing checks are insufficient:**

`GrpcConfiguration.java` line 33 applies only a per-connection cap:

```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // default 5
```

There is no limit on the **number of connections**, no per-IP rate limit, and no authentication on the `subscribeTopic` gRPC endpoint. An attacker opens `C` connections × 5 calls each = `5C` simultaneous polling subscriptions. The global `boundedElastic` scheduler defaults to `10 × CPU_count` threads (e.g., 40 on a 4-core host). Once `5C` exceeds that ceiling, tasks queue; once the queue (100 000 entries) fills, new tasks are rejected with `RejectedExecutionException`, crashing reactive pipelines application-wide.

The same global scheduler is consumed by `SharedTopicListener.listen()` (`.publishOn(Schedulers.boundedElastic(), ...)`) and `PollingTopicMessageRetriever` (also `Schedulers.boundedElastic()`), so starvation is not isolated to the polling path.

### Impact Explanation

- **Availability (High):** All reactive pipelines sharing `Schedulers.boundedElastic()` — including the shared-poll listener and the historical-message retriever — stall or crash. Legitimate subscribers receive no messages.
- **Database amplification:** Each of the `5C` subscriptions issues a full-table-range query every 500 ms (up to `maxPageSize = 5000` rows). With `C = 20` connections the server issues 200 DB queries/second, exhausting the connection pool and degrading the database for all services.
- **Scope:** Affects the entire gRPC module when `listenerType = POLL` is configured.

### Likelihood Explanation

- **No authentication required** on the `subscribeTopic` endpoint (confirmed: no auth interceptor in `GrpcConfiguration`, no credential check in `ConsensusController.subscribeTopic()`).
- **Trivially scriptable:** `grpcurl` or any gRPC client can open hundreds of connections in a loop.
- **POLL mode is not the default** (`REDIS` is), which reduces the exposed population to deployments that explicitly set `hiero.mirror.grpc.listener.type=POLL`. However, such deployments are fully exposed with zero preconditions.
- **Repeatability:** The attack is stateless and can be re-launched immediately after mitigation attempts that do not add connection-level limits.

### Recommendation

1. **Isolate the scheduler:** Replace `Schedulers.boundedElastic()` with a dedicated, bounded scheduler so exhaustion cannot propagate to other pipelines:
   ```java
   private final Scheduler scheduler = Schedulers.newBoundedElastic(
       Math.max(4, Runtime.getRuntime().availableProcessors()),
       100,          // max queued tasks per thread
       "poll-listener",
       60,
       true);
   ```
2. **Limit total concurrent subscriptions:** Add a server-wide semaphore or a Netty `maxConnectionAge` / `maxConnections` setting in `GrpcConfiguration` to cap the total number of live streaming calls.
3. **Move blocking DB work off the scheduler:** Use `.subscribeOn(scheduler)` only for the blocking `poll()` call and release the thread immediately after the stream is materialised (e.g., collect to a list before returning from `poll()`).
4. **Add per-IP connection rate limiting** at the load-balancer or via a gRPC server interceptor.

### Proof of Concept

```bash
# Open 20 connections × 5 subscriptions = 100 concurrent polling loops
for i in $(seq 1 20); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}}' \
      <host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
```

**Expected result:** Within seconds, the `boundedElastic` thread pool is saturated. Legitimate subscribers stop receiving messages; application logs show `RejectedExecutionException` or extreme scheduling latency; database connection pool exhaustion errors appear for all services sharing the same DB.