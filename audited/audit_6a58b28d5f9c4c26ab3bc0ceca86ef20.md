### Title
Unbounded Concurrent Subscriber Polling Exhausts Database Connection Pool via Unlimited gRPC Topic Subscriptions

### Summary
When `PollingTopicListener` is active (listener type `POLL`), any unauthenticated client can open an unlimited number of gRPC `subscribeTopic` connections with `limit=0`. Each subscription triggers an indefinite polling loop that issues a database query every 500 ms. Because no subscriber count cap or per-client rate limit exists, a sufficient number of concurrent connections saturates the JPA connection pool, starving legitimate reads and writes — including fee-schedule topic message delivery.

### Finding Description

**Entry point — no authentication:**
`ConsensusController.toFilter()` maps the proto `limit` field directly to `TopicMessageFilter.limit` with no credential check. [1](#0-0) 

**`hasLimit()` returns false for `limit=0`:** [2](#0-1) 

**`incomingMessages()` propagates `limit=0` to the listener:** [3](#0-2) 

**`poll()` takes the `Integer.MAX_VALUE` branch, capped to `maxPageSize` (default 5000):** [4](#0-3) 

**The polling loop repeats `Long.MAX_VALUE` times with no termination condition for unlimited subscriptions:** [5](#0-4) 

**Each poll calls `getResultList()` — a synchronous, blocking JPA call that holds a DB connection for its full duration:** [6](#0-5) 

**`maxConcurrentCallsPerConnection=5` limits concurrency per TCP connection but does not cap total connections or total subscribers:** [7](#0-6) 

**No subscriber count enforcement exists** — `subscriberCount` is a metric gauge only: [8](#0-7) 

### Impact Explanation
With N concurrent unlimited subscribers, the server issues `N × 2` DB queries per second (at the 500 ms default interval), each fetching up to 5,000 rows. Once the JPA connection pool is exhausted, all subsequent DB operations — including the importer writing new topic messages and other subscribers reading them — queue or fail. This directly disrupts delivery of any topic messages, including those carrying fee-schedule updates, for the duration of the attack.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is unauthenticated and publicly documented. The exploit requires only a standard gRPC client (e.g., `grpcurl`) and the ability to open many TCP connections — no special privileges, tokens, or knowledge of internal state. The attack is trivially repeatable and scriptable. The only deployment-level precondition is that `hiero.mirror.grpc.listener.type` is set to `POLL`; operators who choose this mode for its simplicity are fully exposed. [9](#0-8) 

### Recommendation
1. **Enforce a global subscriber cap**: Reject new subscriptions in `TopicMessageServiceImpl.subscribeTopic()` when `subscriberCount` exceeds a configurable threshold.
2. **Add per-IP / per-connection rate limiting** at the gRPC interceptor layer (analogous to the `ThrottleConfiguration` used in the web3 module). [10](#0-9) 
3. **Introduce a minimum polling interval back-off** when a poll returns zero results, reducing DB pressure from idle unlimited subscriptions.
4. **Cap `RepeatSpec.times()`** to a finite value for unlimited subscriptions, or require an `endTime` when `limit=0`.

### Proof of Concept
```bash
# Open 200 concurrent unlimited subscriptions to any topic (e.g., fee-schedule topic 0.0.111)
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 111}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Each connection now polls the DB every 500 ms fetching up to 5000 rows.
# Monitor DB connection pool saturation:
# SELECT count(*) FROM pg_stat_activity WHERE datname = 'mirror_node';
# Once pool is exhausted, legitimate topic message reads return errors or time out.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-120)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-61)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-61)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
    }
```

**File:** docs/configuration.md (L423-423)
```markdown
| `hiero.mirror.grpc.listener.type`                          | REDIS            | The type of listener to use for incoming messages. Accepts either POLL, REDIS or SHARED_POLL              |
```

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
