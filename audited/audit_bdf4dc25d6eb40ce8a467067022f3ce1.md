### Title
Unauthenticated Unbounded Historical Subscription Causes Indefinite DB Polling DoS via `subscribeTopic()`

### Summary
Any unauthenticated external caller can open a `subscribeTopic` gRPC stream with `startTime=0` and no limit against a topic containing millions of historical messages. The `PollingTopicMessageRetriever` enters throttled mode with `numRepeats=Long.MAX_VALUE` and its `isComplete()` check never returns `true` because each page fills to `maxPageSize`, causing it to issue a `findByFilter()` DB query every 2 seconds indefinitely. Since there is no global subscription cap and `maxConcurrentCallsPerConnection` is per-connection only, an attacker can multiply this load across many connections, holding the database under continuous read pressure until each subscription is manually cancelled.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` (line 43) accepts any `ConsensusTopicQuery` with no authentication check. It calls `toFilter()` (line 55), which sets `startTime=0` when the client sends `consensusStartTime` with seconds=0. `TopicMessageFilter` validates this with `@Min(0)` and `isValidStartTime()` (`startTime <= DomainUtils.now()`), both of which pass for 0. [1](#0-0) [2](#0-1) 

`TopicMessageServiceImpl.subscribeTopic()` (line 63) calls `topicMessageRetriever.retrieve(filter, true)` — throttled=`true`. [3](#0-2) 

In `PollingTopicMessageRetriever`, throttled mode sets `numRepeats = Long.MAX_VALUE` and `maxPageSize = 1000` (default). The `isComplete()` check is:

```java
return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
```

With millions of messages and `limit=0` (no limit), every poll returns exactly 1000 rows (full page), so `pageSize.get() < 1000` is `false`, and `limitHit` is `false`. `isComplete()` never returns `true`. [4](#0-3) 

The `poll()` method constructs a new filter with `limit=pageSize` (1000) and issues `findByFilter()` every `pollingFrequency` (2 seconds default): [5](#0-4) 

`findByFilter()` executes a full JPA query with `setMaxResults(1000)` against the `topic_message` table: [6](#0-5) 

**Why the timeout does not protect:** `.timeout(retrieverProperties.getTimeout(), scheduler)` (60s default) is a reactive idle timeout — it fires only if no item is emitted within 60 seconds. Since 1000 messages are emitted every 2 seconds, the timer resets continuously and never fires. [7](#0-6) 

**Why `maxConcurrentCallsPerConnection` does not protect:** It is set to 5 per connection with no cap on the number of connections and no global subscription limit. [8](#0-7) [9](#0-8) 

### Impact Explanation
Each open subscription with this pattern issues one DB query per 2 seconds, each reading 1000 rows from `topic_message`. With N connections × 5 calls each, the attacker drives N×5 concurrent polling loops. The database connection pool is exhausted, query latency rises for all users, and legitimate subscribers are starved. Because the gRPC port (5600) is publicly exposed and requires no credentials, this is a direct, unauthenticated path to database-level denial of service. The impact is classified as non-network DoS against a critical infrastructure component.

### Likelihood Explanation
The attack requires only a gRPC client (e.g., `grpcurl` or the Hedera SDK), knowledge of any topic ID with historical messages (all public on mainnet/testnet), and the ability to open TCP connections to port 5600. No credentials, tokens, or privileged access are needed. The attack is trivially repeatable and scriptable. A single attacker with modest bandwidth can open hundreds of subscriptions.

### Recommendation
1. **Enforce a maximum subscription duration**: Add a hard wall-clock timeout on the entire retrieval flux (not just idle timeout), e.g., `take(Duration.ofMinutes(10))`.
2. **Require a non-zero `limit` or cap it server-side**: Reject or cap subscriptions with no limit when `startTime` is far in the past.
3. **Global concurrent subscription cap**: Track active subscriptions via `subscriberCount` and reject new ones above a configurable threshold.
4. **Rate-limit new subscription establishment per source IP** at the ingress/proxy layer.
5. **Fix `isComplete()` for throttled mode**: When no limit is set and `startTime` is historical, transition to live-only mode after catching up rather than polling indefinitely.

### Proof of Concept

**Preconditions:** Topic `0.0.X` exists on the target with ≥ 1 million historical messages. gRPC port 5600 is reachable.

**Steps:**

```bash
# Install grpcurl; obtain topic_id with large history (e.g., 0.0.1234)
# Open 5 subscriptions per connection, repeat across many connections:

for i in $(seq 1 100); do
  grpcurl -plaintext \
    -d '{
      "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1234},
      "consensusStartTime": {"seconds": 0, "nanos": 0}
    }' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

**Result:** Each background process holds an open stream. `PollingTopicMessageRetriever` issues a `SELECT ... FROM topic_message WHERE topic_id=1234 AND consensus_timestamp >= <cursor> ORDER BY consensus_timestamp LIMIT 1000` query every 2 seconds per subscription. With 100 concurrent subscriptions, 50 queries/second hit the DB continuously. DB CPU and connection pool utilization spike; legitimate queries time out.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-53)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-51)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L58-59)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-128)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
        }

        private @Nullable TopicMessage getLast() {
            return last.get();
        }

        /**
         * Checks if this publisher is complete by comparing if the number of results in the last page was less than the
         * page size or if the limit has reached if it's set. This avoids the extra query if we were to just check if
         * last page was empty.
         *
         * @return whether all historic messages have been returned
         */
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L33-61)
```java
    public Stream<TopicMessage> findByFilter(TopicMessageFilter filter) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<TopicMessage> query = cb.createQuery(TopicMessage.class);
        Root<TopicMessage> root = query.from(TopicMessage.class);

        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```
