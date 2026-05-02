### Title
Unbounded Concurrent Unthrottled DB Polling via Per-Subscription Safety-Check Gap Recovery

### Summary
Any unprivileged gRPC client can open an arbitrary number of concurrent `subscribeTopic` streams. Each stream unconditionally fires a safety-check after one second that invokes `missingMessages(topicContext, null)`, which calls `topicMessageRetriever.retrieve(gapFilter, false)` — the **unthrottled** path. Because there is no enforced subscriber limit, N concurrent subscriptions produce N simultaneous unthrottled `PollingContext` DB polling loops, each hammering the database at 20 ms intervals with 5 000-row pages for up to 12 polls, multiplying DB load linearly with N.

### Finding Description

**Entry point — no subscriber cap:**
`ConsensusController.subscribeTopic()` accepts every incoming gRPC stream without authentication or rate-limiting. [1](#0-0) 

`subscriberCount` in `TopicMessageServiceImpl` is a Micrometer gauge only — it is never checked against a maximum. [2](#0-1) 

**Safety-check always fires for open-ended subscriptions:**
Every call to `subscribeTopic()` schedules a one-second delayed safety-check conditioned on `!topicContext.isComplete()`. [3](#0-2) 

`TopicContext.isComplete()` returns `false` whenever `filter.getEndTime() == null`, which is the default for any open-ended subscription. [4](#0-3) 

**Safety-check calls the unthrottled retriever:**
When `current == null` (safety-check path), `missingMessages()` calls `topicMessageRetriever.retrieve(gapFilter, false)` — `throttled=false`. [5](#0-4) 

**Unthrottled `PollingContext` is maximally aggressive:**
`PollingContext(filter, false)` selects `maxPageSize=5000`, `maxPolls=12`, `pollingFrequency=20ms` — 12 polls × 5 000 rows at 20 ms intervals per retrieval instance. [6](#0-5) 

**Gap-recovery path also unthrottled:**
The live-stream gap-recovery path in `incomingMessages()` also calls `retrieve(newFilter, false)` for every detected sequence-number gap, compounding the issue when gaps exist. [7](#0-6) 

**Root cause:** The design assumes a small, bounded number of concurrent subscribers. There is no enforcement of that assumption at any layer in the gRPC path.

### Impact Explanation
Each unthrottled `PollingContext` issues up to 12 × 5 000 = 60 000 DB row fetches in ~240 ms. With N concurrent subscriptions the DB receives N × 60 000 rows of reads in the same window. At modest N (e.g., 100 connections from a single client), this is 6 000 000 rows read in under 250 ms, sufficient to saturate a typical PostgreSQL instance and cause latency spikes or outright unavailability for all mirror-node consumers, including fee-schedule readers. Because the safety-check re-arms on every new subscription and open-ended subscriptions never complete, the attacker can sustain the load indefinitely by keeping connections open or reconnecting.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly exposed and requires no credentials. Opening hundreds of TCP/HTTP-2 streams is trivial from a single host using any gRPC client library. The 1-second delay before the safety-check fires is not a meaningful barrier. The attack is fully repeatable and requires no knowledge of internal state beyond a valid topic ID (which is public on-chain data).

### Recommendation
1. **Enforce a global and per-IP subscriber limit** in `TopicMessageServiceImpl.subscribeTopic()` by checking `subscriberCount` (or a per-IP counter) against a configurable maximum and returning `RESOURCE_EXHAUSTED` if exceeded.
2. **Gate the safety-check on a per-topic or global unthrottled-retrieval semaphore** so that at most K unthrottled `PollingContext` instances are active simultaneously across all subscriptions.
3. **Add gRPC-layer rate limiting** (e.g., via a `ServerInterceptor`) to cap new stream creation per source IP per second.
4. **Reduce unthrottled defaults** (`maxPolls`, `maxPageSize`, `pollingFrequency`) or require operator opt-in for the unthrottled path.

### Proof of Concept
```
# Prerequisites: grpcurl or any gRPC client; a known topic ID (e.g., fee-schedule topic 0.0.101)

for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID":{"topicNum":101},"consensusStartTime":{"seconds":0}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

1. All 200 streams connect successfully (no auth, no subscriber cap).
2. After ~1 second each stream's safety-check fires, calling `missingMessages(topicContext, null)`.
3. Each call creates a `PollingContext(filter, false)` and begins polling at 20 ms / 5 000 rows.
4. 200 concurrent unthrottled polling loops hit the DB simultaneously; observe DB CPU/IO spike and query latency increase proportionally.
5. Keeping connections open sustains the load; reconnecting after `timeout` (60 s default) restarts the cycle.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-150)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L164-177)
```java
        TopicMessageFilter newFilter = topicContext.getFilter().toBuilder()
                .endTime(current.getConsensusTimestamp())
                .limit(numMissingMessages)
                .startTime(last.getConsensusTimestamp() + 1)
                .build();

        log.info(
                "[{}] Querying topic {} for missing messages between sequence {} and {}",
                newFilter.getSubscriberId(),
                topicContext.getTopicId(),
                last.getSequenceNumber(),
                current.getSequenceNumber());

        return topicMessageRetriever.retrieve(newFilter, false).concatWithValues(current);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L102-107)
```java
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```
