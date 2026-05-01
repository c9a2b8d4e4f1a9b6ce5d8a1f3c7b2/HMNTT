### Title
Unbounded gRPC `subscribeTopic` Connections Enable DB Pool Exhaustion DoS

### Summary
The gRPC `subscribeTopic` endpoint enforces only a per-TCP-connection stream limit (`maxConcurrentCallsPerConnection = 5`) but imposes no limit on the number of TCP connections from a single IP. An unauthenticated attacker can open an arbitrary number of TCP connections, each carrying 5 concurrent `subscribeTopic` streams, causing each stream to hold a database connection from the finite pool. Once the pool is exhausted, all DB-dependent operations — including the importer and legitimate subscribers — fail, resulting in a full service outage.

### Finding Description

**Per-connection limit only — no per-IP or global cap:**

`GrpcConfiguration.java` applies `maxConcurrentCallsPerConnection` from `NettyProperties`: [1](#0-0) [2](#0-1) 

Default is 5 streams per connection. There is no `maxConnections`, no per-IP limit, and no global subscriber cap enforced anywhere in the gRPC stack.

**`subscriberCount` is a metric, not a gate:**

`TopicMessageServiceImpl` tracks subscribers only as a Micrometer gauge — it never rejects new subscriptions based on count: [3](#0-2) [4](#0-3) 

**Each subscription holds a DB connection:**

`PollingTopicMessageRetriever.retrieve()` creates a polling loop that repeatedly calls `topicMessageRepository.findByFilter()`, holding a connection from the pool for the duration of each poll cycle: [5](#0-4) [6](#0-5) 

The `safetyCheck` flux in `TopicMessageServiceImpl` also schedules additional DB queries on `Schedulers.boundedElastic()` per subscriber: [7](#0-6) 

**No rate limiting exists for the gRPC module:**

The `ThrottleConfiguration` and bucket4j rate limiting exist only in the `web3` module, not in `grpc`: [8](#0-7) 

**Exploit flow:**
1. Attacker opens `N` TCP connections to port 5600 (no authentication required, no IP-level connection cap).
2. On each connection, attacker opens 5 concurrent `subscribeTopic` streams with `startTime=0` and no `endTime`/`limit` (infinite subscription).
3. Each stream triggers `TopicMessageServiceImpl.subscribeTopic()` → `PollingTopicMessageRetriever.retrieve(filter, true)` with `numRepeats = Long.MAX_VALUE` and `pollingFrequency = 2s`.
4. With `N * 5` concurrent polling subscriptions, the HikariCP connection pool (finite, shared with the importer) is saturated.
5. New DB queries from the importer, legitimate subscribers, and the `topicExists` check all block or time out.

### Impact Explanation
Once the DB connection pool is exhausted, the mirror node cannot ingest new transactions (importer stalls), cannot serve any gRPC or REST queries, and cannot confirm new transactions to the network. This matches the stated critical severity: total network-facing service shutdown. The attack is self-sustaining — the attacker only needs to keep TCP connections open, which is trivially cheap.

### Likelihood Explanation
No credentials, API keys, or special network access are required. Any host with TCP reachability to port 5600 can execute this. A single commodity machine can open tens of thousands of TCP connections. The `maxConcurrentCallsPerConnection = 5` default provides no meaningful protection because it only limits streams per connection, not connections per source. The attack is fully repeatable and requires no exploit sophistication.

### Recommendation
1. **Add a global subscriber cap** — enforce a hard limit in `TopicMessageServiceImpl.subscribeTopic()` using the existing `subscriberCount` atomic, rejecting new subscriptions with `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Add a per-IP connection limit** — configure `NettyServerBuilder.maxConnectionsPerIp()` (available in grpc-netty) or add an interceptor that tracks and rejects connections beyond a threshold per remote address.
3. **Separate DB connection pools** — use a dedicated, size-limited pool for gRPC subscriber polling, isolated from the importer pool, so pool exhaustion in one does not cascade to the other.
4. **Add a gRPC-level rate limiter** — apply a bucket4j or similar interceptor (analogous to `ThrottleConfiguration` in `web3`) to the gRPC server to cap new subscription attempts per IP per second.

### Proof of Concept
```bash
# Open 200 TCP connections, each with 5 concurrent infinite subscribeTopic streams
# (1000 total concurrent polling sessions)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
# Result: DB connection pool exhausted; importer and all legitimate queries
# begin timing out with connection acquisition timeout errors.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L76-79)
```java

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-20)
```java
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
```
