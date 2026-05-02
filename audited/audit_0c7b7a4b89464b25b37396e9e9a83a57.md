### Title
Unbounded gRPC Connection Fan-Out Enables Unauthenticated Subscription Flood Exhausting Database Resources

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures `NettyServerBuilder` with only a per-connection concurrent-call cap (`maxConcurrentCallsPerConnection = 5`) but imposes no limit on the total number of inbound connections or connections per source IP. An unauthenticated attacker can open an arbitrary number of TCP connections, each carrying up to 5 concurrent long-lived `subscribeTopic` streams, multiplying the effective subscription count without bound and exhausting the database connection pool shared by the transaction read path.

### Finding Description

**Exact code path:**

`GrpcConfiguration.java` `grpcServerConfigurer()` (lines 28–35) configures the Netty server with exactly two settings:

```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
``` [1](#0-0) 

`NettyProperties.java` sets the default to 5: [2](#0-1) 

The following are **not configured** on the `NettyServerBuilder`:
- `maxInboundConnections(...)` — no cap on total simultaneous TCP connections
- Any per-IP connection limit
- Any new-connection rate limit

**Root cause:** `maxConcurrentCallsPerConnection` is a per-connection ceiling, not a global or per-source ceiling. An attacker opening *N* connections bypasses it entirely, achieving *N × 5* concurrent active subscriptions.

**Each `subscribeTopic` call triggers:**

1. A synchronous DB lookup (`entityRepository.findById`) to verify topic existence.
2. A historical message retrieval loop (`topicMessageRetriever.retrieve`) that polls the DB repeatedly.
3. A live listener subscription (`topicListener.listen`) that holds a reactive pipeline open indefinitely.
4. A 1-second safety-check poll (`missingMessages`) on a `boundedElastic` scheduler thread. [3](#0-2) 

The `subscriberCount` gauge is purely observational — it has no enforcement cap. [4](#0-3) 

**No authentication or rate-limiting interceptor exists** in the production gRPC path. The only registered `ServerInterceptor` is a test-only `GrpcInterceptor` that merely sets an endpoint-context label: [5](#0-4) 

The web3 module has a `ThrottleConfiguration` with `Bucket4j` rate limiting, but **no equivalent exists for the gRPC module**: [6](#0-5) 

### Impact Explanation

Each active subscription holds at least one DB connection slot open (historical polling) and one reactive thread. With a shared DB connection pool, flooding with *N × 5* subscriptions (e.g., 2000 connections × 5 = 10,000 subscriptions) exhausts the pool. Legitimate `subscribeTopic` calls and the importer's transaction-write path both compete for the same pool. The result is:

- Legitimate subscribers receive no messages or timeout errors.
- Transaction data ingestion is delayed because the importer's DB writes queue behind exhausted connections.
- The service does not crash but degrades to a state where real-time topic data is unavailable to all users.

Severity: **High** — directly causes service unavailability for the primary read path with no authentication barrier.

### Likelihood Explanation

Preconditions: none. The gRPC port (default 5600) is publicly exposed. No credentials, tokens, or privileged network position are required. A single attacker machine with standard tooling (e.g., `ghz`, a custom gRPC client loop, or even multiple `grpcurl` processes) can open thousands of TCP connections. The attack is repeatable and sustainable indefinitely because long-lived streaming connections keep subscriptions alive without re-dialing. The optional GCP gateway `maxRatePerEndpoint: 250` is infrastructure-level, not universally deployed, and limits request rate per backend endpoint — not per-source connection count. [7](#0-6) 

### Recommendation

Apply the following mitigations directly in `grpcServerConfigurer()`:

1. **Add `maxInboundConnections`** to cap total simultaneous TCP connections server-wide.
2. **Add `maxConnectionsPerIp`** (available in Netty's `io.grpc.netty.NettyServerBuilder` via channel options or a custom `ChannelHandler`) to limit connections per source IP.
3. **Add a gRPC `ServerInterceptor`** (registered as a `@GlobalServerInterceptor`) that enforces per-IP call rate limiting using a token-bucket (e.g., Bucket4j, Guava `RateLimiter`) keyed on the remote address from `ServerCall.getAttributes()`.
4. **Cap total active subscriptions** by checking `subscriberCount` against a configurable maximum at the start of `subscribeTopic()` and returning `RESOURCE_EXHAUSTED` when exceeded.

### Proof of Concept

```bash
# Install ghz: https://ghz.sh
# Open 500 connections, each sending 5 concurrent subscribeTopic streams (2500 total)
ghz --insecure \
    --proto consensus_service.proto \
    --call com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    --data '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
    --connections 500 \
    --concurrency 2500 \
    --duration 60s \
    <grpc-host>:5600
```

Expected result within 60 seconds: DB connection pool exhausted, legitimate `subscribeTopic` calls from other clients return `UNAVAILABLE` or hang indefinitely, and the `hiero.mirror.grpc.subscribers` gauge shows thousands of active subscriptions with no enforcement ceiling.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-91)
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
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-32)
```java
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

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

**File:** charts/hedera-mirror-grpc/values.yaml (L69-72)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
```
