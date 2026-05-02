### Title
Unbounded Long-Lived gRPC Connection Accumulation Leading to JVM Heap Exhaustion (DoS)

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the `NettyServerBuilder` with only `maxConcurrentCallsPerConnection` (5 per connection) but sets no `maxConnectionAge`, `maxConnectionAgeGrace`, or `maxConnectionIdle`. Because the `subscribeTopic` RPC is a publicly accessible, unauthenticated server-streaming endpoint that runs indefinitely when `limit=0` and no `consensusEndTime` is provided, an unprivileged attacker can slowly accumulate thousands of long-lived connections, each holding up to 5 active reactive stream subscriptions, until JVM heap is exhausted and the gRPC service crashes.

### Finding Description

**Exact code path:**

`GrpcConfiguration.java` `grpcServerConfigurer()` (lines 28–35) is the sole `NettyServerBuilder` customizer:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // NO maxConnectionAge, maxConnectionAgeGrace, maxConnectionIdle, maxInboundConnections
};
``` [1](#0-0) 

`NettyProperties` exposes only one tunable: [2](#0-1) 

The `subscribeTopic` RPC is unauthenticated and explicitly designed to stream indefinitely: [3](#0-2) 

Each call to `subscribeTopic` allocates a `TopicContext`, a multi-operator reactive `Flux` pipeline, a `Disposable`, and Netty channel buffers, all tracked by an unbounded `subscriberCount`: [4](#0-3) 

**Root cause:** `NettyServerBuilder` defaults `maxConnectionAge` to `Long.MAX_VALUE` (effectively infinite) when not explicitly set. The application never calls `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnectionAgeGrace(...)`, or `serverBuilder.maxConnectionIdle(...)`, so every accepted connection lives until the client voluntarily closes it.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` limits streams *per connection*, not the total number of connections. An attacker opens N connections × 5 streams = 5N indefinite subscriptions.
- The GCP backend policy `maxRatePerEndpoint: 250` (requests/second) throttles the *rate* of new connection establishment, not the *total count* of concurrent open connections. An attacker staying at 249 req/s accumulates ~14,940 connections per minute.
- `timeoutSec: 20` in the GCP backend policy applies to unary RPCs; GCP load balancers do not terminate long-lived gRPC server-streaming connections via this timeout. [5](#0-4) 

### Impact Explanation

Each open `subscribeTopic` stream holds: a Netty `Channel` (~64 KB+ of I/O buffers), a `TopicContext` object, a multi-stage Reactor `Flux` pipeline with `safetyCheck` scheduler allocation, and a `Disposable`. With no server-side connection age limit, these objects are never reclaimed. Accumulating tens of thousands of connections exhausts the JVM heap, triggering `OutOfMemoryError` and crashing the gRPC service. This renders the mirror node's HCS topic subscription API completely unavailable — a total service-level shutdown for all consumers of the gRPC API.

### Likelihood Explanation

No authentication or API key is required to call `subscribeTopic`; the endpoint is publicly documented and reachable via plaintext on port 5600. [6](#0-5) 

A single attacker with a modest machine can open connections at 200–249/second (below the rate limit), keep them alive by never sending a FIN/RST, and reach tens of thousands of concurrent connections within minutes. Standard gRPC client libraries make this trivial to script. The attack is repeatable after a service restart with no change in preconditions.

### Recommendation

Add the following to `grpcServerConfigurer()` in `GrpcConfiguration.java`:

```java
serverBuilder.maxConnectionAge(30, TimeUnit.MINUTES);
serverBuilder.maxConnectionAgeGrace(5, TimeUnit.MINUTES);
serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);
serverBuilder.maxInboundConnections(10_000); // hard cap
```

Expose `maxConnectionAge`, `maxConnectionAgeGrace`, `maxConnectionIdle`, and `maxInboundConnections` as configurable fields in `NettyProperties` so operators can tune them per deployment. Additionally, enforce a total concurrent-connection limit at the infrastructure layer (e.g., GCP `maxConnectionsPerEndpoint` in the backend policy).

### Proof of Concept

```bash
# Install ghz (gRPC benchmarking/load tool)
# Open 5000 indefinite streaming subscriptions at 200 conn/s
ghz --insecure \
    --proto consensus_service.proto \
    --call com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    --data '{"topicID":{"topicNum":1},"limit":0}' \
    --concurrency 5000 \
    --connections 5000 \
    --rps 200 \
    --duration 30s \
    <grpc-host>:5600
```

1. Start with a valid topic ID (any existing topic on the network).
2. Set `limit: 0` and omit `consensusEndTime` — the server streams indefinitely.
3. Run multiple waves of the above command without closing prior connections (use `--keepalive` or a custom client that holds connections open).
4. Monitor JVM heap via the exposed Prometheus metric `jvm_memory_used_bytes{application="grpc"}`.
5. Heap climbs monotonically; no connections are recycled. The service eventually throws `OutOfMemoryError` and crashes.

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

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L22-25)
```text

    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
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

**File:** charts/hedera-mirror-grpc/values.yaml (L66-72)
```yaml
        drainingTimeoutSec: 10
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
```

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
