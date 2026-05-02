### Title
Shared `applicationTaskExecutor` Exhaustion via Unbounded Connection Flooding on `subscribeTopic`

### Summary
`grpcServerConfigurer()` assigns a single shared `applicationTaskExecutor` to the entire gRPC server with no per-service thread isolation. Because there is no server-side connection count limit configured, an unprivileged attacker can open an arbitrary number of connections and saturate the shared executor with indefinite `subscribeTopic` streaming calls, starving all other gRPC services (`NetworkService`, etc.) that compete for the same thread pool.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java` lines 28–35, `grpcServerConfigurer()` configures the Netty server with one executor for all services and one per-connection concurrency cap:

```java
serverBuilder.executor(applicationTaskExecutor);                                    // line 32 – single shared pool
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // line 33 – per-conn cap only
```

`NettyProperties` defaults `maxConcurrentCallsPerConnection` to `5` (line 14 of `NettyProperties.java`). No `maxConnections`, `maxConnectionAge`, or per-IP rate limit is set anywhere in the server builder.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` bounds total executor load. It does not — it only limits concurrency *per connection*. With N connections the attacker can submit N × 5 concurrent RPCs to the same executor.

**Exploit flow:**

1. Attacker opens N TCP connections to port 5600 (no server-side connection limit).
2. On each connection, attacker issues 5 concurrent `ConsensusService/subscribeTopic` calls with `limit=0` and no `consensusEndTime` — creating indefinite server-streaming subscriptions (proto definition: `rpc subscribeTopic (ConsensusTopicQuery) returns (stream ConsensusTopicResponse)`).
3. Each active subscription continuously dispatches message-delivery tasks to `applicationTaskExecutor` as new topic messages arrive (see `TopicMessageServiceImpl.subscribeTopic`, lines 59–91, which merges historical + live reactive streams that emit on every new message).
4. `applicationTaskExecutor` (Spring Boot default: 8 core threads, unbounded queue) becomes saturated with dispatch tasks from the attacker's subscriptions.
5. Legitimate `NetworkService/getNodes` or `NetworkService/getFeeEstimate` calls, which share the same executor, queue behind the flood and experience severe latency or timeout.

**Why existing checks fail:**

`maxConcurrentCallsPerConnection = 5` is a per-connection guard, not a global one. With N connections the total active calls are N × 5, unbounded by any server-side control. There is no connection-count limit, no per-IP throttle, and no per-service executor partition in the configuration.

### Impact Explanation

All gRPC services hosted in the same process share the single `applicationTaskExecutor`. Saturating it with `subscribeTopic` flood traffic causes `NetworkService` calls (address book queries, fee estimates) to queue indefinitely, effectively making them unavailable to legitimate clients. The impact is a full gRPC-layer denial-of-service for all services other than the one the attacker is already consuming. No authentication or special privilege is required.

### Likelihood Explanation

The attack requires only a gRPC client library and network access to port 5600, both freely available. The `subscribeTopic` endpoint is publicly documented and reachable without credentials. The attacker needs to sustain N open connections with 5 streams each; even a single commodity machine can hold thousands of HTTP/2 connections. The attack is repeatable and persistent as long as the connections remain open.

### Recommendation

1. **Add a server-side connection limit** in `grpcServerConfigurer()`:
   ```java
   serverBuilder.maxConnectionAge(duration, TimeUnit.SECONDS);
   serverBuilder.maxConnectionIdle(duration, TimeUnit.SECONDS);
   ```
2. **Introduce per-service executor isolation**: create a dedicated `ThreadPoolTaskExecutor` for `ConsensusService` streaming calls and a separate one for `NetworkService`, injecting them via separate `ServerBuilderCustomizer` beans or a gRPC interceptor that re-dispatches to a service-specific pool.
3. **Add a global concurrent-calls cap** via `serverBuilder.maxConcurrentCallsPerConnection` combined with a total connection limit, or use an ingress-layer rate limiter (e.g., Envoy, Traefik middleware) to cap connections per source IP.
4. **Bound the `applicationTaskExecutor` queue** (`spring.task.execution.pool.queue-capacity`) so that overload is surfaced as `RESOURCE_EXHAUSTED` gRPC errors rather than silent queuing.

### Proof of Concept

```bash
# Install grpcurl: https://github.com/fullstorydev/grpcurl
# Open 200 connections × 5 indefinite subscribeTopic streams each (1000 total)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# In a separate terminal, observe NetworkService latency degrading:
time grpcurl -plaintext \
  -d '{"file_id": {"fileNum": 102}, "limit": 10}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.NetworkService/getNodes
# Expected: response time grows proportionally with number of attacker streams
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L47-49)
```text
service ConsensusService {
    rpc subscribeTopic (ConsensusTopicQuery) returns (stream ConsensusTopicResponse);
}
```
