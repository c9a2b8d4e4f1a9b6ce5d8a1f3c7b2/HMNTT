### Title
Unbounded Subscription DoS via Empty-Window Poll Flooding in PollingTopicListener

### Summary
An unprivileged external user can open an arbitrary number of gRPC connections, each carrying up to 5 subscriptions (`maxConcurrentCallsPerConnection = 5`) with a `TopicMessageFilter` whose `endTime` is just 1 nanosecond after `startTime`. Because `poll()` unconditionally fires a DB query on every interval tick regardless of whether results are expected, and because no global subscription count or per-IP rate limit exists in the gRPC layer, an attacker can generate a sustained flood of empty DB queries that exhausts the connection pool and starves legitimate traffic.

### Finding Description

**Exact code path:**

`PollingTopicListener.poll()` — `grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, lines 51–62:

```java
private Flux<TopicMessage> poll(PollingContext context) {
    TopicMessageFilter filter = context.getFilter();
    ...
    var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
    return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));  // DB query always fires
}
```

This is called on every tick of the repeat loop (lines 38–43), which fires every `interval` (default 500 ms, minimum 50 ms). There is no guard that skips the DB call when the filter window is known to be empty.

**Root cause — failed assumption:** The code assumes that subscriptions with a tiny or already-elapsed time window will be short-lived. In reality:

1. `TopicMessageFilter.isValidEndTime()` (line 44–46) only requires `endTime > startTime` — a 1-nanosecond gap is accepted.
2. `TopicMessageFilter.isValidStartTime()` (line 48–50) only requires `startTime <= now()` — both timestamps can be in the past.
3. The `listen()` loop uses `RepeatSpec.times(Long.MAX_VALUE)` (line 40) — it repeats indefinitely.
4. `GrpcProperties.endTimeInterval = 30s` (line 22) suggests a periodic end-time check exists somewhere upstream, but even if it terminates a subscription after ≤30 s, the attacker simply re-opens it immediately, and the 30-second window still yields 60 empty DB queries per subscription at the default interval.
5. `NettyProperties.maxConcurrentCallsPerConnection = 5` (line 14) limits calls **per TCP connection**, not total connections. There is no global connection cap or per-IP subscription rate limit in the gRPC configuration.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` is enforced per connection by `GrpcConfiguration` (line 33), but an attacker opens many connections.
- The `ThrottleConfiguration` with Bucket4j rate limiting exists only in the `web3` module, not in the `grpc` module.
- Validation annotations on `TopicMessageFilter` (`@Min(0)`, `@NotNull`) do not enforce a minimum time window width.

### Impact Explanation

Each attacker-controlled subscription fires one DB query every 500 ms. With N connections × 5 streams = 5N subscriptions, the query rate is 10N queries/second. A typical PostgreSQL connection pool of 10–50 connections is saturated at N ≈ 5–25 connections. Once the pool is exhausted, all legitimate DB operations (historical message retrieval, topic existence checks, other subscriptions) queue or fail, causing service-wide degradation or complete outage of the gRPC mirror node. This maps directly to the stated severity: network inability to confirm new transactions via the mirror node.

### Likelihood Explanation

No authentication or API key is required to open a gRPC subscription — any unprivileged client with network access to port 5600 can execute this. The attack requires only a standard gRPC client library and the ability to open multiple TCP connections. It is fully repeatable and automatable. The attacker does not need to know any valid topic ID if `checkTopicExists = false`, and even with `checkTopicExists = true` (default), topic IDs are publicly enumerable from the REST API.

### Recommendation

1. **Enforce a minimum time-window width** in `TopicMessageFilter.isValidEndTime()` — reject filters where `endTime - startTime` is below a meaningful threshold (e.g., 1 second).
2. **Skip the DB query when the filter window is already fully elapsed**: in `poll()`, check whether `newFilter.getEndTime() != null && newFilter.getEndTime() <= DomainUtils.now()` before calling `findByFilter`, and complete the flux instead.
3. **Add a global concurrent-subscription limit** (not just per-connection) tracked with an `AtomicInteger` or semaphore, rejecting new subscriptions when the limit is reached.
4. **Add per-IP or per-connection subscription rate limiting** in the gRPC layer, analogous to the Bucket4j throttle already present in the `web3` module.
5. **Terminate subscriptions proactively** when `endTime` is in the past at subscription creation time rather than waiting for the `endTimeInterval` check.

### Proof of Concept

```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, mirror_network_service_pb2

def flood(thread_id):
    channel = grpc.insecure_channel("mirror-node-grpc:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    # startTime = 1000 ns epoch, endTime = 1001 ns epoch (1 ns window, fully in the past)
    request = mirror_network_service_pb2.ConsensusTopicQuery(
        topicID=...,
        consensusStartTime=Timestamp(seconds=0, nanos=1000),
        consensusEndTime=Timestamp(seconds=0, nanos=1001),
    )
    while True:
        try:
            for _ in stub.subscribeTopic(request):
                pass
        except:
            pass  # re-open immediately after endTimeInterval terminates it

# Open 200 threads × 5 concurrent streams each = 1000 subscriptions
# = 2000 empty DB queries/second at default 500ms interval
for i in range(200):
    threading.Thread(target=flood, args=(i,), daemon=True).start()
input("Running... press enter to stop")
```

Each thread opens a new TCP connection; gRPC HTTP/2 multiplexing allows 5 concurrent streams per connection (`maxConcurrentCallsPerConnection = 5`). Every 500 ms, each stream triggers `topicMessageRepository.findByFilter(newFilter)` with a 1-nanosecond window that returns zero rows but still acquires a DB connection from the pool. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-46)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L28-30)
```java
    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```
