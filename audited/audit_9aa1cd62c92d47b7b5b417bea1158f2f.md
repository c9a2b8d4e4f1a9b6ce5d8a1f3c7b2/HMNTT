### Title
Unbounded Infinite Retry Without Circuit Breaker in `PollingTopicMessageRetriever` Enables DB Connection Pool Exhaustion During Network Partition

### Summary
`PollingTopicMessageRetriever.retrieve()` applies `Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1))` with no circuit breaker and no global subscriber cap. During a database network partition, every active subscription independently retries DB queries indefinitely (bounded only by the 60 s per-subscription timeout), and an unprivileged attacker can continuously open new subscriptions to keep the HikariCP connection pool saturated, preventing the database from recovering once the partition heals.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, `retrieve()`, lines 51–62:

```java
return Flux.defer(() -> poll(context))
        .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                .jitter(0.1)
                .withFixedDelay(context.getFrequency())
                .withScheduler(scheduler))
        ...
        .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))  // line 58
        .timeout(retrieverProperties.getTimeout(), scheduler)             // line 59
```

**Root cause:** `Retry.backoff(Long.MAX_VALUE, ...)` sets the maximum retry attempts to `Long.MAX_VALUE` — effectively infinite. There is no circuit breaker (confirmed: zero matches for `CircuitBreaker`, `resilience4j`, or equivalent in all `grpc/**/*.java` files). There is also no global subscriber limit enforced in `TopicMessageServiceImpl` — only a metrics gauge (`subscriberCount`) is maintained, never checked against a ceiling.

**Exploit flow:**

1. During a DB network partition, every call to `poll(context)` → `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))` throws a connection exception.
2. `retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))` catches the error and schedules retries with exponential backoff (1 s, 2 s, 4 s, 8 s, 16 s, 32 s ≈ 6 attempts within the 60 s timeout window).
3. Each retry attempt tries to acquire a HikariCP connection from the pool.
4. An attacker opens many gRPC connections (each allowed up to `maxConcurrentCallsPerConnection = 5` concurrent calls) and subscribes to any valid topic. Each subscription starts a fresh 60 s retry window.
5. By continuously opening new subscriptions, the attacker keeps N concurrent subscriptions alive, each independently retrying. The aggregate connection-acquisition rate is N × (retries/60 s), saturating the HikariCP pool.
6. When the partition heals, the thundering herd of simultaneous retry attempts from all active subscriptions hits the DB at once, preventing orderly recovery.

**Why existing checks fail:**

- The 60 s `.timeout()` bounds a single subscription but does not prevent the attacker from immediately opening a replacement subscription.
- The Traefik-level `circuitBreaker` (`charts/hedera-mirror-grpc/values.yaml`, line 157–158) operates on HTTP/gRPC response-code ratios at the ingress layer; it does not observe or trip on internal DB connection failures.
- The `jitter(0.1)` on `RepeatSpec` and exponential backoff reduce per-subscription retry rate but do not coordinate across subscriptions — no shared circuit state exists.

### Impact Explanation
A sustained DB connection pool exhaustion prevents the mirror node gRPC service from serving any subscriber (historical or live) for the duration of the attack. When the DB partition heals, the thundering herd of retry attempts delays recovery proportionally to the number of active attacker subscriptions. In production, this translates to complete unavailability of the `ConsensusService` (topic message streaming) for all legitimate clients, with no automatic self-healing until the attacker stops opening subscriptions.

### Likelihood Explanation
The gRPC `ConsensusService` endpoint is publicly accessible with no authentication required. Any unprivileged client can subscribe to any topic. Opening hundreds of concurrent gRPC connections is trivial with standard gRPC client libraries. The attack requires only knowledge of one valid topic ID (or even an invalid one if `checkTopicExists = false`) and a script that continuously opens subscriptions. The attack is fully repeatable and requires no special privileges or insider knowledge.

### Recommendation
1. **Add a DB-layer circuit breaker**: Wrap `topicMessageRepository.findByFilter()` calls with Resilience4j `CircuitBreaker`. When the DB is clearly unavailable (error rate threshold exceeded), open the circuit and fail fast without acquiring pool connections, allowing the pool to drain and the DB to recover.
2. **Cap retry attempts**: Replace `Long.MAX_VALUE` with a small finite bound (e.g., `Retry.backoff(5, Duration.ofSeconds(1)).maxBackoff(Duration.ofSeconds(30))`). After exhausting retries, propagate the error to the subscriber rather than holding a pool connection slot indefinitely.
3. **Enforce a global subscriber limit**: In `TopicMessageServiceImpl`, reject new subscriptions when `subscriberCount` exceeds a configurable maximum, preventing pool exhaustion from concurrent attacker subscriptions.
4. **Add `maxBackoff`**: Even without a circuit breaker, `.maxBackoff(Duration.ofSeconds(30))` prevents the backoff from growing unboundedly and caps per-subscription connection pressure.

### Proof of Concept
```
# Precondition: DB network partition is active (or can be simulated with iptables)
# iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# Step 1: Identify any valid (or invalid with checkTopicExists=false) topic ID
TOPIC_ID="0.0.1234"

# Step 2: Open N concurrent gRPC subscriptions using grpcurl or a script
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID":{"shardNum":0,"realmNum":0,"topicNum":1234},"consensusStartTime":{"seconds":0}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Step 3: Observe HikariCP metrics:
# hikaricp_connections_active / hikaricp_connections_max → approaches 1.0
# (GrpcHighDBConnections alert fires at >75%)

# Step 4: Restore DB connectivity:
# iptables -D OUTPUT -p tcp --dport 5432 -j DROP
# Observe: DB does not recover promptly; retry storm from 200 active subscriptions
# floods the newly available DB with simultaneous connection attempts.
# New legitimate subscriptions receive errors until the attacker subscriptions time out (60s each).
```