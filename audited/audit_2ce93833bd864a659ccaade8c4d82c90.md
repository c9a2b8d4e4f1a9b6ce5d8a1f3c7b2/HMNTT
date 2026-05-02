### Title
Throttled gRPC Subscription Bypass via limit=maxPageSize Enables Unauthenticated DB Query Storm DoS

### Summary
An unauthenticated attacker can set `limit` equal to `maxPageSize` (1000) on a throttled `subscribeTopic` gRPC call targeting a topic with ≥1000 historical messages. The `isComplete()` logic at line 122 returns `true` via the `limitHit` branch after a single poll, causing the subscription to terminate immediately with no inter-poll delay. Since there is no per-IP connection limit or reconnection rate limit on the gRPC endpoint, an attacker can continuously reopen subscriptions across many connections, generating a sustained high-rate stream of full-page DB queries that exhausts database resources.

### Finding Description

**Exact code path:**

`PollingTopicMessageRetriever.java`, `PollingContext.isComplete()`, lines 121–129:

```java
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    if (throttled) {
        return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
    }
    return limitHit;
}
```

**Root cause — failed assumption:**

The `throttled=true` path is designed to slow down historical retrieval by inserting a `pollingFrequency` delay (default 2 s) between polls via `repeatWhen(...).withFixedDelay(context.getFrequency())` (line 54). The design assumes that a throttled subscription will run for multiple poll cycles, each separated by the delay. However, the delay only applies *between* repeat iterations. When `isComplete()` returns `true`, the `repeatWhen` predicate `r -> !context.isComplete()` evaluates to `false` and the flux terminates immediately — the 2-second delay is never incurred.

**Exploit flow:**

1. `poll()` (line 65) computes `pageSize = Math.min(limit - total, maxPageSize) = Math.min(1000, 1000) = 1000` and issues one DB query via `topicMessageRepository.findByFilter(newFilter)`.
2. The DB returns 1000 rows; `onNext` increments `pageSize` and `total` to 1000 each.
3. `isComplete()` evaluates: `limitHit = (1000 == 1000) = true`; `pageSize < maxPageSize = (1000 < 1000) = false`; returns `true`.
4. The subscription completes after **one poll, zero delay**.
5. The attacker's client immediately reconnects and repeats.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (`NettyProperties`, line 14) limits concurrent streams *per TCP connection*, not per IP or globally. An attacker opens many connections.
- No per-IP or global gRPC rate limiter exists. The `ThrottleConfiguration`/`ThrottleManagerImpl` applies only to the web3/REST module.
- No authentication is required for `subscribeTopic` (`ConsensusController`, line 43–53).
- The `retrieverProperties.getTimeout()` (default 60 s) is an *inactivity* timeout, not a reconnection rate limit.
- The `subscriberCount` gauge (line 48, `TopicMessageServiceImpl`) is metrics-only; it enforces no cap.

### Impact Explanation

Each reconnection triggers `topicMessageRepository.findByFilter()` → `typedQuery.getResultList()` (line 60, `TopicMessageRepositoryCustomImpl`), a full synchronous JDBC query loading up to 1000 rows into memory. With N connections × 5 streams each cycling at the speed of a DB round-trip (~5–50 ms), an attacker with modest resources can sustain hundreds of concurrent full-page queries. This exhausts the DB connection pool, CPU, and I/O, causing query timeouts and service degradation for all legitimate users of the mirror node.

### Likelihood Explanation

The attack requires no credentials, no on-chain funds, and no special tooling — only a standard gRPC client (e.g., `grpcurl` or the Hedera SDK). Any topic on mainnet/testnet with ≥1000 messages (trivially found) suffices. The attacker needs only a single machine with many TCP connections. The attack is fully repeatable and automatable.

### Recommendation

1. **Add a per-IP or global gRPC subscription rate limiter** (e.g., Bucket4j token bucket, analogous to `ThrottleConfiguration` in the web3 module) applied in `ConsensusController.subscribeTopic()` before delegating to the service.
2. **Enforce a global or per-IP cap on concurrent active subscriptions**, checked against `subscriberCount` or a per-IP counter.
3. **Apply a minimum reconnection backoff** server-side, or enforce a minimum subscription lifetime before a new one from the same source is accepted.
4. **Cap the user-supplied `limit`** to a value strictly less than `maxPageSize` (e.g., `maxPageSize / 2`) so that a single poll can never satisfy the limit, ensuring the inter-poll delay always fires at least once.

### Proof of Concept

**Preconditions:** A topic (e.g., `0.0.1234`) exists with ≥1000 messages on the target mirror node.

```bash
# Open 20 parallel gRPC streams, each cycling limit=1000 subscriptions
for i in $(seq 1 20); do
  (
    while true; do
      grpcurl -plaintext \
        -d '{"topicID":{"topicNum":1234},"consensusStartTime":{"seconds":0},"limit":1000}' \
        <mirror-node-host>:5600 \
        com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
        > /dev/null 2>&1
      # No sleep — reconnect immediately after completion
    done
  ) &
done
wait
```

Each iteration causes one DB query fetching 1000 rows. With 20 parallel loops cycling at ~10–50 ms per round-trip, this generates 400–2000 full-page DB queries per second, rapidly exhausting the database connection pool and degrading service for all users.