### Title
Unbounded Thread Exhaustion via Missing Query Timeout in `PollingTopicListener.poll()` Under Network Partition

### Summary
`PollingTopicListener.poll()` invokes `topicMessageRepository.findByFilter()`, which executes a fully blocking, synchronous JDBC `getResultList()` call with no query timeout configured at either the JPA or JDBC layer. Because this call runs on a shared `Schedulers.boundedElastic()` thread pool and no Reactor `.timeout()` operator is applied to the polling Flux chain, a network partition between the gRPC service and the database causes every in-flight poll to block its thread indefinitely. An unprivileged attacker who opens many concurrent gRPC subscriptions before or during a partition can exhaust the bounded thread pool, denying service to all subscribers.

### Finding Description

**Exact code path:**

`PollingTopicListener.poll()` (lines 51–62) constructs a filter and calls:
```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
``` [1](#0-0) 

`TopicMessageRepositoryCustomImpl.findByFilter()` (line 60) materializes the entire result set synchronously before returning:
```java
return typedQuery.getResultList().stream();
``` [2](#0-1) 

No `jakarta.persistence.query.timeout` hint is set on the `TypedQuery` — only `HINT_READ_ONLY` is applied: [3](#0-2) 

The polling loop runs on a single shared `Schedulers.boundedElastic()` instance (a singleton `@Named` bean): [4](#0-3) 

`ListenerProperties` defines no timeout field whatsoever: [5](#0-4) 

No `.timeout()` operator appears anywhere in the `PollingTopicListener` Flux chain: [6](#0-5) 

**Root cause:** `getResultList()` is a blocking JDBC call. When the TCP connection to PostgreSQL hangs (no RST, just silence — the classic network partition symptom), the JDBC driver waits indefinitely because no socket timeout or statement timeout is configured. The `boundedElastic` thread executing `poll()` is held for the duration of the hang. With N concurrent subscribers, N threads are held simultaneously.

**Why existing checks fail:** The sibling class `PollingTopicMessageRetriever` correctly applies `.timeout(retrieverProperties.getTimeout(), scheduler)`: [7](#0-6) 

`PollingTopicListener` has no equivalent protection. The `RepeatSpec` with `withFixedDelay` only delays between polls — it does not bound the duration of an individual poll execution.

### Impact Explanation

`Schedulers.boundedElastic()` defaults to `10 × availableProcessors` threads (typically 40–80 on a production host). Once all threads are blocked, no new poll tasks can execute. All active subscribers stop receiving messages. New subscriptions cannot be scheduled. The gRPC service becomes effectively unavailable for topic streaming. This is a complete Denial-of-Service against the HCS streaming endpoint with no self-recovery until the partition resolves or the process is restarted.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication required: [8](#0-7) 

An unprivileged attacker needs only to:
1. Open a large number of concurrent gRPC subscriptions (trivially scriptable with any gRPC client).
2. Wait for a natural network partition (cloud environments experience these regularly) or induce one via network-level interference if the attacker has any presence on the path between the gRPC pod and the database.

The attacker does not need to cause the partition themselves — they only need to have subscriptions open when one occurs. This makes the attack highly repeatable and low-cost.

### Recommendation

Apply all three layers of defense:

1. **JPA query timeout:** Add `typedQuery.setHint("jakarta.persistence.query.timeout", timeoutMillis)` in `TopicMessageRepositoryCustomImpl.findByFilter()`.

2. **Reactor timeout operator:** Add `.timeout(listenerProperties.getInterval().multipliedBy(N), scheduler)` to the `Flux.defer(() -> poll(context))` chain in `PollingTopicListener.listen()`, mirroring what `PollingTopicMessageRetriever` already does.

3. **JDBC socket timeout:** Configure `socketTimeout` on the PostgreSQL JDBC datasource (e.g., via `spring.datasource.hikari.data-source-properties.socketTimeout=30`) so the driver itself closes hung connections.

4. **Add a `timeout` field to `ListenerProperties`** to make the timeout configurable, consistent with `RetrieverProperties`.

### Proof of Concept

**Preconditions:** gRPC service running in `POLL` listener mode (`hiero.mirror.grpc.listener.type=POLL`), reachable without authentication.

**Steps:**

1. Open `T` concurrent gRPC streams (where `T` ≥ `10 × CPU cores`) to `subscribeTopic` for any valid topic ID, with no `endTime` and no `limit` (so they stay open indefinitely):
   ```bash
   for i in $(seq 1 100); do
     grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' \
       <host>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
   done
   ```

2. Induce a network partition between the gRPC pod and PostgreSQL (e.g., drop packets with `iptables -I OUTPUT -p tcp --dport 5432 -j DROP` on the gRPC host, or use a network policy in Kubernetes).

3. Wait for the next poll interval (default 500 ms). Each of the `T` subscriber polling tasks calls `getResultList()` on a hung TCP connection and blocks its `boundedElastic` thread indefinitely.

4. Attempt to open a new subscription or observe existing subscribers — no messages are delivered. The `boundedElastic` thread pool is saturated. The gRPC service is effectively down for all topic streaming until the partition resolves or the process restarts.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-48)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", interval.toMillis(), filter));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L48-60)
```java
        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L17-43)
```java
public class ListenerProperties {

    private boolean enabled = true;

    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;

    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L58-59)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L1-10)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.grpc.controller;

import com.google.protobuf.InvalidProtocolBufferException;
import com.hedera.mirror.api.proto.ConsensusServiceGrpc;
import com.hedera.mirror.api.proto.ConsensusTopicQuery;
import com.hedera.mirror.api.proto.ConsensusTopicResponse;
import com.hederahashgraph.api.proto.java.ConsensusMessageChunkInfo;
import com.hederahashgraph.api.proto.java.Timestamp;
```
