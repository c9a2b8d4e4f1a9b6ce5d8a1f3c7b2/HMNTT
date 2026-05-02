### Title
Unbounded Blocking JDBC Call in `topicExists()` Enables Thread-Exhaustion DoS During Network Partition

### Summary
`topicExists()` in `TopicMessageServiceImpl` calls `entityRepository.findById()` — a synchronous, blocking Spring Data JPA/JDBC call — eagerly inside `Mono.justOrEmpty()` with no application-level `.timeout()` operator. No JDBC socket timeout is configured for the gRPC service's HikariCP connection pool. During a network partition, the blocking call hangs for the full OS TCP timeout (potentially 15+ minutes), and any unprivileged user sending concurrent `subscribeTopic` requests during that window exhausts the server thread pool, causing a complete DoS.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (line 44–45) calls `topicMessageService::subscribeTopic` via `flatMapMany`, which synchronously invokes `topicExists(filter)` (line 87). Inside `topicExists()` (line 96):

```java
return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
```

`Mono.justOrEmpty(T)` evaluates its argument **eagerly** — `entityRepository.findById(topicId.getId())` is a synchronous blocking JDBC call (Spring Data `CrudRepository<Entity, Long>`) that executes **before** the `Mono` is even assembled. There is no `Mono.fromCallable(...)` deferral, no `.subscribeOn(Schedulers.boundedElastic())`, and no `.timeout(...)` operator anywhere on the `topicExists()` chain.

**Root cause — failed assumption:**
The design assumes the JDBC call will be bounded by `hiero.mirror.grpc.db.statementTimeout = 10000` (ms). This is a PostgreSQL server-side `statement_timeout` session parameter. It fires only when the database server receives and begins executing the query. During a network partition, the TCP socket is established but packets are silently dropped: the query never reaches the server (or the response never returns), so `statement_timeout` **never fires**. The thread blocks at the OS TCP layer.

**No JDBC socket timeout is configured for the gRPC connection pool.** A `grep` across all `grpc/**` files for `socketTimeout`, `connectTimeout`, `connectionTimeout`, and `statementTimeout` returns zero matches. The `socketTimeout`/`connectTimeout` values in `CommonProperties.DatabaseStartupProperties` are used exclusively by `DatabaseWaiter` for startup health checks, not for the runtime HikariCP pool. The HikariCP pool is built from `spring.datasource.hikari` properties with no socket-level timeout set.

**Exploit flow:**
1. Network partition occurs between gRPC service and PostgreSQL (precondition; can be natural failure or attacker-controlled if on the network path).
2. Attacker sends N concurrent `subscribeTopic` gRPC requests with any valid topic ID format.
3. Each request reaches `Mono.justOrEmpty(entityRepository.findById(...))` and blocks its executing thread waiting for a TCP response that never arrives.
4. With default Linux TCP keepalive (`tcp_keepalive_time = 7200s`), each thread blocks for up to ~2 hours unless the OS retransmit timeout fires first (~15 minutes with default `tcp_retries2 = 15`).
5. The gRPC executor thread pool (bounded) is exhausted; all subsequent requests queue and eventually time out or are rejected.

**Why existing checks fail:**
- `statementTimeout = 10000ms`: server-side only; ineffective during network partition.
- `@Cacheable` on `findById`: cache miss on first request per entity; attacker uses distinct topic IDs to bypass cache.
- `netty.maxConcurrentCallsPerConnection = 5`: limits per-connection concurrency, not total server-wide concurrency; attacker opens multiple connections.
- No `.timeout()` on `topicExists()` Mono.
- No `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())` to isolate the blocking call.

### Impact Explanation
Complete DoS of the gRPC service. All `subscribeTopic` calls stall; no new subscriptions can be established. Existing live subscriptions (already past `topicExists`) are unaffected, but no new ones can start. The `subscriberCount` gauge never increments for stalled requests, masking the attack from that metric. Severity: **High** — full service unavailability for all clients during the attack window.

### Likelihood Explanation
The network partition precondition can arise from natural infrastructure failure (cloud AZ split, DB failover, misconfigured firewall rule) without any attacker involvement. Once the partition exists, exploitation requires only the ability to open gRPC connections and send `subscribeTopic` requests — zero privileges, no authentication required. The attack is repeatable: the attacker simply keeps sending requests. The `maxConcurrentCallsPerConnection` limit of 5 is trivially bypassed by opening multiple connections from different source ports or IPs.

### Recommendation

1. **Defer and isolate the blocking call** — wrap `entityRepository.findById()` in `Mono.fromCallable()` and schedule it on `Schedulers.boundedElastic()`:
   ```java
   return Mono.fromCallable(() -> entityRepository.findById(topicId.getId()))
              .subscribeOn(Schedulers.boundedElastic())
              .timeout(Duration.ofSeconds(5))
              .flatMap(Mono::justOrEmpty)
              ...
   ```
2. **Add a JDBC socket timeout** to the gRPC HikariCP pool via `spring.datasource.hikari.data-source-properties.socketTimeout=10` (seconds) in the gRPC `application.yml`. This bounds the OS-level TCP hang.
3. **Add a Reactor `.timeout()` operator** on the `topicExists()` Mono to enforce an application-level deadline independent of the JDBC layer.

### Proof of Concept

**Preconditions:**
- gRPC service running and reachable.
- Network partition between gRPC service and PostgreSQL (e.g., `iptables -I OUTPUT -d <db-host> -j DROP` on the gRPC host, or a firewall rule dropping DB traffic).

**Steps:**
1. Establish the network partition (drop TCP packets to the DB host on port 5432).
2. From an unprivileged client, open 20 gRPC connections and send `subscribeTopic` with a valid topic ID format on each:
   ```
   for i in $(seq 1 20); do
     grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' <grpc-host>:5600 \
       com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
   done
   ```
3. Observe via thread dump (`jstack`) or metrics that gRPC executor threads are all blocked in `entityRepository.findById()` / JDBC socket read.
4. Send a new `subscribeTopic` request from a fresh client — it hangs indefinitely (thread pool exhausted).
5. Restore network connectivity; threads unblock and service recovers.

**Expected result:** Step 4 produces no response until the OS TCP timeout fires (~15 minutes), confirming thread-pool exhaustion DoS. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-92)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** docs/configuration.md (L414-414)
```markdown
| `hiero.mirror.grpc.db.statementTimeout`                    | 10000            | The number of milliseconds to wait before timing out a query statement                                    |
```
