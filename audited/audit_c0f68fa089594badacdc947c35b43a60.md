### Title
Unauthenticated High-Frequency Flooding of GET /api/v1/topics/{id} Causes Unbounded DB Lookups with No Negative-Result Caching

### Summary
`TopicServiceImpl.findById()` delegates directly to a plain `CrudRepository.findById()` with no caching layer. The `rest-java` module has no rate limiting on the `/api/v1/topics/{id}` endpoint. An unprivileged attacker can flood the endpoint with arbitrary non-existent topic IDs, causing one full database SELECT per request with no negative-result cache to absorb repeated misses, degrading database performance for all concurrent users.

### Finding Description
**Exact code path:**

`TopicController.getTopic()` → `TopicServiceImpl.findById()` → `TopicRepository.findById()`

- `TopicController` (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37): The `@GetMapping("/{id}")` handler calls `topicService.findById(id.id())` with no guard.
- `TopicServiceImpl.findById()` (`rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 20): Calls `topicRepository.findById(id.getId()).orElseThrow(...)` — a bare repository call with no caching.
- `TopicRepository` (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java`, lines 1–10): Extends `CrudRepository<Topic, Long>` with no `@Cacheable` annotation of any kind — neither positive nor negative results are cached.

**Root cause:** The `rest-java` `TopicRepository` has no `@Cacheable` annotation (contrast with `grpc/EntityRepository` which annotates `findById` with `@Cacheable(unless = "#result == null")`). Every call — hit or miss — issues a live SQL query to the database.

**Why existing checks fail:**
- The only servlet filters in `rest-java` are `LoggingFilter` and `MetricsFilter` — neither enforces rate limiting.
- The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` rate-limiting infrastructure exists exclusively in the `web3` module and is not wired into `rest-java` at all.
- There is no IP-based throttle, no per-client quota, and no application-level circuit breaker on this endpoint.

### Impact Explanation
Each request for a non-existent topic ID causes a full `SELECT` against the `topic` table. With no negative-result cache, 10,000 requests/second with distinct non-existent IDs produce 10,000 database queries/second. This exhausts database connection pool capacity and query throughput, degrading or denying service for all other API consumers sharing the same database. The impact is classified as griefing/DoS with no economic damage to network participants but measurable service degradation.

### Likelihood Explanation
The attack requires zero privileges — only the ability to send unauthenticated HTTP GET requests. The endpoint is publicly reachable. An attacker can trivially generate distinct non-existent IDs (e.g., large integers beyond the current topic count) using any HTTP load tool (`wrk`, `ab`, `curl` in a loop). The attack is repeatable, cheap, and requires no special knowledge of the system.

### Recommendation
1. Add `@Cacheable` to `TopicRepository.findById()` in `rest-java`, using `unless = "#result == null"` to cache positive results. For negative results, implement a short-TTL null-value cache (e.g., using a `NullValue` sentinel or a separate `@CachePut` on miss).
2. Port or reuse the `bucket4j`-based rate-limiting infrastructure from the `web3` module into `rest-java`, applying a per-IP or global request-per-second limit to all `/api/v1/` endpoints.
3. Consider adding a Spring Cache configuration to `rest-java` analogous to the `CacheConfiguration` in the `grpc` module.

### Proof of Concept
```bash
# Flood with non-existent topic IDs (requires no auth)
for i in $(seq 1000000 1100000); do
  curl -s "https://<mirror-node-host>/api/v1/topics/$i" &
done
wait
```
Each request triggers `SELECT * FROM topic WHERE id = $i` with no cache hit. Sustained at high concurrency, this saturates the database connection pool and increases query latency for all other API endpoints sharing the same database instance. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java (L1-10)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.restjava.repository;

import org.hiero.mirror.common.domain.topic.Topic;
import org.springframework.data.repository.CrudRepository;

public interface TopicRepository extends CrudRepository<Topic, Long> {}


```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L31-37)
```java
    @GetMapping(value = "/{id}")
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```
