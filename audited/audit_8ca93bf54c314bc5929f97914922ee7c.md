### Title
Connection Pool Exhaustion via Unbounded Range Scan on Public `/api/v1/network/registered-nodes` Endpoint

### Summary
The public `GET /api/v1/network/registered-nodes` endpoint in the rest-java service invokes `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()`, which executes a native SQL range scan with no server-side rate limiting. The 10-second `statementTimeout` acts as the upper bound for how long each request can hold a HikariCP connection. An unauthenticated attacker sending concurrent requests with maximally wide ID ranges can keep all pool connections occupied for up to 10 seconds each, starving every other endpoint served by the same rest-java instance.

### Finding Description

**Exact code path:**

`NetworkController.getRegisteredNodes()` (line 174) calls `NetworkServiceImpl.getRegisteredNodes()` (line 140–151), which calls:

```java
registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
        lowerBound, upperBound, nodeTypeId, page);
```

The repository executes:

```sql
select * from registered_node
where registered_node_id >= :lowerBound
  and registered_node_id <= :upperBound
  and deleted is false
  and (:type is null or type @> array[:type]::smallint[])
``` [1](#0-0) 

When no `registerednode.id` parameter is supplied, `lowerBound = 0` and `upperBound = Long.MAX_VALUE` (full table scan). The `type @> array[:type]::smallint[]` array-containment predicate is not index-friendly and forces a sequential filter pass over every row in the range. [2](#0-1) 

**Root cause / failed assumption:**

The design assumes queries will always be fast. The `statementTimeout = 10000` ms is the only guard, but it is the *ceiling* of how long a connection can be held — not a rate limiter. No per-IP or global request-rate limit exists for any rest-java endpoint. [3](#0-2) 

The rest-java configuration table exposes no `maximumPoolSize` override; HikariCP defaults to 10 connections. The Helm chart's Traefik middleware provides only a circuit-breaker and retry — no rate limiting. [4](#0-3) 

### Impact Explanation

With a pool of N connections (default 10) and a statement timeout of T = 10 s, an attacker sustaining N/T = **1 request/second** keeps the pool permanently saturated. All other rest-java endpoints (`/api/v1/network/nodes`, `/api/v1/network/fees`, `/api/v1/accounts/…`, `/api/v1/topics/…`) share the same HikariCP pool and will begin returning `HikariPool-1 - Connection is not available, request timed out` errors after the pool's `connectionTimeout` (HikariCP default 30 s) elapses. This is a full application-layer denial of service for the rest-java service with no collateral damage to the database itself (queries are killed by the statement timeout).

### Likelihood Explanation

- **No authentication required** — the endpoint is publicly documented and reachable without credentials.
- **No rate limiting** — unlike the web3 module (which has `ThrottleManagerImpl` with `requestsPerSecond = 500`), rest-java has zero equivalent protection.
- **Trivial to automate** — a single `curl` loop or any HTTP load tool suffices; no exploit code needed.
- **Repeatability** — the attack is stateless and can be sustained indefinitely.
- The only practical constraint is that the `registered_node` table must be large enough for queries to take more than a few milliseconds. As the network grows and more block nodes register, this threshold is crossed naturally.

### Recommendation

1. **Add a global rate limiter to rest-java** analogous to the web3 `ThrottleManagerImpl`. A Bucket4j filter at the Spring `HandlerInterceptor` level, configured via a new `hiero.mirror.restJava.throttle.requestsPerSecond` property, would bound concurrent DB load.
2. **Reduce `statementTimeout`** for this specific query class. 10 seconds is generous; 2–3 seconds is sufficient for a paginated lookup on an indexed primary key.
3. **Add a dedicated index** on `(deleted, type, registered_node_id)` so the array-containment filter does not degrade to a sequential scan as the table grows.
4. **Configure an explicit `maximumPoolSize`** in the rest-java Helm values so operators are aware of the pool ceiling and can tune it alongside any rate limiter.

### Proof of Concept

```bash
# Exhaust a 10-connection pool at 1 req/s (adjust HOST)
HOST="https://<mirror-node-host>"
for i in $(seq 1 20); do
  curl -s "${HOST}/api/v1/network/registered-nodes?limit=100" &
done
wait

# Verify other endpoints are now timing out:
curl -v "${HOST}/api/v1/network/fees"
# Expected: connection acquisition timeout or 503 from circuit-breaker
```

Each background `curl` triggers `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(0, Long.MAX_VALUE, null, page)` — a full table scan held open for up to 10 seconds. Twenty concurrent requests against a 10-connection pool guarantees pool exhaustion for the duration of the attack.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java (L14-22)
```java
    @Query(value = """
            select * from registered_node
            where registered_node_id >= :lowerBound
            and registered_node_id <= :upperBound
            and deleted is false
            and (:type is null or type @> array[:type]::smallint[])
            """, nativeQuery = true)
    List<RegisteredNode> findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
            long lowerBound, long upperBound, @Nullable Short type, Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L140-152)
```java
    public Collection<RegisteredNode> getRegisteredNodes(RegisteredNodesRequest request) {
        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE.REGISTERED_NODE_ID.getName());
        final var page = PageRequest.of(0, request.getLimit(), sort);

        final var nodeType = request.getType();
        final var bounds = resolveRegisteredNodeIdBounds(request.getRegisteredNodeIds());
        final long lowerBound = bounds.lowerEndpoint();
        final long upperBound = bounds.upperEndpoint();

        final var nodeTypeId = nodeType != null ? nodeType.getId() : null;
        return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
                lowerBound, upperBound, nodeTypeId, page);
    }
```

**File:** docs/configuration.md (L629-629)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L150-156)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms

```
