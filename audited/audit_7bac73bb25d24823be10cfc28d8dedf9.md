### Title
Unauthenticated Repeated Aggregation Query DoS via `/api/v1/network/supply` Without Timestamp

### Summary
The `GET /api/v1/network/supply` endpoint is publicly accessible with no authentication, rate limiting, or caching. When called without a `timestamp` parameter, every request unconditionally executes a full `SUM(balance)` + `MAX(balance_timestamp)` aggregation over the `entity` table. An attacker can flood this endpoint to exhaust database CPU and I/O resources.

### Finding Description

**Exact code path:**

1. `NetworkController.getSupply()` ( [1](#0-0) ) receives the request. When `timestamp` is absent, `Bound.of(null, ...)` returns `Bound.EMPTY`.

2. `NetworkServiceImpl.getSupply()` checks `timestamp.isEmpty()` and, when true, directly calls `entityRepository.getSupply(lowerBounds, upperBounds)` with no intermediate caching or throttling: [2](#0-1) 

3. The repository executes this native SQL on every call: [3](#0-2) 

```sql
SELECT cast(coalesce(sum(e.balance), 0) as bigint) as unreleased_supply,
       cast(coalesce(max(e.balance_timestamp), 0) as bigint) as consensus_timestamp
FROM entity e
JOIN unnest(
    cast(string_to_array(:lowerBounds, ',') as bigint[]),
    cast(string_to_array(:upperBounds, ',') as bigint[])
) as ranges(min_val, max_val)
  ON e.id BETWEEN ranges.min_val AND ranges.max_val
```

**Root cause:** No `@Cacheable` annotation exists anywhere in the `rest-java` service layer (confirmed: zero cache annotations in `rest-java/src/main/java/**/*.java`). No rate-limiting filter or throttle applies to this endpoint (confirmed: no `bucket4j`, `resilience4j`, or custom rate-limit code in the rest-java module for this path). The `HIGH_VOLUME_THROTTLE` constant referenced in the controller is only used for the fee estimation POST endpoint, not for `/supply`.

**Failed assumption:** The design assumes either infrastructure-level protection (reverse proxy rate limiting) or that the query is cheap enough to be harmless. Neither is enforced at the application layer, and on a production mirror node the `entity` table contains millions of rows.

### Impact Explanation

A production Hedera mirror node's `entity` table holds every account, contract, token, and topic ever created — potentially tens of millions of rows. The aggregation (`SUM` + `MAX`) must scan all rows matching the configured ID ranges on every request. Sustained flooding saturates database worker threads and I/O bandwidth, degrading or denying service to all other mirror node API consumers. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and a single HTTP client. The endpoint is documented in the public Hedera mirror node API spec. Any script kiddie can write a tight loop of `curl https://<mirror>/api/v1/network/supply` requests. The attack is trivially repeatable and requires no special knowledge of the system internals.

### Recommendation

Apply at least one of the following mitigations at the application layer:

1. **Cache the result**: Annotate `NetworkServiceImpl.getSupply()` (for the no-timestamp branch) with `@Cacheable` with a short TTL (e.g., 5–10 seconds), since the supply value changes only with each consensus round.
2. **Rate-limit the endpoint**: Integrate Bucket4j or a servlet filter to cap requests per IP per time window for `/api/v1/network/supply`.
3. **Materialize the aggregation**: Maintain a pre-computed supply value updated by the importer, replacing the live aggregation query with a simple primary-key lookup.

### Proof of Concept

```bash
# No authentication, no special headers required
# Run from any machine with network access to the mirror node

while true; do
  curl -s "https://<mirror-node-host>/api/v1/network/supply" -o /dev/null &
done
# Or with parallel connections:
seq 1 200 | xargs -P 200 -I{} curl -s "https://<mirror-node-host>/api/v1/network/supply" -o /dev/null
```

Each request triggers a fresh `SUM(balance)` full aggregation on the `entity` table. With sufficient concurrency, database CPU saturates and query latency for all endpoints degrades or times out.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L132-137)
```java
    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L66-67)
```java
        if (timestamp.isEmpty()) {
            networkSupply = entityRepository.getSupply(lowerBounds, upperBounds);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L19-29)
```java
    @Query(value = """
                    select cast(coalesce(sum(e.balance), 0) as bigint) as unreleased_supply,
                        cast(coalesce(max(e.balance_timestamp), 0) as bigint) as consensus_timestamp
                    from entity e
                    join unnest(
                            cast(string_to_array(:lowerBounds, ',') as bigint[]),
                            cast(string_to_array(:upperBounds, ',') as bigint[])
                         ) as ranges(min_val, max_val)
                      on e.id between ranges.min_val and ranges.max_val
                    """, nativeQuery = true)
    NetworkSupply getSupply(String lowerBounds, String upperBounds);
```
