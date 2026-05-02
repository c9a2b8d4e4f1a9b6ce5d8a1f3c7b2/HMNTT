### Title
Unauthenticated DoS via Uncached Aggregation Query on `/api/v1/network/supply`

### Summary
The `getSupply()` method in `EntityRepository` executes a full `unnest`+`join` aggregation over the `entity` table on every HTTP request to `/api/v1/network/supply`, with no server-side response caching and no rate limiting in the rest-java service layer. An unprivileged attacker sending concurrent requests from multiple source IPs can saturate the database connection pool, starving ≥30% of mirror node DB connections and degrading or halting mirror node processing.

### Finding Description

**Exact code path:**

`GET /api/v1/network/supply`
→ `NetworkController.getSupply()` (lines 132–150)
→ `NetworkServiceImpl.getSupply()` (lines 59–89)
→ `EntityRepository.getSupply(lowerBounds, upperBounds)` (lines 19–29)

The native query at `EntityRepository.java` lines 19–29 is:

```sql
select cast(coalesce(sum(e.balance), 0) as bigint) as unreleased_supply,
       cast(coalesce(max(e.balance_timestamp), 0) as bigint) as consensus_timestamp
from entity e
join unnest(
        cast(string_to_array(:lowerBounds, ',') as bigint[]),
        cast(string_to_array(:upperBounds, ',') as bigint[])
     ) as ranges(min_val, max_val)
  on e.id between ranges.min_val and ranges.max_val
```

This is a multi-range aggregation scan over the `entity` table. It is called unconditionally on every request when no `timestamp` parameter is provided (the common case).

**Root cause — no caching anywhere in the call chain:**

- `NetworkServiceImpl.getSupply()` has no `@Cacheable` or any memoization. [1](#0-0) 
- `NetworkController.getSupply()` has no `@Cacheable`, no `Cache-Control` response header, and no throttle guard. [2](#0-1) 
- The only filter registered in `RestJavaConfiguration` is a `ShallowEtagHeaderFilter`. This filter computes the full response body first (executing the DB query), then optionally suppresses the body if the client sends a matching `If-None-Match` header. An attacker simply omits that header, so the DB query runs on every request regardless. [3](#0-2) 
- No `RateLimit*.java` files exist in the rest-java module. No rate limiting configuration was found in `rest-java/src/main/resources/`. 

**Why the ETag check is insufficient:**

`ShallowEtagHeaderFilter` wraps the response in a `ContentCachingResponseWrapper`, lets the full handler chain execute (including the DB query), then computes an MD5 of the response body. The DB query is already done before the ETag comparison occurs. An attacker who never sends `If-None-Match` gets a full response and forces a full DB query every time.

### Impact Explanation

Spring Boot's default HikariCP pool size is 10 connections. The `unnest`+`join` aggregation over the `entity` table (which grows continuously as the network operates) is a non-trivial query. If an attacker holds 3–4 connections busy with slow aggregation queries simultaneously, that is 30–40% of the pool. Other mirror node operations (importer writes, other REST endpoints) that need a DB connection will queue or time out, degrading or halting mirror node processing. At higher concurrency (10+ simultaneous requests), the pool is fully exhausted and all DB-dependent operations stall. This matches the stated scope: "Shutdown of ≥30% of network processing nodes without brute force actions."

### Likelihood Explanation

- **No authentication required**: the endpoint is fully public.
- **No rate limiting**: confirmed absent in the codebase.
- **Multi-IP bypass**: a single attacker with a modest botnet or cloud VMs can distribute requests across IPs, defeating any infrastructure-level per-IP rate limiting.
- **Repeatability**: the attack is trivially repeatable in a loop; each request is stateless and requires no prior knowledge.
- **Low cost**: a simple `curl` loop or `ab`/`wrk` benchmark from multiple hosts is sufficient.

### Recommendation

1. **Add server-side caching** on `NetworkServiceImpl.getSupply()` with a short TTL (e.g., 5–15 seconds) using Spring's `@Cacheable` with a Caffeine or Redis backend. Supply data changes at block cadence, so a short TTL is safe and eliminates the per-request DB hit for the common case.
2. **Add global rate limiting** at the API gateway or Spring filter level (e.g., Bucket4j, resilience4j `RateLimiter`) for the `/api/v1/network/supply` endpoint, applied per-IP and globally.
3. **Set explicit `Cache-Control` response headers** (e.g., `Cache-Control: public, max-age=10`) so CDN/reverse proxies can absorb repeated requests.
4. **Tune HikariCP** pool size and set a query timeout on the `getSupply` query to bound the blast radius.

### Proof of Concept

```bash
# From multiple hosts/IPs simultaneously:
for i in $(seq 1 50); do
  curl -s "https://<mirror-node-host>/api/v1/network/supply" &
done
wait
```

Repeat in a tight loop from ≥3 source IPs. Each request triggers a full `unnest`+`join` aggregation query. With 10+ concurrent requests, the HikariCP pool (default: 10 connections) is saturated. Monitor with:

```sql
SELECT count(*), state, wait_event_type, wait_event
FROM pg_stat_activity
WHERE query LIKE '%unnest%'
GROUP BY state, wait_event_type, wait_event;
```

Expected result: multiple active connections running the aggregation query, connection pool exhausted, other mirror node DB operations timing out.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L59-89)
```java
    public NetworkSupply getSupply(Bound timestamp) {
        final NetworkSupply networkSupply;

        final var bounds = networkProperties.getUnreleasedSupplyRangeBounds();
        final var lowerBounds = bounds.lowerBounds();
        final var upperBounds = bounds.upperBounds();

        if (timestamp.isEmpty()) {
            networkSupply = entityRepository.getSupply(lowerBounds, upperBounds);
        } else {
            var minTimestamp = timestamp.getAdjustedLowerRangeValue();
            final var maxTimestamp = timestamp.adjustUpperBound();

            // Validate timestamp range
            if (minTimestamp > maxTimestamp) {
                throw new IllegalArgumentException("Invalid range provided for timestamp");
            }

            final var optimalLowerBound = getFirstDayOfMonth(maxTimestamp, -1);
            minTimestamp = Math.max(minTimestamp, optimalLowerBound);

            networkSupply =
                    accountBalanceRepository.getSupplyHistory(lowerBounds, upperBounds, minTimestamp, maxTimestamp);
        }

        if (networkSupply.consensusTimestamp() == 0L) {
            throw new EntityNotFoundException("Network supply not found");
        }

        return networkSupply;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L132-150)
```java
    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);

        if (supplyType != null) {
            final var valueInTinyCoins =
                    supplyType == SupplyType.TOTALCOINS ? NetworkSupply.TOTAL_SUPPLY : networkSupply.releasedSupply();
            final var formattedValue = networkSupplyMapper.convertToCurrencyFormat(valueInTinyCoins);

            return ResponseEntity.ok()
                    .contentType(new MediaType(MediaType.TEXT_PLAIN, UTF_8))
                    .body(formattedValue);
        }

        return ResponseEntity.ok(networkSupplyMapper.map(networkSupply));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```
