### Title
Unauthenticated DoS via Unbounded Repeated `getSupplyHistory` Queries on `/api/v1/network/supply`

### Summary
The `GET /api/v1/network/supply` endpoint in the `rest-java` module accepts arbitrary `timestamp` parameters from any unauthenticated user and, when a timestamp is provided, unconditionally executes a heavy aggregation query (`getSupplyHistory`) against the `account_balance` table on every request. The `rest-java` module has no application-level rate limiting and no caching for this query path, allowing an attacker to flood the database with concurrent expensive queries, exhausting the connection pool and saturating DB CPU, which degrades all other query-dependent services.

### Finding Description

**Exact code path:**

`NetworkController.getSupply()` receives the timestamp parameter and delegates to `NetworkServiceImpl.getSupply()`: [1](#0-0) 

When `timestamp` is non-empty, `NetworkServiceImpl.getSupply()` computes bounds and calls `accountBalanceRepository.getSupplyHistory()` directly — no cache, no guard: [2](#0-1) 

The only mitigation applied is clamping `minTimestamp` to the first day of the prior month relative to `maxTimestamp`: [3](#0-2) 

This still allows up to ~1 month of `account_balance` rows to be scanned per request. The underlying query performs a `DISTINCT ON (account_id)` aggregation with a `JOIN unnest(...)` over the full timestamp range: [4](#0-3) 

**No application-level rate limiting exists in `rest-java`:** The only rate-limiting code in the repository lives in the `web3` module (`ThrottleConfiguration`, `ThrottleManagerImpl`) and is not wired into `rest-java`. The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, `RestJavaConfiguration`, and `WebMvcConfiguration` — none of which enforce request rate limits: [5](#0-4) 

**No caching exists for `getSupplyHistory`:** A grep across all `rest-java` Java sources finds zero `@Cacheable` annotations. Every request with a timestamp parameter hits the database unconditionally.

**Root cause:** The failed assumption is that infrastructure-level controls (e.g., the GCP backend policy `maxRatePerEndpoint: 250` in the Helm chart) are sufficient to prevent abuse. This is a deployment-time configuration, not a code-level guarantee, and is absent in non-GCP or default deployments.

### Impact Explanation

An attacker sending N concurrent requests with distinct timestamp values (to defeat any DB-level plan cache) forces N simultaneous `DISTINCT ON` aggregation queries against the `account_balance` table. Each query can run for up to the configured `statementTimeout` of 10,000 ms: [6](#0-5) 

With a bounded HikariCP connection pool, concurrent long-running queries exhaust available connections. Other endpoints (including transaction-related queries) queue or fail with connection timeout errors, causing effective service degradation or denial of service for the mirror node REST API.

### Likelihood Explanation

No authentication, API key, or credential is required. Any external user can issue `GET /api/v1/network/supply?timestamp=lte:X` with varying `X` values. The attack is trivially scriptable with `curl` or any HTTP load tool. The endpoint is publicly routed via the gateway: [7](#0-6) 

The absence of application-level rate limiting means the only protection is infrastructure configuration, which is not universally applied.

### Recommendation

1. **Add application-level rate limiting** to `rest-java` analogous to the `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl`, applied via a servlet filter on `/api/v1/network/supply`.
2. **Cache `getSupplyHistory` results** using Spring's `@Cacheable` with a short TTL (e.g., 15–30 seconds), keyed on `(lowerTimestamp, upperTimestamp)`. Since balance snapshots are periodic, repeated queries for the same range return identical results.
3. **Enforce a minimum timestamp granularity** (e.g., round to the nearest balance snapshot interval) to collapse many distinct attacker-supplied timestamps to the same cache key.
4. **Add a DB-level connection pool limit per endpoint** or use a query semaphore to cap concurrent `getSupplyHistory` executions.

### Proof of Concept

```bash
# Send 200 concurrent requests with distinct timestamps to force 200 simultaneous DB queries
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/network/supply?timestamp=lte:$((1700000000 + i * 1000000000))" &
done
wait

# Observe: DB CPU spikes, HikariCP active connections saturate,
# other endpoints (e.g., /api/v1/transactions) begin returning 503 or timing out.
```

Each request triggers `accountBalanceRepository.getSupplyHistory()` with a distinct `upperTimestamp`, scanning up to one month of `account_balance` rows per query, holding a DB connection for up to 10 seconds each.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L66-81)
```java
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/AccountBalanceRepository.java (L12-28)
```java
    @Query(value = """
    with account_balances as (
      select distinct on (ab.account_id) ab.balance, ab.consensus_timestamp
      from account_balance ab
      join unnest(
            cast(string_to_array(:lowerBounds, ',') as bigint[]),
            cast(string_to_array(:upperBounds, ',') as bigint[])
         ) as ranges(min_val, max_val)
      on ab.account_id between ranges.min_val and ranges.max_val
      where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp
      order by ab.account_id asc, ab.consensus_timestamp desc
    )
    select cast(coalesce(sum(balance), 0) as bigint) as unreleased_supply,
           coalesce(max(consensus_timestamp), 0) as consensus_timestamp
    from account_balances
    """, nativeQuery = true)
    NetworkSupply getSupplyHistory(String lowerBounds, String upperBounds, long lowerTimestamp, long upperTimestamp);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** docs/configuration.md (L629-629)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L82-84)
```yaml
            type: PathPrefix
            value: '/api/v1/network/'
        - path:
```
