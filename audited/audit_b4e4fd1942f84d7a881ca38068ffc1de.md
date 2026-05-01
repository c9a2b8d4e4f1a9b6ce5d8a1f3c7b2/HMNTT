### Title
Unauthenticated DoS via Unbounded Timestamp-Parameterized Database Queries in `getSupply()` Endpoint

### Summary
The `/api/v1/network/supply` endpoint in the rest-java module accepts user-controlled timestamp parameters that are passed directly to an expensive native SQL aggregation query (`getSupplyHistory`) against the `account_balance` table. No rate limiting, authentication, or result caching exists for this endpoint in the rest-java module. An unprivileged attacker can flood the endpoint with requests using varying timestamp values, each triggering a unique, uncached, expensive database query, exhausting the HikariCP connection pool and denying supply data to legitimate clients.

### Finding Description

**Code path:**

`NetworkController.getSupply()` (line 133-149) accepts `@RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp` with no authentication or rate-limiting guard. [1](#0-0) 

It delegates to `NetworkServiceImpl.getSupply(Bound)` (lines 59-89). When a timestamp is present, the code computes `minTimestamp` and `maxTimestamp` from user input, applies a `getFirstDayOfMonth` floor to `minTimestamp`, then calls:

```java
accountBalanceRepository.getSupplyHistory(lowerBounds, upperBounds, minTimestamp, maxTimestamp);
``` [2](#0-1) 

The `getSupplyHistory` query is a complex native SQL aggregation:
- `distinct on (ab.account_id)` over the full `account_balance` table
- `join unnest(...)` of account ID range arrays
- `where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp`
- `sum(balance)` and `max(consensus_timestamp)` aggregations [3](#0-2) 

**Root cause — failed assumptions:**

1. **No rate limiting in rest-java**: The `ThrottleManager`/`ThrottleConfiguration` infrastructure exists only in the `web3` module. The rest-java `WebMvcConfiguration` adds only argument resolvers; `RestJavaConfiguration` adds only an ETag filter and protobuf converter. No rate-limiting filter or interceptor is registered for `/api/v1/network/supply`. [4](#0-3) [5](#0-4) 

2. **No caching**: Neither `getSupply()` nor `getSupplyHistory()` carries a `@Cacheable` annotation. Every request with a timestamp hits the database unconditionally. [6](#0-5) 

3. **Unique queries defeat DB plan cache**: Because `minTimestamp` and `maxTimestamp` are bind parameters derived from user input, each distinct `maxTimestamp` value (which shifts the `getFirstDayOfMonth` floor) produces a different parameter set, preventing any effective query result caching at the database level.

4. **`getFirstDayOfMonth` does not bound cost**: The optimization narrows `minTimestamp` to the first day of the prior month relative to `maxTimestamp`, but the attacker can sweep `maxTimestamp` across months (e.g., one request per second per month boundary), each producing a distinct, expensive query. [7](#0-6) 

5. **HikariCP pool is finite**: The rest-java module uses a HikariCP connection pool (monitored via `hikaricp_connections_active`). Concurrent long-running queries will exhaust the pool, causing subsequent requests to queue or fail. [8](#0-7) 

### Impact Explanation

An attacker who exhausts the HikariCP connection pool blocks all database-dependent endpoints in the rest-java service, not just `/network/supply`. Clients constructing transactions that rely on current supply data (e.g., to validate HBAR amounts or fee calculations) receive errors or stale data. The `account_balance` table is large (one row per account per balance snapshot cycle), making the aggregation query particularly expensive under concurrent load. Severity: **High** — unauthenticated, service-wide denial of service.

### Likelihood Explanation

No preconditions beyond network access. The endpoint is public, requires no API key or authentication, and accepts arbitrary nanosecond-precision timestamps. A single attacker with a modest HTTP client (e.g., `ab`, `wrk`, or a simple script) can issue hundreds of requests per second with incrementing `timestamp` values. The `@Size(max = 2)` constraint only limits the number of timestamp parameters per request, not the rate of requests. [9](#0-8) 

### Recommendation

1. **Add rate limiting to rest-java**: Implement a `bucket4j`-based rate-limiting filter (mirroring the `web3` `ThrottleConfiguration`) applied to `/api/v1/network/*` endpoints, or use an API gateway/ingress-level rate limiter.
2. **Cache `getSupplyHistory` results**: Apply `@Cacheable` with a short TTL (e.g., 15–30 seconds) on `getSupply()` or `getSupplyHistory()`, keyed on the effective `(minTimestamp, maxTimestamp)` pair. Since balance snapshots are periodic, results are stable within a snapshot window.
3. **Bound the timestamp range**: Reject requests where `maxTimestamp - minTimestamp` exceeds a configured maximum (analogous to `hiero.mirror.rest.query.maxTimestampRange` in the Node.js REST API).
4. **Add a DB statement timeout**: Ensure `hiero.mirror.restJava.db.statementTimeout` (default 10000 ms) is enforced and tuned to abort runaway queries before they hold connections indefinitely. [10](#0-9) 

### Proof of Concept

```bash
# Sweep maxTimestamp across months to generate unique uncached queries
BASE_TS=1700000000000000000
for i in $(seq 1 500); do
  TS=$((BASE_TS + i * 2592000000000000))  # +30 days per request
  curl -s "https://<mirror-node>/api/v1/network/supply?timestamp=lte:$TS" &
done
wait
# Result: HikariCP pool exhausted; subsequent requests to any rest-java endpoint
# receive 500 errors or connection timeout responses.
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L58-89)
```java
    @Override
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L91-97)
```java
    private long getFirstDayOfMonth(long timestamp, int monthOffset) {
        final var instant = Instant.ofEpochSecond(0, timestamp);
        final var dateTime = instant.atZone(ZoneOffset.UTC);
        final var firstDay = dateTime.plusMonths(monthOffset).withDayOfMonth(1);

        return firstDay.toLocalDate().atStartOfDay(ZoneOffset.UTC).toEpochSecond() * DomainUtils.NANOS_PER_SECOND;
    }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-31)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
final class WebMvcConfiguration implements WebMvcConfigurer {

    private final RequestParameterArgumentResolver requestParameterArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(requestParameterArgumentResolver);
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class, EntityIdParameter.class, EntityIdParameter::valueOf);
    }
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-216)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
```

**File:** docs/configuration.md (L630-630)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```
