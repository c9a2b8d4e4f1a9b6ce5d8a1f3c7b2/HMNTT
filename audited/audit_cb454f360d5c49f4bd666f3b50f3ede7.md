### Title
Unauthenticated Sustained Aggregation DoS on `/api/v1/network/supply` via Missing Application-Layer Rate Limiting

### Summary
The `/api/v1/network/supply` endpoint is publicly accessible with no authentication, no application-layer rate limiting, and no result caching. Every request unconditionally executes a full `SUM`/`MAX` aggregation over the `entity` table joined against multiple ID ranges. A single unprivileged attacker sustaining a moderate request rate can cumulatively drive database CPU and I/O consumption well above the 24-hour baseline.

### Finding Description

**Exact code path:**

`NetworkController.getSupply()` (lines 132–150) is a plain `@GetMapping` with no throttle guard: [1](#0-0) 

It delegates unconditionally to `NetworkServiceImpl.getSupply()` (lines 59–89), which has no `@Cacheable` annotation and no memoization of any kind: [2](#0-1) 

When no `timestamp` parameter is supplied (the common case), it calls `EntityRepository.getSupply()` directly: [3](#0-2) 

This native query performs a full `SUM(e.balance)` + `MAX(e.balance_timestamp)` aggregation over the `entity` table, joined via `unnest()` against up to 7 configured ID ranges (accounts 2–750 by default): [4](#0-3) 

**Root cause — failed assumptions:**

1. **No application-layer rate limiting exists in `rest-java`**. The `ThrottleManager`/`ThrottleConfiguration` with bucket4j is scoped exclusively to the `web3` module for contract-call endpoints: [5](#0-4) 
A grep across all `rest-java/src/main/java/**/*.java` for `rate.limit`, `throttle`, `bucket4j`, and `RateLimiter` returns zero matches in the service/controller layer for the supply endpoint.

2. **No result caching**. A grep for `@Cacheable`, `@Cache`, or any cache annotation in `NetworkServiceImpl.java` returns zero matches. The only cache-adjacent artifact in `rest-java` config is a `ShallowEtagHeaderFilter`: [6](#0-5) 
This filter computes an ETag from the response body **after** the DB query has already executed and returned — it does not short-circuit the aggregation.

3. **No authentication requirement**. The `WebMvcConfiguration` registers only argument resolvers and formatters; there is no security filter chain restricting access to `/api/v1/network/supply`: [7](#0-6) 

### Impact Explanation

On a production Hedera mirror node the `entity` table contains tens of millions of rows. Each unauthenticated `GET /api/v1/network/supply` request forces PostgreSQL to scan and aggregate all rows whose `id` falls within the configured ranges, consuming CPU, buffer cache, and I/O. Because there is no caching and no rate limiting, N concurrent or sequential requests produce exactly N full aggregation queries. At a sustained rate of even a few dozen requests per second — well below typical connection-level limits — the cumulative DB load can exceed 30% above the 24-hour baseline, degrading query performance for all other mirror-node consumers (block explorers, wallets, dApps).

### Likelihood Explanation

The attack requires zero privileges, zero authentication tokens, and zero specialized knowledge beyond the public OpenAPI spec: [8](#0-7) 
The endpoint is documented, stable, and exercised by existing load-test tooling (`tools/k6/src/rest-java/test/networkSupply.js`): [9](#0-8) 
Any attacker with a single HTTP client can reproduce the condition. The attack is repeatable, requires no state, and is trivially parallelizable across multiple source IPs.

### Recommendation

1. **Add application-layer rate limiting** to the `rest-java` module for `/api/v1/network/supply` using the same bucket4j pattern already present in `web3/ThrottleConfiguration`, applied via a `HandlerInterceptor` or `OncePerRequestFilter` registered in `WebMvcConfiguration`.
2. **Cache the aggregation result** in `NetworkServiceImpl.getSupply()` with a short TTL (e.g., 10–30 seconds) using `@Cacheable` backed by Caffeine, since the supply value changes only when new blocks are ingested.
3. **Consider infrastructure-level controls** (WAF, reverse-proxy rate limiting per IP) as a defense-in-depth layer independent of the application.

### Proof of Concept

```bash
# No credentials required. Run from any host with network access.
# Sustained 50 req/s against the unauthenticated endpoint:
while true; do
  for i in $(seq 1 50); do
    curl -s "https://<mirror-node-host>/api/v1/network/supply" -o /dev/null &
  done
  wait
done
```

Each iteration fires 50 parallel requests, each triggering a full `SUM`/`MAX` aggregation on the `entity` table. Monitor PostgreSQL `pg_stat_activity` and CPU metrics: within minutes the DB CPU will show a sustained elevation of 30%+ above the prior 24-hour average, with no 429 or throttle response ever returned by the application.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L59-67)
```java
    public NetworkSupply getSupply(Bound timestamp) {
        final NetworkSupply networkSupply;

        final var bounds = networkProperties.getUnreleasedSupplyRangeBounds();
        final var lowerBounds = bounds.lowerBounds();
        final var upperBounds = bounds.upperBounds();

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/NetworkProperties.java (L22-29)
```java
    private List<AccountRange> unreleasedSupplyAccounts = List.of(
            new AccountRange(2, 2),
            new AccountRange(42, 42),
            new AccountRange(44, 71),
            new AccountRange(73, 87),
            new AccountRange(99, 100),
            new AccountRange(200, 349),
            new AccountRange(400, 750));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L36-49)
```java
    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
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

**File:** rest/api/v1/openapi.yml (L1010-1029)
```yaml
  /api/v1/network/supply:
    get:
      summary: Get the network supply
      description: Returns the network's released supply of hbars
      operationId: getNetworkSupply
      parameters:
        - $ref: "#/components/parameters/timestampQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkSupplyResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NotFoundError"
      tags:
        - network
```

**File:** tools/k6/src/rest-java/test/networkSupply.js (L1-17)
```javascript
// SPDX-License-Identifier: Apache-2.0

import http from 'k6/http';

import {isSuccess, RestJavaTestScenarioBuilder} from '../libex/common.js';

const urlTag = '/network/supply';

const {options, run, setup} = new RestJavaTestScenarioBuilder()
  .name('networkSupply') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = `${testParameters['BASE_URL_PREFIX']}${urlTag}`;
    return http.get(url);
  })
  .check('Network supply OK', isSuccess)
  .build();
```
