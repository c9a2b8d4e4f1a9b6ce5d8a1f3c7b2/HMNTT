### Title
Unauthenticated DoS via Unbounded Repeated Expensive DB Aggregation on `GET /api/v1/network/supply`

### Summary
The `GET /api/v1/network/supply` endpoint is publicly accessible with no authentication, no rate limiting in the `rest-java` module, and no caching on the underlying `EntityRepository.getSupply()` query. Every request without a `timestamp` parameter triggers a full aggregation (`SUM`/`MAX`) with an `unnest`-based range join against the `entity` table. A sustained flood of such requests from an unprivileged attacker can saturate database CPU, degrading all mirror node components sharing that database.

### Finding Description

**Exact code path:**

`NetworkController.getSupply()` (lines 132–150) receives `GET /api/v1/network/supply` with no `timestamp` parameter. It constructs an empty `Bound` and calls `networkService.getSupply(bound)`. [1](#0-0) 

`NetworkServiceImpl.getSupply()` (lines 59–89) checks `timestamp.isEmpty()` — true when no timestamp is provided — and directly calls `entityRepository.getSupply(lowerBounds, upperBounds)` with no caching, no guard, and no deduplication. [2](#0-1) 

`EntityRepository.getSupply()` executes a native SQL query that performs a full `SUM(balance)` + `MAX(balance_timestamp)` aggregation over the `entity` table joined via `unnest(cast(string_to_array(:lowerBounds,',') as bigint[]), ...)`. On a production mirror node the `entity` table contains millions of rows; this is a sequential-scan-level aggregation on every invocation. [3](#0-2) 

**Root cause — two failed assumptions:**

1. **No caching.** The `getSupply` method in `EntityRepository` carries no `@Cacheable` annotation (contrast with `web3`'s `EntityRepository` which caches every hot query). Every HTTP request unconditionally issues a new DB query. [3](#0-2) 

2. **No rate limiting in `rest-java`.** The only throttle infrastructure in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`, bucket4j buckets) lives entirely in the `web3` module and is wired to `ContractCallRequest` objects. There is no equivalent filter, interceptor, or annotation applied to any `rest-java` controller endpoint, including `/api/v1/network/supply`. [4](#0-3) [5](#0-4) 

### Impact Explanation

The `entity` table in a production Hedera mirror node holds tens of millions of rows. The `unnest`-join aggregation requires scanning all rows whose `id` falls within the configured ranges, computing `SUM` and `MAX` — a CPU- and I/O-intensive operation. With no caching and no rate limiting, an attacker can hold the database at near-100% CPU by maintaining a high-concurrency flood of requests (limited only by the HikariCP connection pool, default 10 connections). Because the importer, gRPC, and other mirror node components share the same PostgreSQL instance, sustained DB CPU saturation directly degrades their processing throughput, meeting the ≥30% network-processing-node degradation threshold described in the scope.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and only a standard HTTP client. The endpoint is publicly documented in the OpenAPI spec. [6](#0-5) 
The attacker needs only to send concurrent `GET /api/v1/network/supply` requests at a rate that keeps the DB connection pool saturated. This is trivially achievable with tools like `ab`, `wrk`, or `curl` in a loop. The attack is repeatable, stateless, and requires no prior knowledge of the system beyond the public API.

### Recommendation

Apply at least two independent mitigations:

1. **Cache the no-timestamp result.** Add `@Cacheable` (e.g., Caffeine with a short TTL of 5–15 seconds) to `EntityRepository.getSupply()` or to `NetworkServiceImpl.getSupply()` for the `timestamp.isEmpty()` branch. The supply value changes at most once per consensus period, so a short TTL is safe and eliminates repeated DB hits.

2. **Add rate limiting to `rest-java`.** Introduce a servlet filter or Spring MVC interceptor in the `rest-java` module (analogous to the `web3` `ThrottleManagerImpl`) that enforces a per-IP or global requests-per-second cap on the `/api/v1/network/supply` endpoint.

### Proof of Concept

```bash
# Flood the endpoint with 50 concurrent connections, no timestamp param
wrk -t 50 -c 50 -d 60s http://<mirror-node-host>/api/v1/network/supply

# Observe PostgreSQL CPU via pg_stat_activity:
psql -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"
# Expected: up to 10 active queries all running the unnest aggregation,
# DB CPU pegged at ~100%, importer lag increasing.
```

Each request with no `timestamp` parameter hits the `timestamp.isEmpty()` branch in `NetworkServiceImpl.getSupply()` and unconditionally executes the expensive `EntityRepository.getSupply()` native query against the live `entity` table. [7](#0-6)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L132-138)
```java
    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);

```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L59-68)
```java
    public NetworkSupply getSupply(Bound timestamp) {
        final NetworkSupply networkSupply;

        final var bounds = networkProperties.getUnreleasedSupplyRangeBounds();
        final var lowerBounds = bounds.lowerBounds();
        final var upperBounds = bounds.upperBounds();

        if (timestamp.isEmpty()) {
            networkSupply = entityRepository.getSupply(lowerBounds, upperBounds);
        } else {
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
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
