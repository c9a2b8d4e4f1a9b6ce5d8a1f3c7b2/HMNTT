### Title
Unauthenticated DoS via Unbounded Repeated Expensive DB Queries on `GET /api/v1/network/supply`

### Summary
The `GET /api/v1/network/supply` endpoint in the rest-java module requires no authentication and has no application-level rate limiting or response caching. When called without a `timestamp` parameter, every request triggers `EntityRepository.getSupply()`, which executes a costly native SQL query performing a full `unnest`/`JOIN` aggregate scan over the `entity` table. A sustained flood of such requests from any unprivileged external user saturates database CPU, degrading all mirror node components sharing the same PostgreSQL instance.

### Finding Description

**Exact code path:**

1. `NetworkController.getSupply()` — no auth, no rate-limit guard: [1](#0-0) 

2. When `timestamp` is absent, `NetworkServiceImpl.getSupply()` calls directly into the repository with no caching: [2](#0-1) 

3. `EntityRepository.getSupply()` executes a native SQL aggregate scan with `unnest` join against the full `entity` table on every call — no `@Cacheable` annotation: [3](#0-2) 

**Root cause:** The rest-java module has no rate-limiting infrastructure for this endpoint. The `ThrottleManager`/`ThrottleConfiguration` (bucket4j) exists exclusively in the `web3` module and is scoped to `ContractCallRequest` objects: [4](#0-3) 

The documented rest-java configuration properties contain no rate-limiting option: [5](#0-4) 

The only DB-side protection is a `statementTimeout` of 10,000 ms, which limits individual query duration but does not bound concurrency: [6](#0-5) 

**Failed assumption:** The design assumes an external gateway (e.g., ingress/load balancer) will rate-limit this endpoint. No such control is enforced in the application layer, and the endpoint is publicly documented and reachable without credentials.

### Impact Explanation

The `entity` table on mainnet contains millions of rows. Each no-timestamp request causes PostgreSQL to perform a full aggregate scan joined against a multi-element unnested array (7 account ranges by default). Flooding this endpoint with concurrent requests saturates database CPU. Because the mirror node importer, other REST endpoints, and the web3 API all share the same PostgreSQL instance, a saturated database degrades all of them simultaneously — meeting the ≥30% processing node degradation threshold. The `statementTimeout=10s` means each attacking connection holds a DB worker for up to 10 seconds, amplifying the effect.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and a single HTTP client capable of sending concurrent GET requests. The endpoint is publicly documented in the OpenAPI spec: [7](#0-6) 

It is also exercised by k6 load tests without any auth headers, confirming it is reachable from the public internet: [8](#0-7) 

Any attacker with a basic script (e.g., `ab`, `wrk`, or a simple loop with `curl`) can reproduce this.

### Recommendation

1. **Add application-level rate limiting** to the rest-java module for the `/api/v1/network/supply` endpoint (port the existing bucket4j pattern from the web3 module, or use Spring's `HandlerInterceptor`).
2. **Cache the no-timestamp supply result** with a short TTL (e.g., 5–15 seconds) using `@Cacheable` on `EntityRepository.getSupply()` or `NetworkServiceImpl.getSupply()`, since the result changes only when new balance snapshots are ingested.
3. **Limit DB connection pool concurrency** for the rest-java datasource to bound the maximum number of simultaneous expensive queries.
4. **Deploy an ingress-level rate limiter** (e.g., nginx `limit_req`, Envoy rate-limit filter) as a defense-in-depth measure.

### Proof of Concept

```bash
# Send 200 concurrent requests with no timestamp parameter
# Requires no credentials or special access
seq 200 | xargs -P 200 -I{} \
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/network/supply"
```

**Expected result:** PostgreSQL CPU spikes to 100%; mirror node importer lag increases; other REST and web3 endpoints begin timing out or returning 503 errors within seconds of sustained flooding.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
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
```

**File:** docs/configuration.md (L623-637)
```markdown
| Name                                                     | Default                                            | Description                                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.restJava.db.host`                          | 127.0.0.1                                          | The IP or hostname used to connect to the database                                                                                                            |
| `hiero.mirror.restJava.db.name`                          | mirror_node                                        | The name of the database                                                                                                                                      |
| `hiero.mirror.restJava.db.password`                      | mirror_rest_java_pass                              | The database password used to connect to the database                                                                                                         |
| `hiero.mirror.restJava.db.port`                          | 5432                                               | The port used to connect to the database                                                                                                                      |
| `hiero.mirror.restJava.db.sslMode`                       | DISABLE                                            | The SSL level. Accepts either DISABLE, ALLOW, PREFER, REQUIRE, VERIFY_CA or VERIFY_FULL.                                                                      |
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
| `hiero.mirror.restJava.db.username`                      | mirror_rest_java                                   | The username used to connect to the database                                                                                                                  |
| `hiero.mirror.restJava.fee.refreshInterval`              | 10m                                                | How often to check for fee schedule updates from the database. Can accept duration units like `10s`, `2m` etc.                                                |
| `hiero.mirror.restJava.network.unreleasedSupplyAccounts` | 2-2, 42-42, 44-71, 73-87, 99-100, 200-349, 400-750 | Account ranges holding unreleased HBAR supply, excluded from circulating supply calculations                                                                  |
| `hiero.mirror.restJava.query.maxFileAttempts`            | 12                                                 | The maximum amount of times to query for Hedera files when the contents are not valid.                                                                        |
| `hiero.mirror.restJava.response.headers.defaults`        | See application.yml                                | The default headers to add to every response. For each header, specify its `name: value`                                                                      |
| `hiero.mirror.restJava.response.headers.path`            | See application.yml                                | Override default or add headers per path to add to every response. The key is the controller request mapping, then for each header, specify its `name: value` |

```

**File:** rest/api/v1/openapi.yml (L1010-1028)
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
```

**File:** tools/k6/src/rest-java/test/networkSupply.js (L9-16)
```javascript
const {options, run, setup} = new RestJavaTestScenarioBuilder()
  .name('networkSupply') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = `${testParameters['BASE_URL_PREFIX']}${urlTag}`;
    return http.get(url);
  })
  .check('Network supply OK', isSuccess)
```
