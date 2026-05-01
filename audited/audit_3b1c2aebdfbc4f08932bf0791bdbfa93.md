### Title
Unauthenticated, Uncached `/api/v1/network/stake` Endpoint Lacks Rate Limiting, Enabling DoS via DB Connection Pool Exhaustion

### Summary
The `GET /api/v1/network/stake` endpoint in the `rest-java` module is publicly accessible with no authentication, no rate limiting, and no response caching. Every request triggers a correlated subquery directly against the `network_stake` table. An unprivileged attacker can flood this endpoint to exhaust the database connection pool, starving legitimate node operators of the staking state data they need to authorize transactions.

### Finding Description
**Code path:**

`NetworkController.java` line 126–130 handles the endpoint: [1](#0-0) 

It delegates unconditionally to `NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56): [2](#0-1) 

Which calls `NetworkStakeRepository.findLatest()`, executing a correlated subquery on every invocation with no caching: [3](#0-2) 

**Root cause:** The `rest-java` module has no rate-limiting infrastructure. The only registered filters are `LoggingFilter` and `MetricsFilter`:


The throttle/bucket4j infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module and is not applied to `rest-java` endpoints: [4](#0-3) 

There is no `@Cacheable` annotation on `getLatestNetworkStake()` or `findLatest()`, and the `hiero.mirror.restJava` configuration table documents no rate-limiting or caching properties for this endpoint: [5](#0-4) 

**Exploit flow:**
1. Attacker sends a high-volume flood of `GET /api/v1/network/stake` requests (no credentials required).
2. Each request acquires a DB connection and executes `SELECT * FROM network_stake WHERE consensus_timestamp = (SELECT max(consensus_timestamp) FROM network_stake)`.
3. The Spring Boot HikariCP pool (default 10 connections; `statementTimeout` 10 000 ms) becomes saturated.
4. Legitimate requests queue and time out; the endpoint returns errors or hangs.

**Why existing checks fail:** `LoggingFilter` only logs; `MetricsFilter` only records byte counts. Neither rejects or throttles requests. The `ShallowEtagHeaderFilter` registered in `RestJavaConfiguration` only adds ETag headers and does not cache responses server-side. [6](#0-5) 

### Impact Explanation
Node operators polling `/api/v1/network/stake` to read staking parameters (reward rates, stake totals, staking periods) needed before authorizing `NodeStakeUpdate`-dependent transactions are denied service. DB connection pool exhaustion can cascade to other `rest-java` endpoints sharing the same pool, broadening the impact beyond just the stake endpoint.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and no special knowledge beyond the public OpenAPI spec which documents the endpoint: [7](#0-6) 

A single attacker with a modest HTTP flood tool (e.g., `wrk`, `ab`) can sustain enough concurrent requests to saturate a 10-connection pool. The attack is trivially repeatable and requires no state.

### Recommendation
1. **Add response caching** at the service or repository layer (e.g., Spring `@Cacheable` with a short TTL such as 60 s) since staking data changes at most once per day.
2. **Add rate limiting** to the `rest-java` module mirroring the `web3` bucket4j pattern (`ThrottleConfiguration`), applied via a servlet filter or Spring interceptor on `/api/v1/network/**`.
3. **Configure an explicit, bounded HikariCP pool** for `rest-java` with a short `connectionTimeout` so pool exhaustion fails fast rather than queuing indefinitely.

### Proof of Concept
```bash
# Flood the endpoint with 200 concurrent connections for 30 seconds
wrk -t8 -c200 -d30s http://<mirror-node-host>:<port>/api/v1/network/stake

# Observe: legitimate requests begin timing out or returning 500
curl -v http://<mirror-node-host>:<port>/api/v1/network/stake
# Expected during attack: connection hang or HTTP 500 due to DB pool exhaustion
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L52-56)
```java
    public NetworkStake getLatestNetworkStake() {
        return networkStakeRepository
                .findLatest()
                .orElseThrow(() -> new EntityNotFoundException("No network stake data found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkStakeRepository.java (L12-19)
```java
    @Query(value = """
        select *
        from network_stake
        where consensus_timestamp = (
            select max(consensus_timestamp) from network_stake
        )
        """, nativeQuery = true)
    Optional<NetworkStake> findLatest();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-20)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest/api/v1/openapi.yml (L991-1009)
```yaml
    get:
      summary: Get network stake information
      description: Returns the network's current stake information.
      operationId: getNetworkStake
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkStakeResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NetworkStakeNotFound"
        500:
          $ref: "#/components/responses/ServiceUnavailableError"
      tags:
        - network
```
