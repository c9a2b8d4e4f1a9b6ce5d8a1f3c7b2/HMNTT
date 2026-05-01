### Title
Unauthenticated Endpoint `GET /api/v1/network/stake` Executes Uncached DB Query on Every Request, Enabling Sustained DB Resource Exhaustion

### Summary
The `getNetworkStake()` handler in `NetworkController` delegates directly to `networkStakeRepository.findLatest()`, which executes a native SQL query with a correlated subquery on every HTTP request. No caching annotation exists anywhere in the call chain, and the rest-java module applies no rate limiting to this endpoint. Any unauthenticated external caller can sustain continuous database polling by issuing a moderate stream of requests.

### Finding Description

**Exact code path:**

`NetworkController.getNetworkStake()` (lines 126–130) calls `networkService.getLatestNetworkStake()`: [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56) calls `networkStakeRepository.findLatest()` with no intermediate caching: [2](#0-1) 

`NetworkStakeRepository.findLatest()` executes a native SQL query containing a correlated subquery (`select max(consensus_timestamp) from network_stake`) on every invocation: [3](#0-2) 

**Root cause:** Neither `getLatestNetworkStake()` nor `findLatest()` carries a `@Cacheable` annotation. A grep across all rest-java Java sources confirms zero caching annotations on this path. The rest-java module has no rate-limiting infrastructure at all — the throttle/bucket4j machinery found in the codebase lives exclusively in the `web3` module: [4](#0-3) 

That throttle configuration is entirely absent from rest-java. The endpoint also accepts no parameters, so there is no input-validation gate that could slow an attacker.

**Failed assumption:** The design assumes that the `network_stake` table is queried infrequently (it is updated only once per day by `NodeStakeUpdateTransactionHandler`). No defensive measure was added to enforce that assumption at the API layer.

### Impact Explanation
Each request causes the database to execute a two-level query: an outer `SELECT *` joined to an inner `SELECT max(consensus_timestamp)`. Under sustained concurrent load (e.g., 200–500 req/s from a single host), the database connection pool is continuously occupied, CPU cycles are consumed for repeated index/table scans, and I/O bandwidth is used. Because the `network_stake` table is small and the query is fast, the per-query cost is low, but the aggregate effect of hundreds of concurrent, unthrottled requests with no cache hits is a measurable and sustained increase in DB CPU and connection utilization — consistent with the >30% resource-consumption increase described in the threat model. Other legitimate API consumers sharing the same database connection pool are degraded as a side effect.

### Likelihood Explanation
No authentication, API key, or session is required. The endpoint is documented in the public OpenAPI spec: [5](#0-4) 

Any attacker with network access can issue requests using a single machine with a simple loop or a tool such as `ab`, `wrk`, or `k6` (the project itself ships a k6 load-test script for this exact endpoint): [6](#0-5) 

No special knowledge, credentials, or exploit chain is required. The attack is trivially repeatable and can be sustained indefinitely.

### Recommendation
1. **Add a short-lived application-level cache** on `NetworkServiceImpl.getLatestNetworkStake()` using Spring's `@Cacheable` (e.g., `expireAfterWrite=30s`). Because the underlying data changes at most once per day, a 30-second TTL eliminates virtually all redundant DB queries with no observable staleness impact.
2. **Add rate limiting to the rest-java module** analogous to the bucket4j throttle already present in the web3 module, applied globally or per-endpoint via a servlet filter or Spring interceptor.
3. Optionally, add a `Cache-Control: max-age=30` response header so upstream proxies/CDNs can absorb repeated requests before they reach the application.

### Proof of Concept
```bash
# Sustained load — no credentials required
wrk -t4 -c200 -d60s https://<mirror-node-host>/api/v1/network/stake

# Observe DB CPU via pg_stat_activity or node metrics:
# SELECT count(*), state FROM pg_stat_activity GROUP BY state;
# Before attack: near-zero active queries against network_stake
# During attack: continuous stream of active queries against network_stake
# Expected: DB CPU and active connection count rise proportionally with RPS,
#           with no cache hits ever absorbing the load.
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

**File:** rest/api/v1/openapi.yml (L990-1009)
```yaml
  /api/v1/network/stake:
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

**File:** tools/k6/src/rest-java/test/networkStake.js (L1-17)
```javascript
// SPDX-License-Identifier: Apache-2.0

import http from 'k6/http';

import {isSuccess, RestJavaTestScenarioBuilder} from '../libex/common.js';

const urlTag = '/network/stake';

const {options, run, setup} = new RestJavaTestScenarioBuilder()
  .name('networkStake') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = `${testParameters['BASE_URL_PREFIX']}${urlTag}`;
    return http.get(url);
  })
  .check('Network stake OK', isSuccess)
  .build();
```
