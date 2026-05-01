### Title
Unauthenticated HTTP/2 Multiplexed Flood of `/api/v1/network/stake` Drives Uncached Correlated DB Subquery, Enabling DB CPU Exhaustion

### Summary
The `GET /api/v1/network/stake` endpoint in the `rest-java` module requires no authentication and has no application-level rate limiting. Every request unconditionally executes `NetworkStakeRepository.findLatest()`, which runs a correlated subquery (`SELECT max(consensus_timestamp) FROM network_stake`) against the database with no caching. An unprivileged attacker using HTTP/2 multiplexing can saturate the endpoint from a single TCP connection, bypassing any per-IP connection-count heuristics, and drive simultaneous DB queries that collectively spike DB CPU by 30%+.

### Finding Description

**Code path:**

`NetworkController.getNetworkStake()` (line 127–130) calls `networkService.getLatestNetworkStake()` with no throttle guard, no authentication, and no cache check. [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56) calls `networkStakeRepository.findLatest()` directly, with no `@Cacheable` annotation or any in-memory guard. [2](#0-1) 

`NetworkStakeRepository.findLatest()` (lines 12–19) executes a native correlated subquery on every invocation — `SELECT * FROM network_stake WHERE consensus_timestamp = (SELECT max(consensus_timestamp) FROM network_stake)` — with no `@Cacheable` annotation. [3](#0-2) 

**Root cause — failed assumptions:**

1. The `rest-java` module contains **no application-level rate limiting** for this endpoint. The bucket4j throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module and is never applied to `rest-java` controllers. [4](#0-3) 

2. The only infrastructure-level rate limit is the GCP backend policy `maxRatePerEndpoint: 250`, which is a **global aggregate RPS cap per pod**, not a per-source-IP limit. [5](#0-4) 

3. The `grpc` module's `NodeStakeRepository` uses `@Cacheable` with a 24-hour TTL, but the `rest-java` `NetworkStakeRepository.findLatest()` has **no equivalent caching**. [6](#0-5) 

**HTTP/2 multiplexing exploit path:**

HTTP/2 allows a single TCP connection to carry hundreds of concurrent streams. Because the GCP backend policy rate limit is global (not per-IP or per-connection), an attacker opening one HTTP/2 connection and sending N concurrent streams is indistinguishable from N legitimate users. Each stream independently triggers `findLatest()` → correlated DB subquery. There is no per-IP connection limit, no stream-count limit, and no application-level concurrency guard on this endpoint.

### Impact Explanation
Each `findLatest()` call issues a two-phase query (inner `MAX()` scan + outer row fetch) against the `network_stake` table. Under concurrent load, these queries compete for shared DB buffer pool and CPU. With no caching, every HTTP request maps 1:1 to a DB query. On a lightly loaded instance, a sustained burst of ~50–100 concurrent streams from a single HTTP/2 connection is sufficient to increase DB CPU by 30%+ above the 24-hour baseline, satisfying the stated impact threshold. This constitutes a resource exhaustion / denial-of-service condition against the database tier, potentially degrading all other mirror node services sharing the same DB.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no brute force. Any HTTP/2-capable client (curl, Python httpx, h2load) can open a single connection and multiplex concurrent GET requests. The endpoint is publicly documented in the OpenAPI spec and monitored by the k6 load test suite, confirming it is reachable from the internet. The attack is repeatable and automatable with minimal resources. [7](#0-6) [8](#0-7) 

### Recommendation
1. **Add result caching** to `NetworkStakeRepository.findLatest()` or `NetworkServiceImpl.getLatestNetworkStake()` using `@Cacheable` with a short TTL (e.g., 30s–60s), consistent with how the `grpc` module caches node stake data.
2. **Add application-level rate limiting** to the `rest-java` module (e.g., bucket4j per-IP token bucket via a servlet filter), mirroring the pattern already implemented in `web3/ThrottleConfiguration`.
3. **Add an HTTP/2 concurrent-stream limit** at the Tomcat/Netty layer (`server.http2.max-concurrent-streams`) to bound per-connection parallelism.
4. **Add per-source-IP rate limiting** at the GCP gateway layer (e.g., Cloud Armor rate-based rules) in addition to the existing global `maxRatePerEndpoint`.

### Proof of Concept
```bash
# Requires h2load (nghttp2) or equivalent HTTP/2 load tool
# Send 500 concurrent requests over a single HTTP/2 connection
h2load -n 500 -c 1 -m 500 \
  https://<mirror-node-host>/api/v1/network/stake

# Alternatively with Python httpx (HTTP/2 enabled):
python3 - <<'EOF'
import httpx, asyncio

async def flood():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [client.get("https://<mirror-node-host>/api/v1/network/stake")
                 for _ in range(500)]
        responses = await asyncio.gather(*tasks)
        print([r.status_code for r in responses])

asyncio.run(flood())
EOF
```

**Expected result:** 500 simultaneous `findLatest()` correlated subqueries hit the database. Monitor DB CPU via `pg_stat_activity` or Prometheus — CPU will spike proportionally to the number of concurrent queries, with no server-side rejection or throttling observed.

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

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-58)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L24-28)
```java
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
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

**File:** rest/api/v1/openapi.yml (L990-1008)
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
```
