I verified all code references and configuration claims against the actual repository. Here is my assessment:

**Verified facts:**
- `NetworkController.getSupply()` at lines 132–150 calls `networkService.getSupply(bound)` synchronously with no async wrapper. [1](#0-0) 
- `NetworkServiceImpl.getSupply()` at lines 66–67 calls `entityRepository.getSupply(lowerBounds, upperBounds)` as a blocking Spring Data JPA call when no timestamp is provided. [2](#0-1) 
- `EntityRepository.getSupply()` at lines 19–29 executes a native SQL `SUM`/`MAX` aggregation over the `entity` table. [3](#0-2) 
- The only servlet filter in rest-java is `MetricsFilter`, which only records byte counts and performs no rate limiting or request rejection. [4](#0-3) 
- A grep across all rest-java Java sources for `RateLimiter`, `Semaphore`, `throttle`, `rate.limit` returns only matches inside the fee-estimation service — none protecting the supply endpoint.
- The liveness probe has `timeoutSeconds: 2` and `periodSeconds: 10`. [5](#0-4) 
- The Traefik middleware circuit breaker is based on error ratios only, not concurrency. [6](#0-5) 
- `ThrottleConfiguration.java` exists only in the `web3` module, not in rest-java. 

---

Audit Report

## Title
Unauthenticated Thread Pool Exhaustion via Synchronous `getSupply()` on `/api/v1/network/supply`

## Summary
The `GET /api/v1/network/supply` endpoint in the rest-java module executes a blocking PostgreSQL aggregation query on the Tomcat worker thread with no application-level rate limiting, concurrency cap, or async offloading. An unauthenticated attacker sending enough concurrent requests can hold all Tomcat threads blocked for up to the 20-second statement timeout, starving health-check and all other endpoints of threads and causing Kubernetes to restart the pod via liveness probe failures.

## Finding Description

**Exact code path:**

`NetworkController.getSupply()` (lines 132–150) calls `networkService.getSupply(bound)` synchronously on the Tomcat worker thread with no async wrapper, semaphore, or circuit breaker protecting concurrency. [1](#0-0) 

`NetworkServiceImpl.getSupply()` (lines 66–67) calls `entityRepository.getSupply(lowerBounds, upperBounds)` — a blocking Spring Data JPA call — when no timestamp parameter is provided (the default case). [7](#0-6) 

`EntityRepository.getSupply()` (lines 19–29) executes a native SQL aggregation (`SUM`, `MAX`) over the `entity` table joined against a server-configured set of account ID ranges. The query runs entirely on the calling thread until PostgreSQL returns or the statement timeout fires. [3](#0-2) 

**Root cause — missing concurrency control in rest-java:**

The `web3` module has a full `ThrottleConfiguration` / `ThrottleManagerImpl` with per-second rate limiting via Bucket4j. The rest-java module has no equivalent. Its only servlet filter is `MetricsFilter`, which only records byte counts and does not limit or reject requests. [8](#0-7) 

A search across all rest-java Java sources for `RateLimiter`, `Semaphore`, `throttle`, or `rate.limit` returns only matches inside the fee-estimation service — none protecting the supply endpoint.

**Only existing bound — statement timeout:**

The PostgreSQL user `mirror_rest_java` has `statement_timeout = 20000` ms set at the DB level (documented default for `hiero.mirror.restJava.db.statementTimeout`). This means each blocked thread can be held for up to 20 seconds before the DB cancels the query. With Spring Boot/Tomcat's default of 200 worker threads, an attacker needs only ~200 concurrent in-flight requests to saturate the pool entirely for up to 20 seconds at a time.

**Traefik middleware does not protect against this:**

The Helm chart's Traefik middleware only configures a circuit breaker on error ratios and a retry policy — neither limits per-client concurrency nor rejects requests when the thread pool is saturated. [6](#0-5) 

## Impact Explanation

While the Tomcat thread pool is saturated, every incoming HTTP request — including Kubernetes liveness probes at `/actuator/health/liveness` — is queued and eventually times out. The liveness probe has a `timeoutSeconds: 2` timeout and fires every `periodSeconds: 10`. [5](#0-4) 

Repeated probe failures cause Kubernetes to restart the pod. During the attack and restart cycle, the mirror node REST Java API is completely unavailable. Because the mirror node is the canonical source of transaction visibility for clients, this constitutes a full denial-of-service against the mirror node's read path.

## Likelihood Explanation

- **Precondition**: None. The endpoint is public and unauthenticated.
- **Attacker capability**: Any client capable of opening ~200 persistent HTTP connections simultaneously. Trivially achievable with `ab`, `wrk`, `hey`, or a small script.
- **Repeatability**: Fully repeatable. After a pod restart, the attacker can immediately re-saturate the new pod.
- **No authentication, no IP-based throttle**: The Traefik circuit breaker only triggers on error ratios, not on per-client concurrency. The GCP gateway `maxRatePerEndpoint: 250` is a partial mitigation but is deployment-specific (requires `gateway.gcp.enabled: true`) and is not a substitute for application-level concurrency control. [9](#0-8) 

## Recommendation

1. **Add a concurrency semaphore or async offloading** to `NetworkServiceImpl.getSupply()` to cap the number of simultaneous in-flight DB queries (e.g., using a `Semaphore` with a configurable permit count, or by executing the query on a bounded virtual-thread executor).
2. **Implement application-level rate limiting** in rest-java equivalent to the `ThrottleConfiguration` already present in the `web3` module, using Bucket4j or Spring's `RateLimiter` support, applied at the filter or controller level.
3. **Reduce the statement timeout** for the supply query or add a query-level timeout via `@QueryHints` to reduce the maximum thread hold time.
4. **Add a Tomcat connection queue limit** (`server.tomcat.accept-count`) and configure a request timeout (`server.tomcat.connection-timeout`) so that queued requests fail fast rather than holding threads indefinitely.
5. **Enable the GCP gateway `maxRatePerEndpoint`** as a defense-in-depth measure for GCP deployments, and add equivalent rate limiting at the Traefik ingress layer for non-GCP deployments.

## Proof of Concept

```bash
# Saturate the Tomcat thread pool with 200 concurrent requests
# (adjust -c to match the configured thread pool size)
wrk -t 20 -c 200 -d 60s \
  "https://<mirror-node-host>/api/v1/network/supply"

# In a separate terminal, observe liveness probe failures:
kubectl logs -n <namespace> <pod-name> | grep -i "liveness"

# Or watch pod restarts:
kubectl get pods -n <namespace> -w
```

With 200 concurrent connections each triggering the blocking `EntityRepository.getSupply()` aggregation, all Tomcat worker threads become occupied. The `/actuator/health/liveness` endpoint cannot be served within its 2-second timeout, causing Kubernetes to register probe failures and eventually restart the pod. The attack is immediately repeatable against the restarted pod.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L27-58)
```java
class MetricsFilter extends OncePerRequestFilter {

    static final String REQUEST_BYTES = "hiero.mirror.restjava.request.bytes";
    static final String RESPONSE_BYTES = "hiero.mirror.restjava.response.bytes";

    private static final String METHOD = "method";
    private static final String URI = "uri";

    private final MeterProvider<DistributionSummary> requestBytesProvider;
    private final MeterProvider<DistributionSummary> responseBytesProvider;

    MetricsFilter(MeterRegistry meterRegistry) {
        this.requestBytesProvider = DistributionSummary.builder(REQUEST_BYTES)
                .baseUnit("bytes")
                .description("The size of the request in bytes")
                .withRegistry(meterRegistry);
        this.responseBytesProvider = DistributionSummary.builder(RESPONSE_BYTES)
                .baseUnit("bytes")
                .description("The size of the response in bytes")
                .withRegistry(meterRegistry);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L49-60)
```yaml
gateway:
  gcp:
    backendPolicy:
      connectionDraining:
        drainingTimeoutSec: 10
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
    enabled: true
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L150-156)
```yaml
livenessProbe:
  httpGet:
    path: /actuator/health/liveness
    port: http
  initialDelaySeconds: 0
  periodSeconds: 10
  timeoutSeconds: 2
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L158-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```
