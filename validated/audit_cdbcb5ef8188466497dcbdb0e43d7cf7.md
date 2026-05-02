All referenced code paths have been verified against the repository. Here is the result:

---

Audit Report

## Title
Unauthenticated `GET /api/v1/network/registered-nodes` Lacks Application-Level Rate Limiting, Enabling DB Connection Pool Exhaustion DoS

## Summary
The `GET /api/v1/network/registered-nodes` endpoint in the `rest-java` module is publicly accessible with no authentication and no application-level rate limiting. Every request unconditionally issues a native SQL query against the database, consuming a HikariCP connection for the query's duration. A high-volume flood of concurrent requests can exhaust the connection pool, causing all subsequent requests to queue and time out, affecting all endpoints sharing the same `DataSource`.

## Finding Description

**Verified code path:**

`NetworkController.getRegisteredNodes()` at line 174 calls `networkService.getRegisteredNodes(request)`: [1](#0-0) 

`NetworkServiceImpl.getRegisteredNodes()` at line 150 unconditionally calls `registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()`: [2](#0-1) 

The native SQL query issued per request: [3](#0-2) 

**No application-level rate limiting in `rest-java`:**

A search across all `rest-java/src/**/*.java` files returns zero matches for any rate-limiting, throttle filter, or interceptor. The only throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) is confined to the `web3` module: [4](#0-3) [5](#0-4) 

No `WebSecurityConfig.java` exists anywhere in the codebase. No servlet filter or interceptor applies per-IP or global rate limiting to `NetworkController`.

**Input validation bounds result size, not request rate:**

`RegisteredNodesRequest` caps `limit` at `MAX_LIMIT = 100` and `registeredNodeIds` at 2 entries: [6](#0-5) [7](#0-6) 

These constraints bound the *result size* but do not limit *request rate*. An attacker sending `limit=1` still acquires a DB connection per request.

**HikariCP pool — no explicit override in `rest-java`:**

The `rest-java/src/main/resources/` directory contains only `banner.txt` — no `application.yaml` or `application.properties` with HikariCP settings. HikariCP defaults apply: `maximumPoolSize = 10`, `connectionTimeout = 30000ms`.

**Infrastructure-level protection is deployment-specific:**

The Helm chart defines a GCP backend policy with `maxRatePerEndpoint: 250`, but this is a per-endpoint aggregate limit, not per-IP: [8](#0-7) 

Non-GCP deployments (bare-metal, AWS, Azure, local) have no equivalent protection. Even when enabled, a distributed attack from many IPs is not mitigated by an aggregate per-endpoint limit.

## Impact Explanation

When the HikariCP pool (default 10 connections) is saturated, all further requests block waiting for a free connection up to `connectionTimeout` (30 seconds), then throw `SQLTransientConnectionException`. This causes:

- All `GET /api/v1/network/registered-nodes` responses to fail with 500 errors for legitimate clients
- Potential spillover to all other `rest-java` endpoints sharing the same `DataSource` (e.g., `/api/v1/network/nodes`, `/api/v1/network/fees`, account/topic endpoints)
- Gossip node discovery by legitimate network participants is disrupted

The `RestJavaHighDBConnections` alert fires only after 5 minutes sustained at >75% utilization — well after the DoS is effective: [9](#0-8) 

## Likelihood Explanation

**Preconditions:** None. No account, API key, or authentication is required.

**Feasibility:** The `registered_node` table is expected to be small and the query uses an indexed range scan with `LIMIT`, so individual query duration is very short (sub-millisecond under normal conditions). This raises the request rate needed to sustain pool exhaustion. However, under concurrent load from multiple sources, or when the DB is already under load from other queries, the connection hold time increases, lowering the threshold for exhaustion. Tools like `wrk`, `ab`, or `hey` can trivially generate the required concurrency. The attack is stateless and repeatable.

**Mitigating factor:** The short query duration means a single attacker machine must sustain a very high request rate to keep 10 connections simultaneously occupied. However, this does not eliminate the risk in distributed attack scenarios or degraded DB conditions.

## Recommendation

1. **Application-level rate limiting:** Implement a per-IP rate limiter (e.g., bucket4j, Resilience4j `RateLimiter`, or a servlet filter) in the `rest-java` module, analogous to the `ThrottleConfiguration` already present in `web3`.
2. **Explicit HikariCP pool sizing:** Set an explicit `spring.datasource.hikari.maximumPoolSize` in `rest-java` configuration, sized to match expected concurrency, and configure `connectionTimeout` to fail fast rather than queue indefinitely.
3. **Concurrency limit per endpoint:** Consider Spring MVC's `AsyncTaskExecutor` or a semaphore-based guard to cap in-flight DB queries for this endpoint.
4. **Infrastructure hardening:** Ensure the GCP backend policy (or equivalent) is enforced in all deployment environments, and add per-IP rate limiting at the ingress/gateway layer.

## Proof of Concept

```bash
# Flood the endpoint with 50 concurrent connections, 10000 total requests
wrk -t50 -c50 -d30s \
  "https://<mirror-node-host>/api/v1/network/registered-nodes?limit=1"
```

Expected result: After the HikariCP pool (10 connections) is saturated, subsequent requests to any `rest-java` endpoint begin returning HTTP 500 with `SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms`.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L173-187)
```java
    @GetMapping("/registered-nodes")
    RegisteredNodesResponse getRegisteredNodes(@RequestParameter RegisteredNodesRequest request) {
        final var registeredNodes = networkService.getRegisteredNodes(request);
        final var registeredNodeDtos = registeredNodeMapper.map(registeredNodes);

        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE_ID);
        final var pageable = PageRequest.of(0, request.getLimit(), sort);
        final var links = linkFactory.create(registeredNodeDtos, pageable, REGISTERED_NODE_EXTRACTOR);

        final var response = new RegisteredNodesResponse();
        response.setRegisteredNodes(registeredNodeDtos);
        response.setLinks(links);

        return response;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L140-152)
```java
    public Collection<RegisteredNode> getRegisteredNodes(RegisteredNodesRequest request) {
        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE.REGISTERED_NODE_ID.getName());
        final var page = PageRequest.of(0, request.getLimit(), sort);

        final var nodeType = request.getType();
        final var bounds = resolveRegisteredNodeIdBounds(request.getRegisteredNodeIds());
        final long lowerBound = bounds.lowerEndpoint();
        final long upperBound = bounds.upperEndpoint();

        final var nodeTypeId = nodeType != null ? nodeType.getId() : null;
        return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
                lowerBound, upperBound, nodeTypeId, page);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java (L14-22)
```java
    @Query(value = """
            select * from registered_node
            where registered_node_id >= :lowerBound
            and registered_node_id <= :upperBound
            and deleted is false
            and (:type is null or type @> array[:type]::smallint[])
            """, nativeQuery = true)
    List<RegisteredNode> findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
            long lowerBound, long upperBound, @Nullable Short type, Pageable pageable);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L31-44)
```java
    @Builder.Default
    @Min(1)
    @Max(MAX_LIMIT)
    @RestJavaQueryParam(name = LIMIT, required = false, defaultValue = DEFAULT_LIMIT)
    private int limit = Integer.parseInt(DEFAULT_LIMIT);

    @Builder.Default
    @RestJavaQueryParam(name = ORDER, required = false, defaultValue = "asc")
    private Direction order = Direction.ASC;

    @Builder.Default
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L35-35)
```java
    public static final int MAX_LIMIT = 100;
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L50-60)
```yaml
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-221)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```
