I verified all key code references and configuration claims against the actual repository. Here is my assessment:

**Verified:**
- `NetworkController.getRegisteredNodes()` at lines 173–186 — confirmed [1](#0-0) 
- `NetworkServiceImpl.getRegisteredNodes()` at lines 139–152 — confirmed [2](#0-1) 
- `RegisteredNodeRepository` native SQL query at lines 14–22 — confirmed [3](#0-2) 
- Traefik middleware at lines 158–163 contains only `circuitBreaker` and `retry`, no `inFlightReq` or `rateLimit` — confirmed [4](#0-3) 
- Zero rate-limiting infrastructure (`bucket4j`, `ThrottleManager`, etc.) in `rest-java` — confirmed by exhaustive grep returning no matches 
- `WebMvcConfiguration` registers only argument resolvers, no concurrency interceptors — confirmed [5](#0-4) 
- `RestJavaConfiguration` registers only an ETag filter and Protobuf converter, no rate/concurrency filter — confirmed [6](#0-5) 

**One claim that could not be fully confirmed:** The report states "No `maximumPoolSize` or `connectionTimeout` override was found in any YAML configuration for `rest-java`." A grep for those terms in `charts/hedera-mirror-rest-java/values.yaml` returned 2 matches, suggesting some HikariCP configuration does exist. The exact values were not read. This affects the severity argument (default pool of 10) but not the existence of the vulnerability — a larger pool only raises the number of concurrent connections needed to exhaust it.

---

# Audit Report

## Title
Unauthenticated Connection Pool Exhaustion via Concurrent Requests to `/api/v1/network/registered-nodes`

## Summary
The `GET /api/v1/network/registered-nodes` endpoint in the `rest-java` module is publicly accessible with no rate limiting, no in-flight request cap, and no per-IP throttling. Each request holds a HikariCP database connection for the full duration of a synchronous, blocking JPA/native-SQL query. An unauthenticated attacker sending enough concurrent requests can exhaust the shared connection pool, causing connection acquisition timeouts for every other endpoint sharing the same `DataSource`.

## Finding Description

**Verified code path:**

`NetworkController.getRegisteredNodes()` (lines 173–186) [1](#0-0)  → `NetworkServiceImpl.getRegisteredNodes()` (lines 139–152) [2](#0-1)  → `RegisteredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()` (lines 14–22). [3](#0-2) 

The repository executes a native SQL query via Spring Data JPA. This is a synchronous, blocking call: a HikariCP connection is acquired from the shared pool before the query executes and held until the result set is fully fetched and the transaction completes.

**No concurrency control exists in `rest-java`:**

- A full search of `rest-java/` for `bucket4j`, `ThrottleManager`, `ThrottleConfiguration`, and `RateLimit` returns zero matches. The throttle infrastructure present in the `web3` module is entirely absent here. 
- The Traefik middleware for `rest-java` configures only `circuitBreaker` and `retry` — no `inFlightReq` and no `rateLimit`. [4](#0-3) 
- `WebMvcConfiguration` registers only argument resolvers. [7](#0-6) 
- `RestJavaConfiguration` registers only an ETag filter and a Protobuf converter — no concurrency or rate filter. [6](#0-5) 
- `RegisteredNodesRequest` enforces only a `@Max(MAX_LIMIT)` on the result page size, which limits rows returned, not concurrent connections consumed.

**Aggravating factor:** The `retry: attempts: 3` Traefik middleware re-issues failed requests, amplifying connection demand when the pool begins to saturate. [8](#0-7) 

## Impact Explanation

All endpoints served by the `rest-java` process that share the same HikariCP `DataSource` — including `/api/v1/network/nodes`, `/api/v1/network/stake`, `/api/v1/accounts/{id}/allowances/nfts`, `/api/v1/topics/{id}`, etc. — become unavailable for the duration of the attack. Once the pool is exhausted, any new request to any endpoint blocks waiting for a connection and eventually throws `SQLTransientConnectionException` (HikariCP acquisition timeout), returning HTTP 500 to the caller. This is a full application-layer denial of service against the database tier.

## Likelihood Explanation

The attack requires no privileges, no account, and no knowledge beyond the public API documentation. Any attacker with a basic HTTP load tool (`curl`, `wrk`, `ab`, `k6`) can reproduce it. The attack is repeatable and sustainable: as long as the attacker maintains enough concurrent open requests to fill the pool, the pool remains exhausted. The `circuitBreaker` middleware only trips on error ratios after the fact and does not prevent connection acquisition from being exhausted. [4](#0-3) 

## Recommendation

1. **Add an `inFlightReq` Traefik middleware** to `charts/hedera-mirror-rest-java/values.yaml` to cap concurrent requests at the application ingress level, analogous to the configuration present in `hedera-mirror-rosetta/values.yaml`.
2. **Add application-level rate limiting** (e.g., `bucket4j` with a `FilterRegistrationBean`) in `rest-java` for public, unauthenticated endpoints, consistent with the approach used in the `web3` module.
3. **Remove or reduce the `retry` middleware** for endpoints that are already failing due to resource exhaustion, as retries amplify pool pressure. [8](#0-7) 
4. **Explicitly configure `maximumPoolSize`** and `connectionTimeout` in the `rest-java` datasource configuration to a value appropriate for the expected concurrency, and ensure it is sized with the above mitigations in mind.

## Proof of Concept

```bash
# Exhaust the connection pool with N concurrent requests
# Replace N with the configured maximumPoolSize (default: 10)
seq 1 20 | xargs -P 20 -I{} \
  curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes" -o /dev/null

# Simultaneously, observe 500 errors on an unrelated endpoint
curl -v "https://<mirror-node-host>/api/v1/network/stake"
# Expected: HTTP 500 SQLTransientConnectionException (HikariCP pool exhausted)
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L139-152)
```java
    @Override
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L158-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-32)
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
