### Title
Missing Per-IP Rate Limiting in `rest-java` Allows DB I/O Starvation via Repeated `getAirdrops()` Queries

### Summary
The `rest-java` module exposes `GET /api/v1/accounts/{id}/airdrops/outstanding` and `/pending` with no application-level per-IP or per-user rate limiting. Unlike the `web3` module which uses bucket4j-based throttling, `rest-java` relies solely on a global GCP gateway rate limit (`maxRatePerEndpoint: 250`) that is shared across all users and is noted as requiring an HPA change to take effect. A single unprivileged attacker can flood the endpoint up to this global cap, monopolizing DB connections and degrading response times for all other users.

### Finding Description
**Code path:**

- `TokenAirdropsController.getOutstandingAirdrops()` / `getPendingAirdrops()` → `processRequest()` → `service.getAirdrops(request)` (`TokenAirdropsController.java`, lines 66–113)
- `TokenAirdropServiceImpl.getAirdrops()` (`TokenAirdropServiceImpl.java`, lines 19–22): no guards, directly calls `repository.findAll(request, id)`
- `TokenAirdropRepositoryCustomImpl.findAll()` (`TokenAirdropRepositoryCustomImpl.java`, lines 58–72): executes a live DB query on every call, bounded only by `.limit(request.getLimit())` (max 100 rows)

**Root cause:** The `rest-java` Spring MVC configuration (`WebMvcConfiguration.java`) registers only argument resolvers and formatters — no throttle filter, no rate-limit interceptor, no caching layer. The `web3` module has a full bucket4j-based `ThrottleManagerImpl` with per-second request and gas limits, but this infrastructure is entirely absent from `rest-java`.

**Failed assumption:** The design assumes the GCP gateway `maxRatePerEndpoint: 250` is a sufficient guard. This is a *global* limit shared across all clients, not a per-IP limit. Additionally, the comment in `values.yaml` line 56 reads `# Requires a change to HPA to take effect`, meaning the limit may not be enforced at all in default deployments.

**Aggravating factor:** `sessionAffinity: type: CLIENT_IP` (`values.yaml`, line 57–58) routes all requests from the same source IP to the same backend pod. An attacker's flood is therefore concentrated on a single pod's DB connection pool rather than being distributed.

**Exploit flow:**
1. Attacker identifies a highly active `accountId` (e.g., a known airdrop sender with thousands of pending airdrops — publicly observable on-chain).
2. Attacker sends requests at maximum rate (up to 250 req/s per the global cap, or unlimited if HPA-gated limit is inactive) to `GET /api/v1/accounts/{id}/airdrops/outstanding?limit=100`.
3. Each request triggers a full DB index scan on `token_airdrop__sender_id` for that account, returning up to 100 rows, with no caching.
4. The targeted pod's HikariCP connection pool is saturated; legitimate users receive timeouts or queued responses.

### Impact Explanation
Service degradation (increased latency, connection pool exhaustion) for all users of the `rest-java` API. The `RestJavaHighDBConnections` Prometheus alert fires when HikariCP active connections exceed 75% of max (`values.yaml`, lines 203–213), confirming the DB connection pool is a recognized bottleneck. No financial loss occurs, but availability is impaired — consistent with the declared Medium/griefing scope.

### Likelihood Explanation
Any unauthenticated user can execute this. No special privileges, tokens, or on-chain state are required beyond knowing a valid `accountId`. The target account can be identified trivially from public mirror node data. The attack is trivially scriptable (`curl` in a loop or any HTTP load tool). The absence of per-IP rate limiting in `rest-java` (in contrast to `web3`) is a structural gap, not a configuration oversight that operators are likely to have patched.

### Recommendation
1. Add application-level per-IP rate limiting to `rest-java` using bucket4j (already a dependency in `web3`), mirroring the `ThrottleConfiguration` / `ThrottleManagerImpl` pattern.
2. Add a response cache (e.g., Spring Cache with a short TTL of 1–5 seconds) for `getAirdrops()` keyed on `(accountId, type, limit, order, filters)` to absorb repeated identical queries.
3. Ensure `maxRatePerEndpoint` in the GCP gateway is enforced per source IP, not just globally per endpoint.
4. Remove or reduce the `sessionAffinity: CLIENT_IP` setting, or combine it with per-IP rate limiting so that affinity cannot be exploited to concentrate load on a single pod.

### Proof of Concept
```bash
# 1. Identify a highly active sender account (e.g., 0.0.12345) from public mirror data
# 2. Flood the outstanding airdrops endpoint at maximum rate
while true; do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.12345/airdrops/outstanding?limit=100" \
    -o /dev/null &
done
# 3. Observe: HikariCP active connections spike (RestJavaHighDBConnections alert fires),
#    p99 latency for all /api/v1/accounts/*/airdrops/* requests increases sharply,
#    legitimate users receive 503 or timeout responses.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustomImpl.java (L58-72)
```java
    public Collection<TokenAirdrop> findAll(TokenAirdropRequest request, EntityId accountId) {
        var type = request.getType();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, type.getBaseField())
                .and(getBoundConditions(bounds))
                .and(TOKEN_AIRDROP.STATE.eq(AirdropState.PENDING));

        var order = SORT_ORDERS.getOrDefault(type, Map.of()).get(request.getOrder());
        return dslContext
                .selectFrom(TOKEN_AIRDROP)
                .where(condition)
                .orderBy(order)
                .limit(request.getLimit())
                .fetchInto(TokenAirdrop.class);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L34-35)
```java
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L19-31)
```java
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-58)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L203-213)
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
