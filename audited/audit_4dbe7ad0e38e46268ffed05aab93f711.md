### Title
Unauthenticated Concurrent Request Flooding Exhausts HikariCP DB Connection Pool in REST Java Airdrop Endpoint

### Summary
The `GET /api/v1/accounts/{id}/airdrops/outstanding` endpoint in `TokenAirdropsController.processRequest()` issues a synchronous, blocking jOOQ query that holds a HikariCP database connection for the full duration of query execution. No rate limiting or concurrency control exists in the rest-java module for this endpoint. An unprivileged attacker sending enough concurrent requests can exhaust the finite connection pool, causing all subsequent requests from all users to fail with connection acquisition timeouts.

### Finding Description
**Code path:**

- `TokenAirdropsController.java` lines 89–114: `processRequest()` calls `service.getAirdrops(request)` synchronously.
- `TokenAirdropServiceImpl.java` lines 19–22: delegates directly to `repository.findAll(request, id)`.
- `TokenAirdropRepositoryCustomImpl.java` lines 58–72: executes a blocking `dslContext.selectFrom(TOKEN_AIRDROP).where(...).orderBy(...).limit(...).fetchInto(...)` — a synchronous JDBC call that holds a HikariCP connection for the entire query duration.

**Root cause:** The rest-java module has no per-IP, per-user, or global rate limiter for this endpoint. The `RestJavaConfiguration` registers only an ETag filter and jOOQ customizer — no throttle. The bucket4j-based `ThrottleConfiguration`/`ThrottleManagerImpl` exists exclusively in the `web3` module and is not applied here. The HikariCP pool (default `maximumPoolSize = 10`, `statementTimeout = 10 000 ms`) is the only resource bound.

**Why existing checks fail:**
- `@Max(MAX_LIMIT)` (line 69) caps `limit` at 100 rows — limits result size, not concurrency.
- `@Size(max = 2)` (lines 71–73) caps range parameters at 2 — limits query complexity marginally, not request rate.
- Neither check prevents an attacker from issuing many simultaneous requests.

**Exploit flow:** With pool size 10 and statement timeout 10 s, an attacker holding 10 concurrent slow queries (e.g., against an account with many airdrops and wide range filters) saturates the pool. All subsequent requests block waiting for a connection until HikariCP's `connectionTimeout` (default 30 s) elapses, returning errors to legitimate users.

### Impact Explanation
Complete denial of service for all users of the mirror node REST Java API. Because the HikariCP pool is shared across all endpoints served by the rest-java process, exhausting it blocks not only airdrop queries but every other endpoint (network, nodes, etc.) that requires a database connection. The `RestJavaHighDBConnections` Grafana alert fires reactively after 5 minutes at >75% utilization — it is a monitoring signal, not a prevention control.

### Likelihood Explanation
No authentication, API key, or network-level credential is required to call this endpoint. The attack requires only an HTTP client capable of issuing concurrent GET requests — trivially achievable with `curl`, `ab`, `wrk`, or any scripting language. The attacker does not need to know valid account IDs; any syntactically valid ID (e.g., `0.0.1`) will reach the DB layer. The attack is repeatable and stateless, making it easy to sustain.

### Recommendation
1. **Add a global rate limiter** to the rest-java module (e.g., bucket4j `RateLimitBucket` as already done in `web3/ThrottleConfiguration`) applied via a servlet filter or Spring MVC interceptor, limiting requests per second per IP or globally.
2. **Increase pool size** or use a semaphore to cap the number of concurrent in-flight DB queries, returning HTTP 429 when the limit is reached rather than blocking threads.
3. **Deploy an API gateway** (e.g., Envoy, nginx) in front of rest-java with per-IP connection and request-rate limits.
4. **Consider async/reactive DB access** (R2DBC) so that threads are not blocked while waiting for DB results, reducing the blast radius of pool exhaustion.

### Proof of Concept
```bash
# Exhaust the HikariCP pool (default size 10) with 20 concurrent requests
# Each request scans TOKEN_AIRDROP with a wide range, holding a connection
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>/api/v1/accounts/0.0.1/airdrops/outstanding\
?limit=100\
&receiver.id=gte:0.0.1\
&receiver.id=lte:0.0.9999999\
&token.id=gte:0.0.1\
&token.id=lte:0.0.9999999" &
done
wait

# Immediately after, a legitimate request will time out or receive a 500
curl -v "http://<mirror-node-host>/api/v1/accounts/0.0.2/airdrops/outstanding"
# Expected: connection pool exhaustion error / HTTP 500 within 30 s
```

**Key references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L89-114)
```java
    private TokenAirdropsResponse processRequest(
            EntityIdParameter id,
            EntityIdRangeParameter[] entityIds,
            int limit,
            Sort.Direction order,
            NumberRangeParameter[] serialNumbers,
            EntityIdRangeParameter[] tokenIds,
            AirdropRequestType type) {
        var entityIdsBound = new Bound(entityIds, true, ACCOUNT_ID, type.getPrimaryField());
        var request = TokenAirdropRequest.builder()
                .accountId(id)
                .entityIds(entityIdsBound)
                .limit(limit)
                .order(order)
                .serialNumbers(new Bound(serialNumbers, false, SERIAL_NUMBER, TOKEN_AIRDROP.SERIAL_NUMBER))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, TOKEN_AIRDROP.TOKEN_ID))
                .type(type)
                .build();

        var response = service.getAirdrops(request);
        var airdrops = tokenAirdropMapper.map(response);
        var sort = getSort(airdrops, order, type.getParameter());
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(airdrops, pageable, EXTRACTOR);
        return new TokenAirdropsResponse().airdrops(airdrops).links(links);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L34-36)
```java
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```

**File:** docs/configuration.md (L630-630)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```
