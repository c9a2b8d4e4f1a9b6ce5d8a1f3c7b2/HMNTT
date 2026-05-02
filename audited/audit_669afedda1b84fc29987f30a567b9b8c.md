### Title
Unauthenticated High-Frequency Request Flooding on `/api/v1/accounts/{id}/airdrops/outstanding` Causes Sustained Database Load (DoS Griefing)

### Summary
The `GET /api/v1/accounts/{id}/airdrops/outstanding` endpoint in the `rest-java` module accepts unlimited unauthenticated requests with no per-IP or global rate limiting. Each request unconditionally triggers a database query via `TokenAirdropRepositoryCustom.findAll()`. An attacker can flood this endpoint at high frequency with `limit=100` (the maximum), causing sustained database query load that degrades response times for all users of the same service.

### Finding Description
**Code path:**

- Controller: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java`, lines 66–75 (`getOutstandingAirdrops`)
- Service: `rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java`, lines 19–22 (`getAirdrops`)
- Repository: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustom.java`, line 14 (`findAll`)

**Root cause:**

The `getOutstandingAirdrops` handler applies only a `@Max(MAX_LIMIT)` bean-validation constraint on the `limit` parameter (capping it at 100 rows per response) and no other access control:

```java
@GetMapping(value = "/outstanding")
TokenAirdropsResponse getOutstandingAirdrops(
        @PathVariable EntityIdParameter id,
        @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
        ...
```

Every request unconditionally flows through `TokenAirdropServiceImpl.getAirdrops()` → `repository.findAll(request, id)`, issuing a live database query each time. There is no caching, no per-IP throttle, and no global request-rate limiter in the `rest-java` module.

**Why existing checks are insufficient:**

1. `@Max(MAX_LIMIT)` (MAX_LIMIT = 100) only bounds the result-set size per query; it does not limit request frequency.
2. The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` rate-limiting infrastructure exists exclusively in the `web3` module (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`). It is not wired into `rest-java` at all.
3. `WebMvcConfiguration` in `rest-java` registers only argument resolvers and formatters — no rate-limiting interceptor.
4. The DB-level `statementTimeout` (default 10 000 ms) limits individual query duration but does not prevent a flood of concurrent or sequential queries.
5. The constant `HIGH_VOLUME_THROTTLE` is declared in `Constants.java` but no throttle enforcement using it was found in the `rest-java` request path.

**Exploit flow:**

An attacker sends repeated requests:
```
GET /api/v1/accounts/0.0.1/airdrops/outstanding?limit=100
```
at maximum concurrency/frequency. Each request causes a full indexed scan of the `token_airdrop` table filtered by `sender_account_id`, returning up to 100 rows. With no rate gate, the attacker can saturate the database connection pool and degrade or block legitimate queries.

### Impact Explanation
Sustained flooding degrades or denies service for all users querying any `rest-java` endpoint that shares the same database connection pool and PostgreSQL backend. The impact is availability degradation (increased latency, connection pool exhaustion, query queue buildup) with no economic cost to the attacker. This matches the stated scope: "griefing with no economic damage to any user on the network."

### Likelihood Explanation
No authentication, no API key, and no rate limiting are required. Any HTTP client (curl, Python script, k6 — as the project's own load-test script `tools/k6/src/rest-java/test/accountsOutstandingAirdrop.js` demonstrates) can reproduce this at arbitrary request rates. The attack is trivially repeatable from a single IP or distributed across many IPs to bypass any upstream network-layer controls.

### Recommendation
Implement request-rate limiting in the `rest-java` module analogous to the existing `ThrottleConfiguration` in `web3`:

1. Add a global or per-IP token-bucket rate limiter (e.g., Bucket4j, as already used in `web3`) as a Spring `HandlerInterceptor` registered in `WebMvcConfiguration`.
2. Apply the limiter specifically to the `/api/v1/accounts/{id}/airdrops/**` path group.
3. Return HTTP 429 when the limit is exceeded.
4. Optionally add response caching (e.g., short TTL via the existing Redis infrastructure) for identical repeated queries to reduce DB round-trips.

### Proof of Concept
```bash
# Flood the endpoint from a single unauthenticated client
while true; do
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.1/airdrops/outstanding?limit=100" \
    -o /dev/null &
done
# Or with parallelism via k6 (mirrors the project's own test pattern):
# k6 run --vus 200 --duration 60s accountsOutstandingAirdrop.js
```

Each iteration issues a live DB query with no server-side rejection. Monitor DB connection pool saturation and p99 latency on the endpoint to observe degradation for concurrent legitimate users.