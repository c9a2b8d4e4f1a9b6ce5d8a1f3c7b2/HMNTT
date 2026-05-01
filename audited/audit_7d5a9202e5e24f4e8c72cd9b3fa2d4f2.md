Based on my investigation, I have confirmed the following:

1. **`NftAllowanceServiceImpl.getNftAllowances()`** has no rate limiting — only parameter validation before issuing a live DB query.
2. **Rate limiting (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module** for `ContractCallRequest` objects — it is entirely absent from `rest-java`.
3. **`RestJavaConfiguration`** registers only an ETag filter and a Protobuf converter — no throttle filter.
4. **`rest-java/src/main/resources/`** contains only `banner.txt` — no `application.yml` with rate-limit settings.
5. **Infrastructure mitigations**: Traefik circuit breaker (reactive, not proactive) and pgbouncer `max_user_connections: 250` for `mirror_rest` (shared across all instances).

---

### Title
Absence of Rate Limiting on `/api/v1/accounts/{id}/allowances/nfts` Enables Resource Exhaustion DoS

### Summary
The `rest-java` module exposes `GET /api/v1/accounts/{id}/allowances/nfts` via `AllowancesController` with no application-level rate limiting. Unlike the `web3` module which enforces per-second request limits via bucket4j, `rest-java` has no equivalent throttle. An unauthenticated attacker can flood this endpoint with concurrent requests, exhausting the HikariCP database connection pool and Tomcat HTTP thread pool, degrading or stopping service across mirror node instances that share the same pgbouncer pool.

### Finding Description
**Code path:**
- `AllowancesController.getNftAllowances()` (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java`, lines 57–83): accepts unauthenticated GET requests, builds an `NftAllowanceRequest`, and calls `service.getNftAllowances(request)` with no throttle guard.
- `NftAllowanceServiceImpl.getNftAllowances()` (`rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java`, lines 21–31): performs only parameter validation, then calls `repository.findAll(request, id)`.
- `NftAllowanceRepositoryCustomImpl.findAll()` (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java`, lines 37–47): executes a live jOOQ SQL query against the `nft_allowance` table, consuming a HikariCP connection for the duration.

**Root cause:** The `web3` module's `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` (all under `org.hiero.mirror.web3`) are not wired into `rest-java`. `RestJavaConfiguration` registers only `ShallowEtagHeaderFilter` — no rate-limit filter exists. There is no `@RateLimiter`, no bucket4j bean, and no Spring Security throttle in the `rest-java` application context.

**Why existing checks fail:**
- Parameter validation (`checkOwnerSpenderParamValidity`) only rejects malformed inputs; valid requests proceed unconditionally to the DB.
- `@Max(MAX_LIMIT)` on `limit` bounds result set size but does not limit request frequency.
- Traefik circuit breaker (`NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25`) is reactive — it trips only after damage is already occurring and does not prevent the flood.
- pgbouncer `max_user_connections: 250` for `mirror_rest` is a hard cap shared across all `rest-java` pod instances. Once exhausted, every instance fails to acquire a DB connection.

### Impact Explanation
Each concurrent request holds a HikariCP connection for the duration of the SQL query. With enough concurrent requests (exceeding the HikariCP pool size, Spring Boot default: 10 per instance), new requests queue and eventually time out. Because pgbouncer enforces `max_user_connections: 250` for `mirror_rest` across all pods, an attacker sustaining ~250 slow concurrent queries exhausts the shared DB connection budget, causing all `rest-java` instances to fail DB acquisition simultaneously — meeting the ≥30% node degradation threshold. HTTP thread pool exhaustion on individual pods compounds this.

### Likelihood Explanation
No authentication is required. The endpoint is publicly accessible. A single attacker with a modest botnet or even a single high-throughput client (e.g., `wrk`, `ab`, or a simple async HTTP script) can sustain thousands of requests per second. The attack is trivially repeatable and requires no special knowledge beyond the public API documentation. The `approved_for_all = true` filter in the query (`NftAllowanceRepositoryCustomImpl` line 26) does not prevent the query from executing and consuming a connection even when it returns zero rows.

### Recommendation
1. Add a bucket4j rate-limiting filter to `rest-java` mirroring the `web3` module's `ThrottleConfiguration` — wire it into `RestJavaConfiguration` as a `FilterRegistrationBean` applied to `/api/*`.
2. Expose a `hiero.mirror.restJava.throttle.requestsPerSecond` property (analogous to `hiero.mirror.web3.throttle.requestsPerSecond`) with a safe default (e.g., 200 RPS per instance).
3. Consider per-IP rate limiting at the Traefik ingress layer using `InFlightReq` or `RateLimit` middleware in addition to the existing circuit breaker.
4. Set an explicit `spring.datasource.hikari.maximum-pool-size` in `rest-java`'s configuration to prevent unbounded connection acquisition attempts.

### Proof of Concept
```bash
# Requires: wrk (https://github.com/wg1996/wrk)
# Target: a publicly accessible mirror node rest-java instance

wrk -t 16 -c 500 -d 60s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.1000/allowances/nfts"

# Expected result within 10-30 seconds:
# - HTTP 503 / connection refused from the targeted instance
# - Other rest-java pods begin returning DB connection timeout errors
#   (HikariCP: "Connection is not available, request timed out after Xms")
# - pgbouncer logs: "max_client_conn reached" for mirror_rest user
```