### Title
Unauthenticated Connection Pool Exhaustion via Unbounded Concurrent Requests to `/api/v1/accounts/{id}/airdrops/pending`

### Summary
The `/api/v1/accounts/{id}/airdrops/pending` endpoint in `TokenAirdropsController` requires no authentication and has no application-level rate limiting. Every request unconditionally triggers at least one database query through `entityService.lookup()` and `repository.findAll()`. An unprivileged attacker sending thousands of concurrent requests can exhaust the HikariCP connection pool (Spring Boot default: 10 connections), causing all subsequent DB-dependent requests across the service to queue indefinitely or time out, effectively severing the service from its database.

### Finding Description
**Code path:**

- `TokenAirdropsController.getPendingAirdrops()` — `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java`, lines 77–86: plain `@GetMapping("/pending")`, no authentication, no throttle annotation.
- Delegates to `TokenAirdropServiceImpl.getAirdrops()` — `rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java`, lines 19–22:

```java
public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
    var id = entityService.lookup(request.getAccountId());   // DB query for alias/EVM addr
    return repository.findAll(request, id);                  // always a DB query
}
```

- `EntityServiceImpl.lookup()` — lines 31–37: for `EntityIdAliasParameter` or `EntityIdEvmAddressParameter` inputs, issues a `SELECT` against the `entity` table. For numeric IDs it skips the first query, but `repository.findAll()` always executes.
- `TokenAirdropRepositoryCustomImpl.findAll()` — lines 58–72: executes a jOOQ `SELECT … FROM token_airdrop WHERE … LIMIT ?` via `DSLContext`, consuming one HikariCP connection per in-flight request.

**Root cause:** No rate limiting exists at the application layer in `rest-java`. The only filters registered are `LoggingFilter` (logging only) and `ShallowEtagHeaderFilter` (ETag only) — confirmed in `RestJavaConfiguration.java` lines 42–46. The throttle infrastructure present in the `web3` module (`ThrottleManagerImpl`, `RequestFilter`) is entirely absent from `rest-java`.

**Why existing checks fail:**

- `charts/hedera-mirror-rest-java/values.yaml` line 56 sets `maxRatePerEndpoint: 250` but this is a GCP BackendPolicy that only applies when `gateway.gcp.enabled: true`; the default ingress uses Traefik.
- `global.middleware: false` (line 98) disables Traefik middleware (circuit breaker/retry) by default.
- `hpa.enabled: false` (line 104) means the service runs as a single replica by default, with no horizontal scale-out to absorb load.
- The Prometheus alert `RestJavaHighDBConnections` (line 208) fires only after 5 minutes at >75% pool utilization — far too slow to prevent exhaustion.

### Impact Explanation
Spring Boot's default HikariCP pool size is 10 connections. With thousands of concurrent requests each holding a connection for the duration of a DB query, the pool is exhausted within milliseconds. All other endpoints sharing the same pool (network info, topics, allowances) also become unable to acquire connections. New requests queue until `connectionTimeout` (default 30 s) expires, returning 500 errors. This constitutes a full denial-of-service for all DB-backed functionality — equivalent to a network partition between the service and its database — achievable with no credentials.

### Likelihood Explanation
The endpoint is publicly documented (OpenAPI spec), requires zero authentication, and accepts any valid account ID format (numeric, alias, EVM address). A single attacker with a modest HTTP load tool (e.g., `wrk`, `hey`, `ab`) can sustain thousands of concurrent connections from a single machine. The attack is trivially repeatable and requires no special knowledge beyond the public API path. The default single-replica, no-HPA, no-application-rate-limit deployment configuration makes every production instance vulnerable out of the box.

### Recommendation
1. **Application-level rate limiting:** Add a per-IP (or global) rate limiter in `rest-java` — mirror the `RequestFilter`/`ThrottleManagerImpl` pattern from the `web3` module, or use Spring's `bucket4j`/Resilience4j `RateLimiter` as a servlet filter applied to `/api/*`.
2. **Explicit HikariCP pool sizing:** Configure `spring.datasource.hikari.maximum-pool-size` and `connection-timeout` in `rest-java`'s `application.yml` to match expected concurrency and fail fast rather than queue indefinitely.
3. **Enable HPA by default:** Set `hpa.enabled: true` with a sensible `minReplicas` so load is distributed.
4. **Enable Traefik middleware:** Set `global.middleware: true` to activate the circuit breaker (`NetworkErrorRatio() > 0.10`) that can shed load before pool exhaustion.
5. **Concurrency cap at controller level:** Consider `server.tomcat.max-threads` / `server.tomcat.accept-count` tuning to bound the number of simultaneously active requests.

### Proof of Concept
```bash
# Prerequisites: any valid account ID on the network (e.g., 0.0.1234)
# Tool: wrk (or hey/ab)

# Send 5000 concurrent requests, sustaining load for 30 seconds
wrk -t 50 -c 5000 -d 30s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.1234/airdrops/pending"

# Expected result:
# - Within seconds, HikariCP pool (10 connections) is fully occupied
# - All other DB-backed endpoints begin returning HTTP 500
# - Prometheus alert RestJavaHighDBConnections fires (after 5 min lag)
# - Service recovers only after attack traffic stops and queued requests time out

# Variant using alias-format ID (triggers two DB queries per request):
wrk -t 50 -c 5000 -d 30s \
  "https://<mirror-node-host>/api/v1/accounts/AABBCCDD/airdrops/pending"
```