### Title
Connection Pool Exhaustion via Unauthenticated Concurrent `findAll()` Requests on NFT Allowances Endpoint

### Summary
The `GET /api/v1/accounts/{id}/allowances/nfts` endpoint in `rest-java` is publicly accessible with no rate limiting, no concurrency controls, and no per-IP throttling. Each request synchronously acquires a HikariCP database connection for the duration of the query. An unprivileged attacker sending a sufficient number of concurrent requests can exhaust the connection pool, causing all subsequent database-dependent requests across the service to fail until the pool drains.

### Finding Description
**Code path:**
- Controller: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java`, lines 57–83 — publicly mapped `@GetMapping("/nfts")`, no authentication or rate-limit annotation.
- Repository: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java`, lines 37–47 — `findAll()` calls `dslContext.selectFrom(NFT_ALLOWANCE).where(...).limit(...).fetchInto(...)`, a synchronous blocking JOOQ query that holds a HikariCP connection for its entire duration.

**Root cause:**
1. No rate limiting exists in the `rest-java` module. The `ThrottleConfiguration`/`ThrottleManagerImpl` with Bucket4j rate limiting exists exclusively in the `web3` module (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`). There is no equivalent in `rest-java`.
2. The `rest-java` module uses HikariCP (`common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java`, lines 60–95), configured via `spring.datasource.hikari` properties. No explicit `maximumPoolSize` is set in `rest-java` resources (only `banner.txt` exists under `rest-java/src/main/resources/`), so HikariCP defaults apply (default `maximumPoolSize = 10`).
3. Each concurrent call to `findAll()` holds one connection from this pool for the full query round-trip.

**Why existing checks are insufficient:**
- `@Max(MAX_LIMIT)` (line 61 of `AllowancesController.java`) caps result rows at 100, bounding per-query data volume but not concurrency or connection hold time.
- `@Positive` validates the `limit` parameter but provides no concurrency protection.
- No servlet filter, interceptor, or Spring Security rule in `rest-java` limits request rate or concurrent connections per IP or globally.

**Exploit flow:**
An attacker sends N concurrent HTTP GET requests (where N ≥ HikariCP pool size, e.g., 10–20) to `/api/v1/accounts/{validId}/allowances/nfts`. Each request enters `findAll()` and acquires a pool connection. With the pool exhausted, any new request requiring a DB connection (including unrelated endpoints sharing the same pool) blocks waiting for `connectionTimeout` (HikariCP default: 30 seconds), then throws `SQLTransientConnectionException`, resulting in HTTP 500 responses to all users.

### Impact Explanation
All endpoints in `rest-java` that share the same HikariCP `DataSource` become unavailable for the duration of the attack. This constitutes a full service-level denial of service for the mirror node REST API, not just the NFT allowances endpoint. The attacker does not need credentials, special knowledge, or elevated privileges — only the ability to send concurrent HTTP requests to a public endpoint.

### Likelihood Explanation
The attack requires no authentication, no special tooling beyond a basic HTTP load generator (e.g., `ab`, `wrk`, `curl` in parallel), and is trivially repeatable. The attacker needs only ~10–20 concurrent connections sustained continuously to keep the pool exhausted. Valid `accountId` values are publicly discoverable from the Hedera ledger. The absence of rate limiting in `rest-java` (in contrast to the explicit Bucket4j throttling in `web3`) indicates this protection gap was not intentional design but an oversight.

### Recommendation
1. **Add rate limiting to `rest-java`**: Implement a Bucket4j or similar token-bucket rate limiter (mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`) as a servlet filter or Spring interceptor applied to all `/api/v1/**` routes.
2. **Set an explicit HikariCP `maximumPoolSize`** appropriate for the expected concurrency, and configure `connectionTimeout` to fail fast rather than queue indefinitely.
3. **Add a Tomcat/server-level connection limit** (`server.tomcat.max-connections`, `server.tomcat.accept-count`) to reject excess connections at the HTTP layer before they reach the DB layer.
4. **Consider a statement timeout** on the JOOQ `DSLContext` to bound the maximum time any single query can hold a connection.

### Proof of Concept
```bash
# Requires a valid accountId known to have NFT allowances (publicly discoverable)
ACCOUNT_ID="0.0.12345"
BASE_URL="https://<mirror-node-host>"

# Send 20 concurrent requests to exhaust a default pool of 10
for i in $(seq 1 20); do
  curl -s "$BASE_URL/api/v1/accounts/$ACCOUNT_ID/allowances/nfts?limit=100" &
done
wait

# Immediately probe a different endpoint sharing the same DataSource
# Expected result: HTTP 500 (SQLTransientConnectionException / pool exhausted)
curl -v "$BASE_URL/api/v1/accounts/$ACCOUNT_ID/allowances/nfts"
```
While the 20 concurrent queries hold all pool connections, the final probe (and any legitimate user request) will receive a 500 error due to connection pool exhaustion. Repeat the loop continuously to sustain the outage.