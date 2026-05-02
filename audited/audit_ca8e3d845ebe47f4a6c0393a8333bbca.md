### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Alias Lookup in `getEncodedId()`

### Summary
The `getEncodedId()` function in `rest/service/entityService.js` unconditionally fires a live database query for every syntactically valid `AccountAlias` string without any caching or rate-limiting guard at the application layer. Because the default REST DB connection pool is only 10 connections with a 20-second statement timeout, an unauthenticated attacker flooding the endpoint with unique valid alias strings can exhaust the pool, causing all subsequent legitimate requests to queue and time out, effectively taking a mirror node replica offline.

### Finding Description

**Exact code path:**

`getEncodedId()` (line 125–126) checks `AccountAlias.isValid(entityIdString)` — a pure regex test against `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/` — and, on match, immediately calls `getAccountIdFromAlias()` with no caching interposed:

```
getEncodedId()                          entityService.js:125-126
  → getAccountIdFromAlias()             entityService.js:71-81
    → getAccountFromAlias()             entityService.js:42-53
      → super.getRows(entityFromAliasQuery, [accountAlias.alias])   entityService.js:43
```

`entityFromAliasQuery` (lines 17–20) is a full table scan filtered by `alias = $1` against the `entity` table — a real DB round-trip every time.

**No alias-lookup caching exists in the REST Node.js service.** The `quickLru` cache in `rest/entityId.js` (lines 301–333) only caches `EntityId` string parsing (shard.realm.num → encoded integer). The `hiero.mirror.rest.cache.entityId` config (maxAge=1800, maxSize=100000) documented in `docs/configuration.md` lines 546–547 applies to that same EntityId parse cache, not to alias→entity DB lookups. `EntityService.getAccountFromAlias()` has no cache wrapper.

**Root cause:** The failed assumption is that alias lookups are cheap or infrequent. In reality, every syntactically valid alias string — regardless of whether it exists in the DB — triggers a full DB query. The `AccountAlias.isValid()` check is purely syntactic and imposes zero cost on the attacker.

**Pool configuration:** `rest/dbpool.js` lines 13–14 set `max: config.db.pool.maxConnections` and `statement_timeout: config.db.pool.statementTimeout`. The documented defaults (`docs/configuration.md` lines 555–557) are `maxConnections=10` and `statementTimeout=20000ms`. With 10 connections and a 20-second hold time per slow/missing-alias query, an attacker needs only 10 concurrent requests to saturate the pool.

**No application-level rate limiting:** The Traefik middleware chain (including `rateLimit` and `inFlightReq`) is gated on `global.middleware: false` by default in `charts/hedera-mirror-rest/values.yaml` line 89. The web3 `ThrottleManagerImpl` applies only to the Java web3 service. The REST Node.js service has no per-IP or global request-rate enforcement at the application layer.

### Impact Explanation

With the pool exhausted, `pg` queues new connection requests until `connectionTimeoutMillis` (default 20,000 ms) elapses, after which all queued requests fail with a connection-timeout error. Every API endpoint that resolves an account by alias (accounts, balances, NFTs, allowances, token relationships) becomes unavailable. Targeting multiple replicas simultaneously degrades the mirror node tier proportionally. Since mirror nodes are the sole read path for dApps, wallets, and explorers querying Hedera state, sustained unavailability constitutes meaningful degradation of network data-access capacity.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero knowledge of existing accounts. Valid alias strings are trivially generated: any sequence of characters from `[A-Z2-7]` passes `AccountAlias.isValid()`. A single attacker with a modest HTTP client (e.g., `ab`, `wrk`, or a simple async script) sending 10–20 concurrent requests per second with unique alias strings is sufficient to keep the pool saturated indefinitely. The attack is repeatable, stateless, and requires no prior reconnaissance.

### Recommendation

1. **Cache alias lookups:** Wrap `getAccountFromAlias()` with a short-lived negative-result cache (e.g., using the existing `quickLru` infrastructure) keyed on the decoded alias bytes. Even a 5–10 second TTL for negative results eliminates the amplification from repeated unique-alias flooding.
2. **Apply per-IP rate limiting at the application layer:** Do not rely solely on optional Traefik middleware. Add an in-process rate limiter (e.g., `express-rate-limit`) on alias/EVM-address resolution paths.
3. **Increase pool size or add a concurrency semaphore** for alias-lookup queries specifically, or enforce a maximum number of in-flight alias DB queries.
4. **Enable Traefik middleware by default** (`global.middleware: true`) with `inFlightReq` limits for alias-bearing paths.

### Proof of Concept

```bash
# Generate 10000 unique valid alias strings and flood a single replica
python3 -c "
import itertools, string
chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
for i, combo in enumerate(itertools.product(chars, repeat=5)):
    if i >= 10000: break
    print(''.join(combo))
" | xargs -P 50 -I{} curl -s \
  "https://<mirror-node-host>/api/v1/accounts/{}" -o /dev/null

# Within seconds, legitimate requests begin timing out:
curl -v "https://<mirror-node-host>/api/v1/accounts/0.0.2"
# → 503 or connection timeout after 20s
```

The 50-parallel-connection `xargs` invocation keeps the 10-connection pool permanently saturated. Each alias is unique, bypassing any future caching. No credentials are required.