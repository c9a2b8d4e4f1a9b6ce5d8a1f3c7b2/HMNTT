### Title
Unbounded Pagination-Driven Database Exhaustion in `listStakingRewardsByAccountId` with No Application-Level Rate Limiting

### Summary
The `listStakingRewardsByAccountId` function in `rest/controllers/accountController.js` generates a `next` pagination link whenever `response.rewards.length === query.limit`, with no cap on how many sequential pages an unauthenticated caller may fetch. The REST API middleware stack contains no per-IP rate limiting or request throttling (unlike the `web3` service which has an explicit `ThrottleManagerImpl`), and the database connection pool defaults to only 10 connections with a 20-second statement timeout. An unprivileged attacker can drive a sustained stream of DB queries by following pagination links, exhausting the shared pool and degrading the mirror node REST API for all users.

### Finding Description
**Exact code path:**

`rest/controllers/accountController.js`, `listStakingRewardsByAccountId` (lines 170–203):

- Line 172: `EntityService.isValidAccount(accountId)` — first DB query per request.
- Lines 180–185: `StakingRewardTransferService.getRewards(...)` — second DB query per request, executing the SQL in `rest/service/stakingRewardTransferService.js` (lines 11–16): `SELECT … FROM staking_reward_transfer srt WHERE srt.account_id = $1 ORDER BY … LIMIT $2`.
- Lines 194–200: If `response.rewards.length === query.limit`, a `next` link is unconditionally emitted with a timestamp cursor. There is no page count ceiling, no session token, and no server-side state tracking how many pages a client has consumed.

**Root cause — no application-level rate limiting on the REST API:**

`rest/server.js` (lines 67–98) shows the complete middleware stack: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler` (optional), `responseCacheCheckHandler` (optional). There is no rate-limiting middleware. The `ThrottleManagerImpl` / `ThrottleConfiguration` / `ThrottleProperties` classes that enforce per-second request limits exist exclusively in the `web3/` module and are never wired into the REST Express app.

The Traefik `middleware.yaml` template (`charts/hedera-mirror-rest/templates/middleware.yaml`, lines 3–27) is guarded by `{{ if and .Values.global.middleware .Values.middleware }}` — it is opt-in and not enabled in the default chart values, so no network-layer rate limit is guaranteed to be present.

**DB pool constraint:**

`rest/dbpool.js` (lines 13–15) and the documented default (`hiero.mirror.rest.db.pool.maxConnections = 10`, `statementTimeout = 20000 ms`). With 10 connections and a 20-second timeout, an attacker holding all connections with in-flight queries blocks every other REST API request that needs a DB connection.

**Why the `authHandler` check is insufficient:**

`rest/middleware/authHandler.js` only sets a custom response-size limit for authenticated users via `httpContext`; unauthenticated requests pass through without any restriction (`authHandler.test.js` line 37–41 confirms: "No Authorization header — proceeds without authentication").

### Impact Explanation
Each call to `/api/v1/accounts/{id}/rewards` issues two sequential DB queries. An attacker following pagination links at high frequency (or from multiple IPs) can saturate the 10-connection pool. Once the pool is exhausted, every other REST API endpoint (accounts, transactions, tokens, etc.) that requires a DB connection will queue or time out, effectively taking the mirror node REST service offline for legitimate users. In a horizontally scaled deployment where multiple REST pods share a single PostgreSQL read replica, the replica itself becomes the bottleneck, amplifying the impact across all pods.

### Likelihood Explanation
No privileges, API keys, or special knowledge are required. The attacker only needs to:
1. Identify any account with more staking reward records than the page limit (trivially discoverable on mainnet).
2. Script a loop that follows the `links.next` URL from each response.

The attack is fully automatable, repeatable, and can be launched from a single machine or distributed across many IPs to defeat any upstream IP-based firewall rules. The `next` link is self-contained and requires no session state, making it trivial to parallelize.

### Recommendation
1. **Add application-level rate limiting to the REST API.** Introduce a per-IP token-bucket middleware (e.g., `express-rate-limit`) in `rest/server.js`, mirroring the pattern already used in the `web3` service (`ThrottleManagerImpl`).
2. **Enforce a maximum page depth or cursor expiry.** Track a signed, time-limited cursor so that a pagination chain cannot be followed indefinitely without re-authenticating or re-validating.
3. **Enable the Traefik middleware by default** in `charts/hedera-mirror-rest/values.yaml` with `inFlightReq` and `rateLimit` entries (as already done for the Rosetta chart).
4. **Increase `db.pool.maxConnections`** or add a query queue with a maximum wait time to prevent full pool exhaustion from a single endpoint.

### Proof of Concept
```bash
# Step 1: Get first page (no credentials needed)
NEXT="/api/v1/accounts/0.0.800/rewards?limit=100&order=asc"
BASE="https://<mirror-node-host>"

while true; do
  RESPONSE=$(curl -s "${BASE}${NEXT}")
  NEXT=$(echo "$RESPONSE" | jq -r '.links.next')
  # If next is null, restart from beginning to keep pressure on DB
  if [ "$NEXT" = "null" ]; then
    NEXT="/api/v1/accounts/0.0.800/rewards?limit=100&order=asc"
  fi
  # Optionally parallelize: run N copies of this loop simultaneously
done
```

Each iteration issues 2 DB queries. Running 10 parallel instances of this loop against a default deployment (pool size = 10) will saturate the connection pool, causing all other REST API requests to fail with connection timeout errors.