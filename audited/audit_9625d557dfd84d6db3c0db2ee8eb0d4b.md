### Title
Unauthenticated Concurrent Request Flooding via Unbounded Timestamp IN-Clause Queries on `/accounts/:id/rewards`

### Summary
The `listStakingRewardsByAccountId` handler in `rest/controllers/accountController.js` accepts up to 100 repeated `timestamp` query parameters per request (the configured `maxRepeatedQueryParameters` default), each of which is aggregated into a SQL `IN (...)` clause against the `staking_reward_transfer` table. The REST API has zero application-level rate limiting or per-IP concurrency controls. An unprivileged attacker can flood the endpoint with many concurrent requests, each carrying the maximum allowed timestamp filters, exhausting the database connection pool and degrading service availability for legitimate users.

### Finding Description

**Code path:**

`rest/routes/accountRoute.js:16` registers the route with no middleware beyond request parsing:
```js
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
```

`rest/controllers/accountController.js:170-185` — `listStakingRewardsByAccountId` issues **two** DB queries per request unconditionally:
1. `EntityService.isValidAccount(accountId)` — entity table lookup
2. `StakingRewardTransferService.getRewards(...)` — staking reward table query

`rest/controllers/accountController.js:110-162` — `extractStakingRewardsQuery` collects every `timestamp=eq:T` filter into `timestampInValues[]` and emits a single `consensus_timestamp IN ($3, $4, ..., $N)` SQL condition. There is no cap on how many `eq` values are accumulated beyond the global `maxRepeatedQueryParameters` (default **100**).

`rest/service/stakingRewardTransferService.js:11-35` — the final query is:
```sql
SELECT account_id, amount, consensus_timestamp
FROM staking_reward_transfer srt
WHERE srt.account_id = $1
  AND srt.consensus_timestamp IN ($3, ..., $102)
ORDER BY srt.consensus_timestamp DESC
LIMIT $2
```

**Root cause:** `rest/middleware/requestHandler.js:15-20` configures `qs` with `arrayLimit: config.query.maxRepeatedQueryParameters` and `throwOnLimitExceeded: true`, which only rejects requests with **more than 100** repeated parameters. Requests with exactly 1–100 repeated `timestamp` values pass through and each triggers two DB queries. There is no rate limiter, no per-IP concurrency cap, and no token-bucket anywhere in the REST API middleware stack (`grep` for `rateLimit|throttle|inFlightReq` in `rest/**/*.js` returns zero matches). The web3 `ThrottleManager` (bucket4j) is entirely separate and does not apply here.

**Why existing checks are insufficient:**
- `maxRepeatedQueryParameters = 100` limits the IN-clause width per request but does not limit request rate or concurrency.
- `throwOnLimitExceeded: true` only fires for >100 values; it does not throttle.
- `isValidAccount` pre-check adds a second DB round-trip per request, doubling DB load.
- No infrastructure-level rate limiting is configured for the REST API (Traefik rate limiting shown in the repo is scoped to the Rosetta service only).

### Impact Explanation
An attacker can saturate the PostgreSQL connection pool (default `maxConnections` is a small finite number per the pool config) by sending a high volume of concurrent requests, each with 100 `timestamp=eq:T` parameters. This causes legitimate requests to queue or fail with connection timeout errors, effectively denying service. Because the `staking_reward_transfer` table can be large on mainnet, the `IN (100 values)` scan — even if indexed — multiplied across hundreds of concurrent connections produces measurable DB CPU and I/O pressure. No authentication, API key, or any other credential is required.

### Likelihood Explanation
Any external actor with a basic HTTP client and a valid account ID (trivially obtained from the public ledger) can execute this attack. The attack is stateless, requires no prior knowledge beyond a valid account number, and is trivially scriptable. The endpoint is publicly documented in the OpenAPI spec. Repeatability is unlimited.

### Recommendation
1. **Add application-level rate limiting** to the REST API Express app (e.g., `express-rate-limit` or a token-bucket middleware) scoped per source IP, applied globally or specifically to the `/accounts/:id/rewards` route.
2. **Cap the number of `eq` timestamp values** accepted by `extractStakingRewardsQuery` independently of `maxRepeatedQueryParameters` (e.g., limit to 10–25 IN-clause values for this endpoint).
3. **Add a DB statement timeout** for the REST API database role (analogous to the `statementTimeout` already present in the web3 pool config) to bound worst-case query duration.
4. Consider adding Traefik `inFlightReq` and `rateLimit` middleware to the REST API ingress, mirroring what is already done for the Rosetta service.

### Proof of Concept
```bash
# Generate 100 timestamp eq-filters (valid format)
PARAMS=$(python3 -c "print('&'.join(['timestamp=eq:1234567890.%09d' % i for i in range(1,101)]))")

# Flood with 200 concurrent requests, each carrying 100 timestamp filters
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1001/rewards?$PARAMS" &
done
wait
# Observe: DB connection pool exhaustion, 503/timeout responses for legitimate users
```

Each iteration fires 2 DB queries (isValidAccount + getRewards with a 100-value IN clause). 200 concurrent requests = 400 simultaneous DB queries against a pool typically sized at 10–20 connections.