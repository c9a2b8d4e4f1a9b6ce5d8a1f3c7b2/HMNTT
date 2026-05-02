### Title
Unauthenticated Pagination-Driven DB Connection Pool Exhaustion via `listStakingRewardsByAccountId`

### Summary
`listStakingRewardsByAccountId()` unconditionally sets `response.links.next` whenever `rewards.length === query.limit`, meaning any unprivileged caller using `limit=1` against an account with staking rewards receives a perpetual pagination chain. The REST API has no per-IP rate limiting or in-flight request cap in its ingress middleware, and the default DB connection pool is only 10 connections. An attacker flooding concurrent paginated requests — especially during or to induce a DB slowdown — can exhaust the pool and deny service to all users.

### Finding Description

**Pagination trigger** (`rest/controllers/accountController.js`, lines 194–200):
```js
if (response.rewards.length === query.limit) {
  const lastRow = last(response.rewards);
  const lastValue = { [filterKeys.TIMESTAMP]: lastRow.timestamp };
  response.links.next = utils.getPaginationLink(req, false, lastValue, query.order);
}
```
With `limit=1`, every response for an account that has at least one more reward record will include a `next` link. The attacker follows each link, generating a new DB query per hop. There is no server-side cursor, no session state, and no cost to the attacker per hop.

**DB connection pool** (`rest/dbpool.js`, lines 7–16; `docs/configuration.md`, line 556):
- Default `maxConnections = 10`
- `statementTimeout = 20000 ms`
- `connectionTimeout = 20000 ms`

Ten concurrent requests, each holding a connection for up to 20 seconds (e.g., during DB slowness or a partial network partition), fully exhaust the pool. All subsequent requests queue and eventually time out.

**No per-IP rate limiting on the REST API** (`charts/hedera-mirror-rest/values.yaml`, lines 134–139):
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```
The REST API ingress has only a `circuitBreaker` and a `retry` middleware. It has **no** `inFlightReq` (per-IP concurrent request cap) and **no** `rateLimit` (per-IP request rate cap). By contrast, the Rosetta API (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–163) has both `inFlightReq: amount: 5` and `rateLimit: average: 10`. The GraphQL API also has `inFlightReq`. The REST API is the only service missing these controls.

**Retry amplification**: The `retry: attempts: 10` middleware means each attacker HTTP request that fails at the ingress is retried up to 10 times, multiplying DB load by up to 10× per attacker request.

**Exploit flow**:
1. Attacker identifies any account with staking rewards (public data).
2. Sends `N` concurrent `GET /api/v1/accounts/{id}/rewards?limit=1` requests (N ≥ 10 to saturate the pool).
3. Each request acquires a DB connection and executes `SELECT … FROM staking_reward_transfer … LIMIT $2`.
4. During normal operation, connections are released quickly. During any DB slowness (high load, partial partition, lock contention), connections are held for up to 20 seconds each.
5. With the pool exhausted, all other REST API users receive connection timeout errors (after 20 seconds of waiting).
6. The `retry` middleware re-issues each failed request up to 10 times, sustaining the attack with fewer attacker-side connections.
7. The `circuitBreaker` only trips at 25% error ratio — by which point the pool has already been exhausted for a sustained window.

### Impact Explanation
Complete REST API denial of service for all users. The DB connection pool (default: 10) is a shared resource across all endpoints. Exhausting it blocks `/api/v1/accounts`, `/api/v1/transactions`, `/api/v1/tokens`, and every other REST endpoint simultaneously. The `statementTimeout` of 20 seconds means each attacker connection holds a pool slot for up to 20 seconds, requiring only 10 concurrent attacker requests to sustain a full outage. Severity: **High** (full service DoS, no authentication required, low attacker resource cost).

### Likelihood Explanation
Any unprivileged internet user can execute this attack. The only precondition is knowledge of one account ID with staking rewards, which is publicly discoverable via the same API. The attack requires only 10 concurrent HTTP connections — trivially achievable from a single machine. The absence of per-IP rate limiting (present on Rosetta and GraphQL but absent on the REST API) means there is no ingress-level defense. The attack is repeatable and sustainable indefinitely.

### Recommendation
1. **Add `inFlightReq` per-IP middleware** to `charts/hedera-mirror-rest/values.yaml`, matching the Rosetta pattern (`inFlightReq: amount: 5, sourceCriterion: ipStrategy: depth: 1`).
2. **Add `rateLimit` per-IP middleware** to the REST API ingress (e.g., `average: 100, sourceCriterion: requestHost: true`).
3. **Increase `maxConnections`** from the default of 10 to a value commensurate with expected concurrency (e.g., 50–100), or use PgBouncer in front of the REST API as is done for other services.
4. **Enforce a minimum effective `limit`** floor (e.g., 5) or add a cost-based throttle for pagination depth to reduce the amplification factor of `limit=1` chains.
5. **Remove or reduce the `retry: attempts: 10`** on the REST API ingress, or scope retries only to idempotent non-DB-bound failures, to prevent retry amplification.

### Proof of Concept
```bash
# Step 1: Find an account with staking rewards
ACCOUNT="0.0.1001"

# Step 2: Launch 10+ concurrent paginated requests (saturates default pool of 10)
for i in $(seq 1 15); do
  curl -s "https://<mirror-node>/api/v1/accounts/${ACCOUNT}/rewards?limit=1" \
    -o /dev/null &
done
wait

# Step 3: Verify service degradation for all other users
curl -v "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: connection timeout or 503 after ~20 seconds

# Step 4: Sustain attack by following next links in a loop
NEXT="/api/v1/accounts/${ACCOUNT}/rewards?limit=1"
while [ -n "$NEXT" ]; do
  RESP=$(curl -s "https://<mirror-node>${NEXT}")
  NEXT=$(echo "$RESP" | jq -r '.links.next // empty')
  # Fire additional concurrent requests here to maintain pool saturation
done
```