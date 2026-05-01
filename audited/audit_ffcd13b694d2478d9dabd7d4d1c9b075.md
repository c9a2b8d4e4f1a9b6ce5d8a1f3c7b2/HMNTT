### Title
Incorrect `consensus_timestamp` Derived from Paginated Subset in `getTokenBalances()` During Replica Lag

### Summary
In `rest/tokens.js`, `getTokenBalances()` computes the response `timestamp` field as `MAX(balance_timestamp)` from a paginated, `associated = true`-filtered CTE against the `token_account` table. During replica lag (e.g., network partition recovery), the replica's `token_account` table is incomplete, causing the CTE to omit recently-associated accounts and return a `MAX(balance_timestamp)` that is lower than the true network state — producing a structurally incorrect `consensus_timestamp` in the API response. No privileges are required to trigger this; any GET request to `/api/v1/tokens/{tokenId}/balances` (without a timestamp filter) during replica catch-up is sufficient.

### Finding Description
**Exact code path:**

`rest/tokens.js`, `extractSqlFromTokenBalancesRequest()`, lines 667–686 (the `else` branch, triggered when no `timestamp` query param is supplied):

```js
conditions.push('ti.associated = true');
// ...
query = `
  with filtered_token_accounts as (
    select ti.account_id, ti.balance, ti.balance_timestamp
      from token_account as ti
      where ${conditions.join(' and ')}
      order by ti.account_id ${order}
      limit $${params.push(limit)}          // ← paginated subset only
  )
  select 
    tif.account_id,
    tif.balance,
    (select MAX(balance_timestamp) from filtered_token_accounts) as consensus_timestamp
  from filtered_token_accounts as tif`;
```

`getTokenBalances()`, lines 729–730, then surfaces this value directly:

```js
const timestamp = rows[0].consensus_timestamp ?? rows[0].snapshot_timestamp;
response.timestamp = utils.nsToSecNs(timestamp);
```

**Root cause — two compounding failed assumptions:**

1. **Structural (always present):** `MAX(balance_timestamp)` is computed over the CTE, which is already bounded by `LIMIT $N` (default 25). Even on a fully-synced replica, the returned `consensus_timestamp` reflects only the maximum balance timestamp of the current page, not the global network state.

2. **Replica-lag amplification:** During partition recovery the replica's `token_account` rows for recently-associated accounts have not yet been applied. The `ti.associated = true` predicate therefore silently drops those accounts from the CTE entirely. The `MAX(balance_timestamp)` is computed over this reduced set, producing a timestamp that is arbitrarily older than the true head of the chain.

**Why existing checks are insufficient:**

- There is no replica-lag guard (e.g., no check against a known-good `consensus_end` from the `record_file` table before serving the query).
- There is no validation that the computed `MAX(balance_timestamp)` is within an acceptable staleness window.
- The timestamp-filter branch (lines 638–666) uses `token_balance` with an explicit `consensus_timestamp` range and is not affected; only the no-timestamp branch (lines 667–686) uses `token_account` with this aggregate.

### Impact Explanation
Clients that rely on the `timestamp` field to assess data freshness (e.g., wallets, DeFi integrations, compliance tools checking "as-of" token holder snapshots) receive a silently incorrect value. The response appears structurally valid — HTTP 200, well-formed JSON — so no client-side error is raised. The `balances` array is also incomplete (missing recently-associated holders), meaning token holder counts and distributions are understated. In protocol contexts where the mirror node is used to verify token association state before executing a dependent operation, this can cause false-negative association checks.

### Likelihood Explanation
Network partition events and replica catch-up windows are routine in distributed PostgreSQL deployments (failover, maintenance, replication slot lag). The trigger requires zero attacker privileges — a plain unauthenticated GET request. The attacker does not need to cause the partition; they only need to issue requests during the recovery window, which can last from seconds to minutes. The condition is detectable externally by comparing successive `timestamp` values in responses (a stale or non-advancing timestamp signals lag). This makes the window both identifiable and repeatable.

### Recommendation
1. **Fix the aggregate scope:** Move `MAX(balance_timestamp)` outside the paginated CTE by computing it in a separate subquery over the full (unpaginated) `token_account` where `token_id = $1 AND associated = true`, independent of the `LIMIT`. This removes the structural flaw regardless of replica state.
2. **Add a replica-lag guard:** Before executing the query, compare the replica's `MAX(consensus_end)` from `record_file` against a configurable staleness threshold (e.g., 10 seconds). Return HTTP 503 if the replica is too far behind, consistent with how other mirror-node endpoints handle lag.
3. **Document the semantic:** If the intent is "max balance_timestamp of the returned page," rename the field (e.g., `page_max_balance_timestamp`) so clients are not misled into treating it as a network consensus timestamp.

### Proof of Concept
**Preconditions:**
- Mirror node is configured with a read replica.
- A network partition or replication lag event causes the replica's `token_account` table to lag behind the primary by ≥1 recently-committed association.

**Steps:**
1. On the primary, associate account `0.0.X` with token `0.0.T` (sets `associated = true`, `balance_timestamp = T_new`).
2. Before the replica replicates this row, send:
   ```
   GET /api/v1/tokens/0.0.T/balances
   ```
   (no `timestamp` query parameter — triggers the `else` branch).
3. **Observed:** Response `timestamp` is `MAX(balance_timestamp)` of the stale, incomplete CTE — does not include `T_new`. Account `0.0.X` is absent from `balances[]`.
4. **Expected:** Response `timestamp` should reflect the true head of the replicated chain; account `0.0.X` should appear (or the endpoint should return 503 indicating replica lag).
5. Repeat during the catch-up window to confirm the timestamp advances only as rows are replicated, not as they are committed on the primary. [1](#0-0) [2](#0-1)

### Citations

**File:** rest/tokens.js (L667-686)
```javascript
  } else {
    conditions.push('ti.associated = true');
    if (balanceConditions.length) {
      conditions.push(...balanceConditions);
    }

    query = `
      with filtered_token_accounts as (
        select ti.account_id, ti.balance, ti.balance_timestamp
          from token_account as ti
          ${joinEntityClause}
          where ${conditions.join(' and ')}
          order by ti.account_id ${order}
          limit $${params.push(limit)}
      )
      select 
        tif.account_id,
        tif.balance,
        (select MAX(balance_timestamp) from filtered_token_accounts) as consensus_timestamp
      from filtered_token_accounts as tif`;
```

**File:** rest/tokens.js (L724-730)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length > 0) {
    const cachedTokens = await TokenService.getCachedTokens(new Set([tokenId]));
    const decimals = cachedTokens.get(tokenId)?.decimals ?? null;
    response.balances = rows.map((row) => formatTokenBalanceRow(row, decimals));
    const timestamp = rows[0].consensus_timestamp ?? rows[0].snapshot_timestamp;
    response.timestamp = utils.nsToSecNs(timestamp);
```
