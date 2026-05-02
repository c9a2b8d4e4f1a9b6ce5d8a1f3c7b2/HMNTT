### Title
Zero-Balance Misreport via COALESCE Fallback for Dormant Accounts in `getLatestBalanceSnapshot`

### Summary
In `rosetta/app/persistence/account.go`, the `latestBalanceBeforeConsensus` SQL query anchors its balance lookup to the latest treasury snapshot timestamp, then uses `COALESCE(..., 0)` for the target account's balance. Under the deduplication design, accounts with stable balances receive no new `account_balance` rows between snapshots. If an account's last balance row predates the `lower_bound` (second-to-last partition boundary), the COALESCE silently returns `balance=0` with a valid `ConsensusTimestamp`, and `getBalanceChange()` then accumulates only transfers since that snapshot — producing a materially incorrect balance for any dormant account with a real non-zero balance.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/account.go`, lines 30–50 (`latestBalanceBeforeConsensus`):

```sql
select
  bt.consensus_timestamp,
  coalesce((
    select balance
    from account_balance as ab
    where account_id = @account_id and
      ab.consensus_timestamp <= bt.consensus_timestamp and
      ab.consensus_timestamp >= @lower_bound and          -- ← window floor
      ab.consensus_timestamp <= @timestamp
    order by ab.consensus_timestamp desc
    limit 1
  ), 0) as balance                                        -- ← silent zero fallback
from (
  select consensus_timestamp
  from account_balance
  where account_id = @treasury_entity_id and             -- ← anchored to treasury
    consensus_timestamp >= @lower_bound and
    consensus_timestamp <= @timestamp
  order by consensus_timestamp desc
  limit 1
) as bt
```

`getLatestBalanceSnapshot` (lines 267–311) calls this query, then passes the returned `ConsensusTimestamp` directly to `getBalanceChange()` (lines 313–339) as `consensusStart`. The balance change query sums `crypto_transfer` amounts strictly after `consensusStart`, so the final reported balance is `0 + Σ(transfers since snapshot)`.

**Root cause — failed assumption:**

The design assumes every account with a non-zero balance will have at least one `account_balance` row within the `[lower_bound, treasury_snapshot_timestamp]` window. This assumption is broken by the deduplication scheme: `balanceSnapshotDeduplicate` only inserts rows for accounts whose `balance_timestamp > minConsensusTimestamp` (see `AccountBalanceRepository.java` lines 36–47). Accounts that have not transacted for longer than two partition periods receive no new rows and fall entirely outside the `lower_bound` window.

**Exploit flow:**

1. Attacker identifies a dormant account (e.g., a cold-storage account) with a known non-zero balance whose last `account_balance` row is older than the second-to-last partition boundary.
2. Attacker calls the Rosetta `/account/balance` endpoint (or any path that reaches `RetrieveBalanceAtBlock`) with a recent block identifier.
3. `selectPreviousPartitionLowerBound` returns a `lower_bound` that is newer than the account's last balance row.
4. The inner subquery of `latestBalanceBeforeConsensus` finds no row for the target account → COALESCE returns `0`.
5. `getLatestBalanceSnapshot` returns `(treasury_snapshot_timestamp, balance=0)`.
6. `getBalanceChange` sums only transfers after `treasury_snapshot_timestamp`; if the account has been dormant, this sum is also 0.
7. Rosetta reports the account balance as **0** instead of its true value.

**Why existing checks are insufficient:**

- The `lower_bound` guard (lines 276–285) is intended to widen the search window, but it only reaches back to the second-to-last partition — it does not guarantee coverage for accounts inactive beyond that horizon.
- The `ab.ConsensusTimestamp == 0` guard (line 304) only catches the case where the treasury itself has no snapshot; it does not detect the case where the treasury snapshot exists but the target account row is absent.
- No validation compares the returned `balance=0` against the entity's existence or last-known balance.

### Impact Explanation
Any consumer of the Rosetta API (exchanges, validators, block explorers, automated trading systems) that relies on `/account/balance` for a dormant account will receive a fabricated zero balance. This can be used to falsely assert an account is empty, enabling social-engineering attacks, incorrect reconciliation, or manipulation of off-chain systems that gate actions on reported balance. The misreported balance also propagates into the `hbarAmount.Value` returned by `RetrieveBalanceAtBlock` (line 211), affecting all downstream callers.

### Likelihood Explanation
No privileges are required. Any caller with network access to the Rosetta API endpoint can trigger this by supplying a valid recent block identifier. The precondition (an account inactive for longer than two partition periods) is common on mainnet for cold-storage, foundation, or escrow accounts. The attacker needs only to know the target account ID and confirm its inactivity — both are observable from public ledger data. The attack is repeatable and deterministic.

### Recommendation
1. **Remove the `lower_bound` floor on the target account lookup**, or extend it to the full history, so that the most recent balance row for any account is always found regardless of inactivity period.
2. **Treat `balance=0` with a valid `ConsensusTimestamp` as ambiguous**: after the COALESCE returns 0, perform a secondary check to confirm the account genuinely had zero balance at that snapshot (e.g., verify no prior balance row exists at all, or that the account was created after the snapshot).
3. **Return an explicit error** (rather than silently returning 0) when the target account exists in the `entity` table but has no `account_balance` row reachable within the search window.

### Proof of Concept
**Preconditions:**
- Account `0.0.X` has a real balance of, say, 1000 HBAR.
- Its last `account_balance` row has `consensus_timestamp = T0`.
- The current second-to-last partition lower bound is `T1 > T0`.
- Treasury account has a snapshot at `T2` where `T1 ≤ T2`.

**Steps:**
```
GET /account/balance
{
  "network_identifier": { ... },
  "account_identifier": { "address": "0.0.X" },
  "block_identifier": { "index": <block at T2> }
}
```

**Expected (correct) response:** `balance = 1000 HBAR`

**Actual response:** `balance = 0 HBAR`

This is because `latestBalanceBeforeConsensus` anchors to treasury snapshot `T2`, finds no row for `0.0.X` in `[T1, T2]`, COALESCE returns 0, and `getBalanceChange` finds no transfers after `T2` for the dormant account.