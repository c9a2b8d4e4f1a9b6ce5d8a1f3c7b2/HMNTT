Looking at the code carefully:

### Title
Key Range Filter Bypass in `getHookStorageChange()` via Mixed In-Range/Out-of-Range Key List

### Summary
In `HookServiceImpl.getHookStorageChange()`, the guard at line 93 only blocks requests where **all** supplied keys fall outside the declared range. When at least one key is in range, the guard passes — but the subsequent repository call at line 104 forwards the raw, unfiltered `keys` collection (not `keysInRange`) to `findByKeyInAndTimestampBetween()`. Because the SQL query uses only `key in (:keys)` with no range predicate, any out-of-range keys in the list are also resolved, exposing hook storage entries the caller was never authorized to read.

### Finding Description

**Exact code path:**

`HookServiceImpl.java`, `getHookStorageChange()`, lines 89–105:

```java
final var keys        = request.getKeys();          // raw, user-supplied
final boolean requestHasKeys = !keys.isEmpty();
final var keysInRange = request.getKeysInRange();   // filtered to [lower, upper]

// Guard: only fires when ALL keys are out of range
if (keysInRange.isEmpty() && requestHasKeys) {      // line 93
    return new HookStorageResult(ownerId, List.of());
}
// ...
if (requestHasKeys) {
    changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
            ownerId.getId(), hookId, keys,           // BUG: `keys`, not `keysInRange`
            timestampLowerBound, timestampUpperBound, page);
}
```

`HookStorageChangeRepository.java`, lines 41–56 — the SQL contains no key-range predicate:

```sql
where owner_id = :ownerId
  and hook_id  = :hookId
  and key in (:keys)                                -- no range check
  and consensus_timestamp between ...
```

**Root cause:** The guard at line 93 is a necessary-but-not-sufficient check. It only eliminates the degenerate case where every supplied key is out of range. For any mixed list (≥1 key in range, ≥1 key out of range), `keysInRange` is non-empty, the guard is skipped, and the full `keys` list — including out-of-range entries — is handed to the repository. `getKeysInRange()` in `HookStorageRequest` correctly computes the filtered list, but the result is never used in the historical branch.

**Failed assumption:** The developer apparently assumed that computing `keysInRange` and checking its emptiness was sufficient to enforce the range constraint, not realizing that the actual query still receives the unfiltered list.

### Impact Explanation
An unprivileged caller who knows (or can guess) any single key that falls within the declared range can append arbitrarily many out-of-range keys to the same request. The API will return historical hook storage values for all of them. Hook storage can contain smart-contract state such as balances, allowances, and ownership mappings. Leaking this data breaks confidentiality guarantees and, in protocols where storage values drive financial decisions (e.g., off-chain settlement, oracle reads), can enable front-running or targeted exploitation of exposed positions.

### Likelihood Explanation
- No authentication or privilege is required beyond knowing a valid `ownerId`/`hookId` pair, which are typically enumerable from public ledger data.
- The attacker only needs to include one legitimate in-range key alongside the target out-of-range keys; the legitimate key can be the range lower-bound itself.
- The exploit is deterministic, requires a single HTTP request, and is trivially repeatable.
- No rate-limiting or anomaly detection specific to key-list composition is visible in the service layer.

### Recommendation
Replace `keys` with `keysInRange` at line 104 of `HookServiceImpl.java`:

```java
// Before (buggy)
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keys, ...);

// After (correct)
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keysInRange, ...);
```

This mirrors the correct pattern already used in `getHookStorage()` (lines 72–79), where `keysInRange` is passed to the non-historical repository call.

### Proof of Concept

**Preconditions:**
- A hook exists with `ownerId=O`, `hookId=H`.
- The API is called with a timestamp range making `isHistorical()` return `true`.
- `keyLowerBound = 0x00`, `keyUpperBound = 0x0F` (declared range).
- `key_secret = 0xFF` is a storage slot outside the declared range containing sensitive data.
- `key_decoy = 0x05` is any key within the declared range (can be the lower bound itself).

**Steps:**

1. Craft a request:
   ```
   GET /hooks/{ownerId}/{hookId}/storage?
       key.gte=0x00&key.lte=0x0F
       &key[]=0x05          ← in-range decoy
       &key[]=0xFF          ← out-of-range target
       &timestamp=lte:...
   ```

2. Service evaluates:
   - `keys = [0x05, 0xFF]`
   - `keysInRange = [0x05]` (non-empty → guard at line 93 does NOT fire)
   - `requestHasKeys = true` → branch at line 103 taken
   - Repository called with `keys = [0x05, 0xFF]`

3. SQL executed:
   ```sql
   ... where owner_id = O and hook_id = H
         and key in (0x05, 0xFF)   -- 0xFF included, no range check
         and consensus_timestamp between ...
   ```

4. **Result:** Response includes the historical storage entry for `key=0xFF`, which is outside the declared `[0x00, 0x0F]` range and should never have been returned.