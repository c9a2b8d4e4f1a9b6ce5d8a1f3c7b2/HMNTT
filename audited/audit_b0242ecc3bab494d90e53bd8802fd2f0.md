### Title
BigInt Overflow in `getTransactionDetailsFromTransactionId` Causes PostgreSQL Out-of-Range Error (DoS)

### Summary
In `rest/service/transactionService.js`, `getTransactionDetailsFromTransactionId()` computes `maxConsensusTimestamp` by converting `transactionId.getValidStartNs()` (a string concatenation of seconds and nanoseconds) to a BigInt and adding `maxTransactionConsensusTimestampRangeNs`. Because input validation only bounds the *seconds* component (≤ 9223372036854775807) and not the combined nanosecond value, an unprivileged user can supply a seconds value that, when concatenated with nanoseconds and converted to BigInt, exceeds PostgreSQL's bigint maximum (9223372036854775807). This causes PostgreSQL to throw an "integer out of range" error, resulting in a 500 response — a user-triggered denial of service.

### Finding Description

**Code path:**

`rest/transactionId.js` line 25 — `getValidStartNs()` returns a plain string concatenation:
```js
return `${this.validStartSeconds}${String(this.validStartNanos).padStart(9, '0')}`;
``` [1](#0-0) 

`rest/transactionId.js` line 51 — input validation only checks the *seconds* component:
```js
if (!isPositiveLong(txIdMatches[4], true)) {
``` [2](#0-1) 

`rest/service/transactionService.js` line 65 — the combined ns string is blindly cast to BigInt:
```js
const maxConsensusTimestamp = BigInt(transactionId.getValidStartNs()) + maxTransactionConsensusTimestampRangeNs;
``` [3](#0-2) 

This `maxConsensusTimestamp` is then passed as parameter `$3` directly to PostgreSQL:
```sql
and consensus_timestamp <= $3
``` [4](#0-3) 

**Root cause:** `isPositiveLong` validates only that the *seconds* field ≤ 9223372036854775807. It does not validate that `seconds × 10⁹ + nanos` fits within PostgreSQL's bigint range. The combined nanosecond value can far exceed 9223372036854775807 (PostgreSQL bigint max) while the seconds component alone passes validation.

**Overflow boundary:** PostgreSQL bigint max in nanoseconds = 9223372036854775807 ns = 9223372036 seconds + 854775807 ns. Any input with `seconds ≥ 9223372037` (or `seconds = 9223372036` with `nanos > 854775807`) produces a combined ns value that overflows PostgreSQL bigint. The seconds value 9223372037 is a valid positive long and passes `isPositiveLong`.

### Impact Explanation
PostgreSQL does not silently truncate out-of-range bigint parameters — it raises `ERROR: value "..." is out of range for type bigint`. This propagates as an unhandled database error, returning HTTP 500 to the caller. Any unauthenticated user who can reach the `/api/v1/transactions/:transactionId` endpoint can trigger this deterministically and repeatedly, constituting a reliable denial-of-service against the transaction lookup endpoint.

### Likelihood Explanation
No authentication is required. The exploit requires only crafting a transaction ID string with a large seconds value (e.g., `0.0.1-9223372037-0`), which is syntactically valid and passes all existing input checks. The attack is trivially repeatable with a single HTTP GET request and requires no special knowledge beyond the API format.

### Recommendation
After parsing, validate that the combined nanosecond timestamp fits within the valid range before using it in a query. Specifically, in `rest/transactionId.js` `fromString()`, after computing `seconds` and `nanos`, verify:

```js
const MAX_NS = 9223372036854775807n;
const combinedNs = seconds * 1_000_000_000n + BigInt(nanos);
if (combinedNs > MAX_NS) {
  throw new InvalidArgumentError(message);
}
```

Additionally, in `getTransactionDetailsFromTransactionId`, clamp `maxConsensusTimestamp` to `MAX_NS` before passing it to the query, to guard against any future path that bypasses the parser.

### Proof of Concept
```
GET /api/v1/transactions/0.0.1-9223372037-000000000
```
1. `fromString` parses seconds = `9223372037`, nanos = `0`.
2. `isPositiveLong("9223372037", true)` → passes (well within long range).
3. `getValidStartNs()` returns `"9223372037000000000"`.
4. `BigInt("9223372037000000000")` = `9223372037000000000n` > `9223372036854775807n` (PostgreSQL bigint max).
5. Adding `maxTransactionConsensusTimestampRangeNs` (600000000000n) makes it larger still.
6. PostgreSQL receives `$3 = 9223372037600000000` for a `bigint` column → throws `ERROR: value "9223372037600000000" is out of range for type bigint`.
7. Server returns HTTP 500.

### Citations

**File:** rest/transactionId.js (L24-26)
```javascript
  getValidStartNs() {
    return `${this.validStartSeconds}${String(this.validStartNanos).padStart(9, '0')}`;
  }
```

**File:** rest/transactionId.js (L51-53)
```javascript
  if (!isPositiveLong(txIdMatches[4], true)) {
    throw new InvalidArgumentError(message);
  }
```

**File:** rest/service/transactionService.js (L20-22)
```javascript
    where ${Transaction.PAYER_ACCOUNT_ID} = $1 
        and ${Transaction.CONSENSUS_TIMESTAMP} >= $2 and ${Transaction.CONSENSUS_TIMESTAMP} <= $3
        and ${Transaction.VALID_START_NS} = $2
```

**File:** rest/service/transactionService.js (L65-71)
```javascript
    const maxConsensusTimestamp = BigInt(transactionId.getValidStartNs()) + maxTransactionConsensusTimestampRangeNs;
    return this.getTransactionDetails(TransactionService.transactionDetailsFromTransactionIdQuery, [
      transactionId.getEntityId().getEncodedId(),
      transactionId.getValidStartNs(),
      maxConsensusTimestamp,
      nonce,
    ]);
```
