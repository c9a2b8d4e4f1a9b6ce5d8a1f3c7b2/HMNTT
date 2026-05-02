### Title
Unbounded `json_agg` on `transaction_signature` in `getSchedules()` Enables Memory Exhaustion via Signature Accumulation

### Summary
The `signatureQuery` constructed in `getSchedules()` at line 255 of `rest/schedules.js` uses `transactionSignatureJsonAgg` — a `json_agg()` with no row-level `LIMIT` — to aggregate all signatures for every schedule in the result page. Because the `transaction_signature` table has no unique constraint (by design), an unprivileged attacker can accumulate an unbounded number of signature rows for a single schedule by repeatedly submitting `ScheduleSign` transactions. A subsequent call to `GET /api/v1/schedules` forces the database to aggregate all rows into a single JSON array, potentially producing a multi-megabyte payload that exhausts server memory during serialization.

### Finding Description

**Exact code path:**

`transactionSignatureJsonAgg` is defined at lines 39–45 of `rest/schedules.js`:

```js
const transactionSignatureJsonAgg = `
  json_agg(json_build_object(
    'consensus_timestamp', ts.consensus_timestamp,
    'public_key_prefix', encode(ts.public_key_prefix, 'base64'),
    'signature', encode(ts.signature, 'base64'),
    'type', ts.type
  ) order by ts.consensus_timestamp)`;
``` [1](#0-0) 

This template is embedded verbatim into `signatureQuery` at lines 255–259 inside `getSchedules()`:

```js
const signatureQuery = `select entity_id, ${transactionSignatureJsonAgg} as signatures
    from transaction_signature ts
    where entity_id in (${positions})
    group by entity_id
    order by entity_id ${order}`;
``` [2](#0-1) 

There is no `LIMIT` clause inside the aggregation, no `FETCH FIRST N ROWS` per group, and no application-level cap on the size of `row.signatures` before it is serialized.

**Root cause — failed assumption:**

The code assumes the number of signatures per schedule is naturally bounded. The database schema explicitly contradicts this: the `transaction_signature` table has **no unique constraint or primary key**, because "the client can potentially sign multiple times with the same key." [3](#0-2) 

Every `ScheduleCreate` and every `ScheduleSign` transaction inserts one row per `sigMap` entry for the target `entity_id`, with no deduplication enforced at the database level. [4](#0-3) 

**Exploit flow:**

1. Attacker creates a schedule (any unprivileged account can do this).
2. Attacker repeatedly submits `ScheduleSign` transactions for that schedule. Each transaction can carry multiple `sigMap` entries; each entry produces one row in `transaction_signature` for the schedule's `entity_id`. Because there is no uniqueness constraint, the same key can be submitted again and again across separate transactions.
3. After accumulating N rows (e.g., 50,000), the attacker calls `GET /api/v1/schedules` (or `GET /api/v1/schedules?schedule.id=<target>`).
4. `getSchedules()` first fetches up to `defaultLimit` schedules, then issues `signatureQuery` with those `entity_id` values. PostgreSQL executes `json_agg(...)` over all N rows for the target schedule with no row cap, building a single JSON array in memory.
5. The result is returned to Node.js, which serializes the entire array into the HTTP response — exhausting heap memory proportional to N × (signature size).

**Why existing checks are insufficient:**

- The schedule list query applies a `LIMIT` on the **number of schedules** returned (line 67–78), not on signatures per schedule. [5](#0-4) 
- `formatScheduleRow` only filters signatures where `consensus_timestamp !== null` (line 84) — a trivially satisfied condition that removes nothing meaningful. [6](#0-5) 
- No response-size guard, streaming serialization, or per-group `LIMIT` exists anywhere in the handler.
- The same unbounded aggregation also exists in `getScheduleByIdQuery` (line 59), making `GET /api/v1/schedules/:id` equally affected. [7](#0-6) 

### Impact Explanation

A single schedule with 50,000 signature rows (each ~100 bytes of base64 data) produces a JSON array of ~5 MB. With the default page size of 25 schedules all seeded with large signature sets, a single request can force the server to allocate 100+ MB in the PostgreSQL aggregation buffer and again in the Node.js JSON serializer. Repeated concurrent requests can exhaust the process heap, causing an out-of-memory crash or severe latency degradation — a full Denial of Service against the REST API. No authentication is required to call `GET /api/v1/schedules`.

### Likelihood Explanation

Any account on the Hedera network can submit `ScheduleSign` transactions. Transaction fees are fractions of a cent in HBAR. An attacker can automate submission of thousands of signing transactions over hours or days at negligible cost, then trigger the DoS on demand. The attack is repeatable: after the node recovers, the poisoned rows remain in the database and the attack can be re-triggered immediately. No special privileges, insider access, or cryptographic material beyond a funded Hedera account are required.

### Recommendation

1. **Add a per-group row cap in the SQL aggregation.** Replace the bare `json_agg(...)` with a subquery that pre-limits rows per `entity_id`, e.g.:
   ```sql
   json_agg(sub.obj ORDER BY sub.consensus_timestamp)
   FROM (
     SELECT ts.consensus_timestamp, ts.public_key_prefix, ts.signature, ts.type
     FROM transaction_signature ts
     WHERE ts.entity_id = s.schedule_id
     ORDER BY ts.consensus_timestamp
     LIMIT 1000
   ) sub
   ```
2. **Enforce a unique constraint** on `(entity_id, consensus_timestamp, public_key_prefix)` in `transaction_signature` to prevent duplicate accumulation.
3. **Add a response-size guard** in `formatScheduleRow` that truncates `signatures` beyond a configurable maximum and signals truncation in the response.
4. **Apply a `statementTimeout`** at the DB pool level (already configurable in `config.js` line 139) to bound runaway aggregation queries.

### Proof of Concept

```
# Step 1 – Create a schedule (any Hedera account)
hedera schedule create --body "crypto-transfer ..."

# Step 2 – Flood transaction_signature rows (repeat 10,000 times)
for i in $(seq 1 10000); do
  hedera schedule sign --schedule-id 0.0.<SCHEDULE_ID>
done
# Each call inserts ≥1 row in transaction_signature for entity_id=<SCHEDULE_ID>
# No uniqueness check prevents accumulation.

# Step 3 – Trigger unbounded json_agg
curl -v "https://<mirror-node>/api/v1/schedules?schedule.id=0.0.<SCHEDULE_ID>"

# Expected result:
# - PostgreSQL aggregates all 10,000+ rows into a single JSON array
# - Node.js serializes a multi-MB response
# - Under concurrent load, server heap is exhausted → OOM / 503
```

### Citations

**File:** rest/schedules.js (L39-45)
```javascript
const transactionSignatureJsonAgg = `
  json_agg(json_build_object(
    'consensus_timestamp', ts.consensus_timestamp,
    'public_key_prefix', encode(ts.public_key_prefix, 'base64'),
    'signature', encode(ts.signature, 'base64'),
    'type', ts.type
  ) order by ts.consensus_timestamp)`;
```

**File:** rest/schedules.js (L59-64)
```javascript
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

**File:** rest/schedules.js (L67-78)
```javascript
const scheduleLimitQuery = (paramCount) => `limit $${paramCount}`;
const scheduleOrderQuery = (order) => `order by s.schedule_id ${order}`;

/**
 * Get the schedules list sql query to be used given the where clause, order and param count
 * @param whereQuery
 * @param order
 * @param count
 * @returns {string}
 */
const getSchedulesQuery = (whereQuery, order, count) => {
  return [schedulesMainQuery, whereQuery, scheduleOrderQuery(order), scheduleLimitQuery(count)].join('\n');
```

**File:** rest/schedules.js (L82-91)
```javascript
  const signatures = row.signatures
    ? row.signatures
        .filter((signature) => signature.consensus_timestamp !== null)
        .map((signature) => ({
          consensus_timestamp: utils.nsToSecNs(signature.consensus_timestamp),
          public_key_prefix: signature.public_key_prefix,
          signature: signature.signature,
          type: SignatureType.getName(signature.type),
        }))
    : [];
```

**File:** rest/schedules.js (L255-259)
```javascript
  const signatureQuery = `select entity_id, ${transactionSignatureJsonAgg} as signatures
    from transaction_signature ts
    where entity_id in (${positions})
    group by entity_id
    order by entity_id ${order}`;
```

**File:** docs/design/scheduled-transactions.md (L65-65)
```markdown
> **_Note:_** There's no unique constraint/primary key since the client can potentially sign multiple times with the same key
```

**File:** docs/design/scheduled-transactions.md (L105-119)
```markdown
- Insert a `TransactionSignature` for every entry in the `sigMap`:
  - Set `consensusTimestamp` to the `consensusTimestamp` in the transaction record.
  - Set `publicKeyPrefix` to the `sigPair.pubKeyPrefix`.
  - Set `entityId` to the `scheduleID` in the transaction receipt.
  - Set `signature` to the `sigPair.signature` `oneof` field.

#### Schedule Sign

- Insert a `Transaction` with `scheduled` set to false.
- Upsert an `Entities` for the `scheduleID`.
- Insert a `TransactionSignature` for every entry in the `sigMap`:
  - Set `consensusTimestamp` to the `consensusTimestamp` in the transaction record.
  - Set `publicKeyPrefix` to the `sigPair.pubKeyPrefix`.
  - Set `entityId` to the `scheduleID` in the transaction receipt.
  - Set `signature` to the `sigPair.signature` `oneof` field.
```
