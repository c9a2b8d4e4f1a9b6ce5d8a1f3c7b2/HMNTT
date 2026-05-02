### Title
Unbounded `json_agg()` Over `transaction_signature` in `getScheduleByIdQuery` Enables Paid DoS via Oversized Response

### Summary
The `getScheduleByIdQuery` in `rest/schedules.js` performs an unbounded `json_agg()` aggregation over all `transaction_signature` rows for a given schedule with no row limit. Because the `transaction_signature` table has no unique constraint and accumulates one row per signature per `ScheduleCreate`/`ScheduleSign` transaction, any Hedera network participant can inflate this table for a target schedule by submitting many `ScheduleSign` transactions. Subsequent calls to `GET /api/v1/schedules/{scheduleId}` force PostgreSQL to aggregate all accumulated rows into a single JSON payload, consuming unbounded memory and producing an arbitrarily large response that includes the `transaction_body` field.

### Finding Description

**Exact code location:** `rest/schedules.js`, lines 39–64.

The `transactionSignatureJsonAgg` expression and `getScheduleByIdQuery` are:

```js
// rest/schedules.js lines 39-45
const transactionSignatureJsonAgg = `
  json_agg(json_build_object(
    'consensus_timestamp', ts.consensus_timestamp,
    'public_key_prefix', encode(ts.public_key_prefix, 'base64'),
    'signature', encode(ts.signature, 'base64'),
    'type', ts.type
  ) order by ts.consensus_timestamp)`;

// rest/schedules.js lines 46-64
const getScheduleByIdQuery = `
  select ...
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

There is no `LIMIT`, `FETCH FIRST`, or `WHERE` clause restricting the number of `transaction_signature` rows joined and aggregated.

**Root cause — failed assumption:** The design assumes the number of signatures per schedule is small and bounded. The `transaction_signature` schema explicitly has no unique constraint:

> "There's no unique constraint/primary key since the client can potentially sign multiple times with the same key"

The importer inserts one row per `sigPair` entry in the `sigMap` of every successful `ScheduleCreate` or `ScheduleSign` transaction. Multiple `ScheduleSign` transactions for the same schedule each append new rows — confirmed by the `scheduleSignTwoBatches` test which shows rows accumulating across sign batches.

**Handler path:** `getScheduleById` (lines 115–128) calls `pool.queryQuietly(getScheduleByIdQuery, scheduleId)` and passes the entire result directly to `formatScheduleRow`, which maps all signatures into the response with no truncation. The `responseHandler.js` sends the full serialized payload with no size cap.

**Existing checks reviewed and shown insufficient:**
- `statement_timeout` (configured in `rest/dbpool.js` line 15 via `config.db.pool.statementTimeout`) can kill long-running queries, but a large aggregation over an indexed column (`entity_id`) completes quickly — it does not time out, it just returns a huge result.
- The `response.limit` config (default 25, max 100) applies only to the list endpoint `getSchedules`, not to `getScheduleById`.
- No response body size cap exists in `responseHandler.js` or any middleware.
- The `metricsHandler.js` only *measures* response size; it does not enforce a limit.

### Impact Explanation

Each API call to `GET /api/v1/schedules/{scheduleId}` causes PostgreSQL to materialize the full `json_agg()` result in memory. With tens of thousands of accumulated signature rows (each containing base64-encoded `public_key_prefix` and `signature` fields), the response JSON can reach tens to hundreds of megabytes. This causes:
1. **PostgreSQL memory pressure** — `work_mem` consumed per query execution for the sort inside `json_agg(...order by...)`.
2. **Mirror node memory pressure** — the full JSON string is held in Node.js heap before being sent.
3. **Network bandwidth exhaustion** — large responses for every concurrent request to the same schedule ID.
4. **Cascading DoS** — repeated concurrent requests amplify DB and application load disproportionately to the attacker's on-chain cost.
5. **Information exposure** — `transaction_body` (the serialized scheduled transaction protobuf, base64-encoded) is returned in every response regardless of signature count.

### Likelihood Explanation

Any Hedera network participant with a small HBAR balance can execute this attack. The cost per `ScheduleSign` transaction is a fraction of a cent on mainnet. A single attacker can submit hundreds of `ScheduleSign` transactions over a schedule's lifetime (up to 62 days), each with multiple `sigPair` entries in the `sigMap`, accumulating thousands of rows. Once the rows exist, the attack is amplified: the attacker (or any third party) can repeatedly call the read-only REST endpoint at no further on-chain cost, with each call triggering the full unbounded aggregation. The attack is repeatable, requires no privileged access to the mirror node, and the read endpoint has no authentication.

### Recommendation

1. **Add a `LIMIT` to the signature join:** Rewrite `getScheduleByIdQuery` to use a subquery or lateral join that caps the number of `transaction_signature` rows aggregated, e.g.:
   ```sql
   left join lateral (
     select * from transaction_signature
     where entity_id = s.schedule_id
     order by consensus_timestamp
     limit 1000
   ) ts on true
   ```
2. **Add a unique or deduplication constraint:** Consider deduplicating `transaction_signature` on `(entity_id, public_key_prefix)` at ingest time, since a given key signing the same schedule multiple times is semantically redundant for the API response.
3. **Enforce a response-level signature cap:** In `formatScheduleRow`, truncate `row.signatures` to a configurable maximum (e.g., 1000) before serialization.
4. **Add a configurable `work_mem` guard** at the PostgreSQL session level for the REST API role to bound per-query memory for sort operations inside `json_agg`.

### Proof of Concept

1. Create a schedule on Hedera testnet with `wait_for_expiry=true` and a long expiration (up to 62 days). Note the `scheduleId`.
2. Using a script, submit N `ScheduleSign` transactions for that `scheduleId`, each with a `sigMap` containing multiple `sigPair` entries (e.g., 10 pairs per transaction × 1000 transactions = 10,000 rows in `transaction_signature`).
3. Wait for the mirror node importer to process the transactions.
4. Issue: `GET /api/v1/schedules/{scheduleId}`
5. Observe: the response `signatures` array contains all 10,000 entries; response size is in the tens of megabytes; PostgreSQL CPU and memory spike during aggregation.
6. Issue the same request concurrently from multiple clients to amplify DB load. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/schedules.js (L39-64)
```javascript
const transactionSignatureJsonAgg = `
  json_agg(json_build_object(
    'consensus_timestamp', ts.consensus_timestamp,
    'public_key_prefix', encode(ts.public_key_prefix, 'base64'),
    'signature', encode(ts.signature, 'base64'),
    'type', ts.type
  ) order by ts.consensus_timestamp)`;
const getScheduleByIdQuery = `
  select
    s.consensus_timestamp,
    s.creator_account_id,
    e.deleted,
    s.executed_timestamp,
    s.expiration_time,
    e.key,
    e.memo,
    s.payer_account_id,
    s.schedule_id,
    s.transaction_body,
    s.wait_for_expiry,
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

**File:** rest/schedules.js (L115-128)
```javascript
const getScheduleById = async (req, res) => {
  utils.validateReq(req);
  const parseOptions = {allowEvmAddress: false, paramName: constants.filterKeys.SCHEDULEID};
  const scheduleId = EntityId.parseString(req.params.scheduleId, parseOptions).getEncodedId();

  const {rows} = await pool.queryQuietly(getScheduleByIdQuery, scheduleId);
  if (rows.length !== 1) {
    throw new NotFoundError();
  }

  const schedule = rows[0];
  res.locals[constants.responseHeadersLabel] = getScheduleCacheControlHeader(schedule);
  res.locals[constants.responseDataLabel] = formatScheduleRow(schedule);
};
```

**File:** rest/dbpool.js (L15-15)
```javascript
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** docs/design/scheduled-transactions.md (L52-65)
```markdown
- Add a new `transaction_signature` table that represents the signatories that have signed a transaction. Currently,
  only those in the `sigMap` of `ScheduleCreate` or `ScheduleSign` are saved:

```sql
create table if not exists transaction_signature
(
  consensus_timestamp bigint not null,
  public_key_prefix   bytea  not null,
  entity_id           bigint null,
  signature           bytea  not null
);
```

> **_Note:_** There's no unique constraint/primary key since the client can potentially sign multiple times with the same key
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.0__create_tables.sql (L700-709)
```sql
-- transaction_signature
create table if not exists transaction_signature
(
    consensus_timestamp bigint not null,
    entity_id           bigint null,
    public_key_prefix   bytea  not null,
    signature           bytea  not null,
    type                smallint
);
comment on table transaction_signature is 'Transaction signatories';
```
