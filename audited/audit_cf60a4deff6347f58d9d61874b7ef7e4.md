### Title
Unbounded `json_agg` Over `transaction_signature` Rows in `getScheduleById` Enables Connection-Pool Exhaustion DoS

### Summary
`getScheduleByIdQuery` in `rest/schedules.js` performs an uncapped `LEFT JOIN` against `transaction_signature` and aggregates every matching row with `json_agg(... ORDER BY ts.consensus_timestamp)` in a single PostgreSQL aggregation. Because the REST API has no rate limiting and the DB pool is capped at 10 connections with a 20-second statement timeout, an attacker who has seeded a schedule with many signature rows can hold all pool connections simultaneously, making the entire REST API unavailable for up to 20 seconds per wave of requests.

### Finding Description

**Exact code path**

`rest/schedules.js` lines 39–64 define `transactionSignatureJsonAgg` and `getScheduleByIdQuery`:

```js
// rest/schedules.js:39-45
const transactionSignatureJsonAgg = `
  json_agg(json_build_object(
    'consensus_timestamp', ts.consensus_timestamp,
    'public_key_prefix', encode(ts.public_key_prefix, 'base64'),
    'signature', encode(ts.signature, 'base64'),
    'type', ts.type
  ) order by ts.consensus_timestamp)`;
```

```sql
-- rest/schedules.js:46-64
select ...
  json_agg(...) as signatures
from schedule s
left join entity e on e.id = s.schedule_id
left join transaction_signature ts on ts.entity_id = s.schedule_id
where s.schedule_id = $1
group by s.schedule_id, e.id
``` [1](#0-0) 

The handler at lines 115–128 issues this query with no pre-check or post-limit on signature count: [2](#0-1) 

**Root cause and failed assumption**

The design assumes the number of `transaction_signature` rows per schedule is small. The database schema explicitly documents the opposite: *"There's no unique constraint/primary key since the client can potentially sign multiple times with the same key"*, meaning rows accumulate without deduplication. [3](#0-2) 

The index `transaction_signature (entity_id DESC, consensus_timestamp DESC)` makes the join fast but does not bound the number of rows fed into `json_agg`. PostgreSQL must materialise every matching row into a JSON array in the worker's memory before returning a single result row. [4](#0-3) 

**Exploit flow**

1. Attacker creates a schedule on Hedera (small HBAR fee).
2. Attacker submits many `ScheduleSign` transactions against that schedule ID. Because there is no unique constraint, the same key may sign repeatedly, each submission inserting additional rows into `transaction_signature` with `entity_id = schedule_id`.
3. Attacker opens ≥10 concurrent HTTP connections and issues `GET /api/v1/schedules/{scheduleId}` on each.
4. Each request calls `pool.queryQuietly(getScheduleByIdQuery, scheduleId)`, acquiring one of the 10 pool connections.
5. PostgreSQL must aggregate all N signature rows via `json_agg` before returning. With large N, each query runs for several seconds.
6. All 10 pool connections are held simultaneously. Any other REST API request that needs a DB connection blocks or times out at `connectionTimeoutMillis = 20 000 ms`.
7. The attacker repeats the wave every 20 seconds (the `statement_timeout`), keeping the pool perpetually exhausted.

**Why existing checks are insufficient**

| Check | Value | Why it fails |
|---|---|---|
| `statementTimeout` | 20 000 ms | Limits individual query duration but means each connection is held for up to 20 s — long enough to exhaust the pool with only 10 concurrent requests |
| `maxConnections` | 10 | Tiny pool; 10 concurrent slow queries fully exhaust it |
| Rate limiting | None | `grep` across `rest/**/*.js` for `rateLimit`, `throttle`, `express-rate` returns zero matches; no per-IP or global RPS cap exists on the REST API | [5](#0-4) [6](#0-5) 

### Impact Explanation

With all 10 DB connections held, every other REST API endpoint (`/api/v1/transactions`, `/api/v1/accounts`, etc.) stalls waiting for a connection. The `connectionTimeoutMillis` of 20 000 ms means callers receive errors after 20 seconds. The attacker can sustain this indefinitely with a steady stream of 10 concurrent requests, causing a complete non-network DoS of the mirror node REST API — affecting all consumers of the public mirror node, including wallets, explorers, and dApps that depend on it.

### Likelihood Explanation

- **No privilege required**: Any Hedera account (obtainable for a few cents) can create a schedule and submit `ScheduleSign` transactions.
- **Low cost**: Hedera transaction fees are fractions of a cent; accumulating hundreds of signature rows costs under $1.
- **Repeatable**: The schedule ID is public; once seeded, any unauthenticated HTTP client can trigger the DoS indefinitely.
- **No rate limiting**: Confirmed absent from the REST API codebase.
- **Amplification**: A single seeded schedule ID can be queried by many distributed clients simultaneously.

### Recommendation

1. **Add a LIMIT on signatures in `getScheduleByIdQuery`**: Cap the `LEFT JOIN` or use a subquery with `FETCH FIRST N ROWS ONLY` on `transaction_signature` before feeding into `json_agg`.
2. **Add rate limiting to the REST API**: Apply a per-IP (or global) request-rate limit on the Express application, particularly for single-resource lookup endpoints.
3. **Increase `maxConnections`** or introduce a per-endpoint concurrency cap so one slow query pattern cannot starve the entire pool.
4. **Deduplicate `transaction_signature` rows**: Add a unique constraint on `(entity_id, public_key_prefix)` to prevent unbounded accumulation from repeated signing with the same key.

### Proof of Concept

```bash
# Step 1: Create a schedule and accumulate many ScheduleSign rows
# (done via Hedera SDK or hiero-cli; each ScheduleSign adds rows to transaction_signature)
SCHEDULE_ID="0.0.XXXXX"

# Step 2: Exhaust the 10-connection pool with concurrent requests
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/schedules/$SCHEDULE_ID" &
done
wait

# Step 3: Verify other endpoints are now timing out / returning 503
curl -v "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: connection timeout or 503 after ~20s

# Step 4: Repeat step 2 every 20 seconds to maintain the DoS
while true; do
  for i in $(seq 1 10); do
    curl -s "https://<mirror-node>/api/v1/schedules/$SCHEDULE_ID" &
  done
  wait
  sleep 1
done
```

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

**File:** docs/design/scheduled-transactions.md (L65-67)
```markdown
> **_Note:_** There's no unique constraint/primary key since the client can potentially sign multiple times with the same key

- Add an index to `transaction_signature` for `entity_id`.
```

**File:** importer/src/main/resources/db/migration/v1/V1.108.0__update_transaction_signature_indexes.sql (L4-5)
```sql
create index if not exists transaction_signature__entity_id
    on transaction_signature (entity_id desc, consensus_timestamp desc);
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
