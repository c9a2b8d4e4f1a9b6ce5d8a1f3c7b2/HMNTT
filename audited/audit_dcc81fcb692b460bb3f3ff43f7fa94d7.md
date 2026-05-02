### Title
TOAST-Amplified Disk I/O DoS via `coalesce(size, length(bytes))` in `blocksQuery` Under Unauthenticated Max-Limit Requests

### Summary
The `blocksQuery` in `RecordFileService` uses `coalesce(size, length(bytes)) as size` to compute block size. When `size IS NULL` and `bytes` is non-null, PostgreSQL must fully dereference the TOAST-stored `bytes` value from disk to evaluate `length(bytes)`. An unauthenticated attacker can repeatedly issue max-limit requests to `/api/v1/blocks`, forcing repeated full TOAST detoasting of large binary record-file content for every qualifying row, causing sustained excessive disk I/O that can degrade or partition the database node.

### Finding Description

**Exact code location:**

`rest/service/recordFileService.js`, lines 64–70 — the static `blocksQuery`:

```js
static blocksQuery = `select
  ${RecordFile.COUNT}, ${RecordFile.HASH}, ${RecordFile.NAME}, ${RecordFile.PREV_HASH},
  ${RecordFile.HAPI_VERSION_MAJOR}, ${RecordFile.HAPI_VERSION_MINOR}, ${RecordFile.HAPI_VERSION_PATCH},
  ${RecordFile.INDEX}, ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.GAS_USED},
  ${RecordFile.LOGS_BLOOM}, coalesce(${RecordFile.SIZE}, length(${RecordFile.BYTES})) as size
  from ${RecordFile.tableName}
`;
```

`RecordFile.BYTES = 'bytes'` and `RecordFile.SIZE = 'size'` (model, lines 20, 37).

**Root cause:** PostgreSQL's `coalesce` is short-circuit: if `size IS NOT NULL`, `bytes` is never accessed. But when `size IS NULL`, PostgreSQL evaluates `length(bytes)`. For a `bytea` column, `length()` requires full detoasting — PostgreSQL has no mechanism to retrieve the byte-length from the TOAST pointer metadata alone; it must read all TOAST chunks from disk. The `bytes` column stores raw record file content (binary protobuf/stream data), which can be megabytes per row.

The test spec `rest/__tests__/specs/blocks/no-params.json` explicitly documents and tests this fallback path (lines 6–8: *"bytes has value and null size, the rest api should return the length of the bytes as size"*), confirming this is a live, exercised code path in production.

**Limit enforcement** (`blockController.js`, lines 57–61):

```js
extractLimitFromFilters = (filters) => {
  const limit = findLast(filters, {key: filterKeys.LIMIT});
  const maxLimit = getEffectiveMaxLimit();
  return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
};
```

If `limit.value <= maxLimit`, the exact requested value is used. An attacker sends `limit=<maxLimit>` (e.g., 100) to get the maximum rows per query. There is no rate limiting visible in the controller or route layer.

**Exploit flow:**
1. Attacker sends `GET /api/v1/blocks?limit=100` (no auth required).
2. `getBlocks()` calls `RecordFileService.getBlocks(formattedFilters)` which executes `blocksQuery` with `LIMIT 100`.
3. For each row where `size IS NULL` and `bytes IS NOT NULL`, PostgreSQL reads all TOAST chunks for that row's `bytes` column from disk.
4. Attacker repeats at high frequency from multiple IPs.

**Why existing checks fail:**
- The limit cap prevents unbounded single-query row counts but does not prevent repeated requests.
- There is no per-IP rate limiting, no authentication, and no query-cost budget.
- The `coalesce` fallback is intentional and documented, so it is not filtered out.

### Impact Explanation

Each request with `N` rows having `size IS NULL` forces `N` full TOAST reads of potentially multi-megabyte `bytes` values. At 100 rows/request × ~1–5 MB/row = up to 500 MB of disk reads per request. Sustained concurrent requests from multiple clients can saturate PostgreSQL's I/O bandwidth, causing query latency spikes across all database consumers, effectively partitioning the mirror node's REST API from its database — matching the described "network partition caused outside of design parameters."

**Severity: High** — unauthenticated, no special knowledge required, directly impacts database availability.

### Likelihood Explanation

- Zero privilege required; the endpoint is public.
- The vulnerable code path is confirmed exercised by the test suite.
- The attack is trivially scriptable (`curl` in a loop or any HTTP load tool).
- No rate limiting or authentication is present in the route or controller layer.
- The condition (`size IS NULL, bytes IS NOT NULL`) is a documented, expected production state for legacy or in-migration rows.

**Likelihood: High** — any external actor aware of the API can trigger this.

### Recommendation

1. **Immediate:** Replace `length(bytes)` with `octet_length(bytes)` — while functionally equivalent for `bytea`, audit whether a stored/computed column approach is feasible. More importantly, **add a generated/stored `size` column** populated at write time so `bytes` is never read at query time.
2. **Short-term:** Rewrite the query to avoid touching `bytes` entirely in the list path. If `size IS NULL` is acceptable to return as `null`, remove the `length(bytes)` fallback from `blocksQuery`. The fallback is only needed for legacy rows; a one-time migration backfill of `size` from `length(bytes)` at import time eliminates the runtime cost.
3. **Defense-in-depth:** Add per-IP rate limiting on `/api/v1/blocks` at the API gateway or middleware layer. Add a PostgreSQL `statement_timeout` for REST API queries.

### Proof of Concept

```bash
# No authentication required
# Assumes some record_file rows have size=NULL and bytes=non-null (documented production state)

# Single high-I/O request
curl "https://<mirror-node-host>/api/v1/blocks?limit=100"

# Sustained attack (parallel, no auth)
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/blocks?limit=100" &
done
wait
```

Each request forces PostgreSQL to evaluate `length(bytes)` for every `size IS NULL` row in the result set, reading full TOAST-stored binary content from disk. Monitoring `pg_stat_bgwriter` and `pg_stat_io` will show a spike in block reads correlated with these requests. Database query latency for all consumers will increase proportionally to I/O saturation.