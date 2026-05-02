### Title
Unbounded Historical Key-Range Scan via `DISTINCT ON` Pre-Deduplication in `getHookStorageChange()` Enables Unauthenticated DB Resource Exhaustion

### Summary
Any unauthenticated caller can supply a single `timestamp` query parameter to activate the historical code path in `HookServiceImpl.getHookStorageChange()`, while omitting `key` filters so the default full key range (0x00…00 to 0xFF…FF) is used. The resulting native SQL query in `HookStorageChangeRepository.findByKeyBetweenAndTimestampBetween()` uses `SELECT DISTINCT ON (key)` which PostgreSQL must fully sort and deduplicate before applying the `LIMIT` clause, forcing the database to process every matching row regardless of the requested page size. Repeated concurrent requests against a hook with substantial historical data can drive DB CPU and memory consumption well above normal baselines.

### Finding Description

**Entry point** — `HooksController.getHookStorage()` (line 104-130):

```
@RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
        TimestampParameter[] timestamps,
@RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
```

Any non-empty `timestamp` value causes `HookStorageRequest.isHistorical()` to return `true` (line 66-68 of `HookStorageRequest.java`), routing execution to `getHookStorageChange()`.

**Default key range** — `HooksController.hookStorageChangeRequest()` (lines 167-168):

```java
var lowerBound = MIN_KEY_BYTES;   // 32 × 0x00
var upperBound = MAX_KEY_BYTES;   // 32 × 0xFF
```

When no `key` parameters are supplied, these defaults flow unchanged into the repository call.

**Service dispatch** — `HookServiceImpl.getHookStorageChange()` (lines 107-114):

```java
changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
        ownerId.getId(), hookId,
        request.getKeyLowerBound(),   // 0x00…00
        request.getKeyUpperBound(),   // 0xFF…FF
        timestampLowerBound,          // 0 (gte:0)
        timestampUpperBound,          // Long.MAX_VALUE
        page);                        // LIMIT N
```

**The SQL query** — `HookStorageChangeRepository.java` (lines 15-39):

```sql
select distinct on (key)
     owner_id, hook_id, key, value_written as "value", ...
from hook_storage_change
where owner_id = :ownerId
  and hook_id  = :hookId
  and key >= :keyLowerBound
  and key <= :keyUpperBound
  and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
```

PostgreSQL's `DISTINCT ON (key)` semantics require the engine to sort the entire qualifying result set by `(key ASC, consensus_timestamp DESC)` and deduplicate before the `LIMIT` clause is evaluated. The primary key index is `(owner_id, hook_id, key, consensus_timestamp)` (ascending). Because the desired order is `consensus_timestamp DESC` for the secondary sort, PostgreSQL cannot satisfy the mixed-direction requirement with a single forward index scan and must materialise all matching rows, sort them, then deduplicate. Only after that step does `LIMIT N` truncate the output.

**Root cause**: The application assumes `LIMIT` bounds DB work, but `DISTINCT ON` deduplication is a pre-`LIMIT` operation. There is no guard on the width of the timestamp range, no pre-query row-count check, and no rate limiting on this endpoint in the `rest-java` module.

### Impact Explanation
A hook belonging to an active account can accumulate millions of `hook_storage_change` rows over its lifetime (every EVM execution that touches storage writes a row). A single request with `timestamp=gte:0` and no key filter forces the DB to scan, sort, and deduplicate all of those rows before returning at most 100 results. With concurrent requests (trivially parallelised), DB CPU can be saturated and the connection pool exhausted, degrading or denying service to all other API consumers. The `statementTimeout` of 10 000 ms (from `hiero.mirror.restJava.db.statementTimeout`) limits each query to 10 seconds, but 10 seconds of full-table sort per request, multiplied across concurrent attackers, is sufficient to exceed a 30 % resource-consumption threshold.

### Likelihood Explanation
No authentication is required. The `ownerId` is a public Hedera entity ID discoverable via the existing accounts API. The `hookId` is enumerable via `GET /api/v1/accounts/{id}/hooks`. The attack request is a single well-formed HTTP GET with one query parameter (`timestamp=gte:0`). No brute force is needed; a modest number of concurrent connections (e.g., 10–20) is sufficient to keep the DB busy continuously. The attack is fully repeatable and requires no special tooling.

### Recommendation
1. **Enforce a maximum timestamp range width** in `HooksController.hookStorageChangeRequest()` analogous to `maxTimestampRange` used elsewhere in the REST module. Reject requests where `timestampUpperBound − timestampLowerBound` exceeds a configured ceiling (e.g., 7 days).
2. **Rewrite the query** to use a correlated subquery or lateral join that leverages the `(owner_id, hook_id, key, consensus_timestamp)` index efficiently per key, avoiding a full-table sort:
   ```sql
   SELECT DISTINCT ON (key) ... FROM hook_storage_change
   WHERE owner_id = ? AND hook_id = ?
     AND key BETWEEN ? AND ?
     AND consensus_timestamp BETWEEN ? AND ?
   ORDER BY key ASC, consensus_timestamp DESC
   LIMIT ?
   ```
   Add a **partial index** or **covering index** on `(owner_id, hook_id, key, consensus_timestamp DESC)` so PostgreSQL can satisfy the mixed-direction sort without a sort node.
3. **Add per-endpoint rate limiting** to the `rest-java` hooks storage endpoint (the existing `ThrottleConfiguration` is only wired to the `web3` module).
4. **Add a DB-level row scan limit** (e.g., via `SET LOCAL statement_timeout` per query or a `LIMIT` on an inner subquery) to cap the number of rows processed before deduplication.

### Proof of Concept

**Preconditions**: A hook `0.0.123/hooks/1` exists with a large number of historical storage changes (realistic in production after sustained hook execution activity).

**Step 1 – Discover a valid hook:**
```
GET /api/v1/accounts/0.0.123/hooks
```

**Step 2 – Trigger the expensive historical scan (repeat concurrently):**
```
GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0&limit=1
```

- `timestamp=gte:0` → `isHistorical()` = true, `timestampLowerBound` = 0, `timestampUpperBound` = `Long.MAX_VALUE`
- No `key` parameter → `keyLowerBound` = 0x00…00, `keyUpperBound` = 0xFF…FF
- `limit=1` → only 1 row returned to the caller, but the DB must sort and deduplicate **all** matching rows first

**Step 3 – Observe impact:**
Run 20 concurrent instances of Step 2 in a loop. Monitor DB CPU (`pg_stat_activity`, `pg_stat_statements`) and observe query execution times approaching the 10-second `statementTimeout`, with DB CPU sustained at elevated levels throughout the attack window. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L84-118)
```java
    private HookStorageResult getHookStorageChange(HookStorageRequest request) {
        final var page = request.getPageRequest();
        final var ownerId = entityService.lookup(request.getOwnerId());
        final long hookId = request.getHookId();

        final var keys = request.getKeys();
        final boolean requestHasKeys = !keys.isEmpty();
        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty() && requestHasKeys) {
            return new HookStorageResult(ownerId, List.of());
        }

        final var timestamp = request.getTimestamp();
        final long timestampLowerBound = timestamp.getAdjustedLowerRangeValue();
        final long timestampUpperBound = timestamp.adjustUpperBound();

        List<HookStorage> changes;

        if (requestHasKeys) {
            changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
                    ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);
        } else {
            changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
                    ownerId.getId(),
                    hookId,
                    request.getKeyLowerBound(),
                    request.getKeyUpperBound(),
                    timestampLowerBound,
                    timestampUpperBound,
                    page);
        }

        return new HookStorageResult(ownerId, changes);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L15-39)
```java
    @Query(nativeQuery = true, value = """
                    select distinct on (key)
                         owner_id,
                         hook_id,
                         key,
                         value_written       as "value",
                         consensus_timestamp as "modified_timestamp",
                         consensus_timestamp as "consensus_timestamp",
                         0                   as "created_timestamp",
                         (value_written is null or length(value_written) = 0) as "deleted"
                    from hook_storage_change
                    where owner_id = :ownerId
                      and hook_id = :hookId
                      and key >= :keyLowerBound
                      and key <= :keyUpperBound
                      and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
                    """)
    List<HookStorage> findByKeyBetweenAndTimestampBetween(
            long ownerId,
            long hookId,
            byte[] keyLowerBound,
            byte[] keyUpperBound,
            long timestampLowerBound,
            long timestampUpperBound,
            Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-130)
```java
    @GetMapping("/{hookId}/storage")
    ResponseEntity<HooksStorageResponse> getHookStorage(
            @PathVariable EntityIdParameter ownerId,
            @PathVariable @Min(0) long hookId,
            @RequestParam(name = KEY, required = false, defaultValue = "") @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    List<SlotRangeParameter> keys,
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Direction order) {

        final var request = hookStorageChangeRequest(ownerId, hookId, keys, timestamps, limit, order);
        final var hookStorageResult = hookService.getHookStorage(request);
        final var hookStorage = hookStorageMapper.map(hookStorageResult.storage());

        final var sort = Sort.by(order, KEY);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(hookStorage, pageable, HOOK_STORAGE_EXTRACTOR);

        final var hookStorageResponse = new HooksStorageResponse();
        hookStorageResponse.setHookId(hookId);
        hookStorageResponse.setLinks(links);
        hookStorageResponse.setOwnerId(hookStorageResult.ownerId().toString());
        hookStorageResponse.setStorage(hookStorage);

        return ResponseEntity.ok(hookStorageResponse);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L158-198)
```java
    private HookStorageRequest hookStorageChangeRequest(
            EntityIdParameter ownerId,
            long hookId,
            List<SlotRangeParameter> keys,
            TimestampParameter[] timestamps,
            int limit,
            Direction order) {
        final var keyFilters = new ArrayList<byte[]>();

        var lowerBound = MIN_KEY_BYTES;
        var upperBound = MAX_KEY_BYTES;

        for (final var key : keys) {
            final byte[] value = key.value();

            if (key.hasLowerBound()) {
                if (key.operator() == RangeOperator.EQ) {
                    keyFilters.add(value);
                } else if (Arrays.compareUnsigned(value, lowerBound) > 0) {
                    lowerBound = value;
                }
            } else if (key.hasUpperBound()) {
                if (Arrays.compareUnsigned(value, upperBound) < 0) {
                    upperBound = value;
                }
            }
        }

        final var bound = Bound.of(timestamps, TIMESTAMP, HookStorageChange.HOOK_STORAGE_CHANGE.CONSENSUS_TIMESTAMP);

        return HookStorageRequest.builder()
                .hookId(hookId)
                .keys(keyFilters)
                .limit(limit)
                .keyLowerBound(lowerBound)
                .keyUpperBound(upperBound)
                .order(order)
                .ownerId(ownerId)
                .timestamp(bound)
                .build();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L54-68)
```java
    public PageRequest getPageRequest() {
        Sort sort;

        if (isHistorical()) {
            sort = Sort.by(new Sort.Order(order, Constants.KEY), new Sort.Order(Direction.DESC, CONSENSUS_TIMESTAMP));
        } else {
            sort = Sort.by(order, Constants.KEY);
        }

        return PageRequest.of(0, limit, sort);
    }

    public boolean isHistorical() {
        return !timestamp.isEmpty();
    }
```

**File:** importer/src/main/resources/db/migration/v1/V1.112.1__add_hooks_support.sql (L33-43)
```sql
create table if not exists hook_storage_change
(
    consensus_timestamp bigint not null,
    hook_id             bigint not null,
    owner_id            bigint not null,
    key                 bytea  not null,
    value_read          bytea  not null,
    value_written       bytea,

    primary key (owner_id, hook_id, key, consensus_timestamp)
);
```
