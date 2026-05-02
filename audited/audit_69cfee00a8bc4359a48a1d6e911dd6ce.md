### Title
Unbounded Timestamp Range in `findByKeyBetweenAndTimestampBetween()` Enables Database Resource Exhaustion via DISTINCT ON Scan

### Summary
The `getHookStorageChange()` method in `HookServiceImpl` passes user-controlled timestamp bounds directly to a native SQL query using `DISTINCT ON (key)` with no maximum timestamp range enforcement. An unprivileged user can supply a single open-ended timestamp parameter (e.g., `timestamp=gte:1`), causing the upper bound to default to `Long.MAX_VALUE` and forcing PostgreSQL to scan every row for the given `(owner_id, hook_id)` pair across all time partitions before applying DISTINCT, consuming excessive database CPU and memory.

### Finding Description

**Exact code path:**

In `HooksController.java` (line 110), the `timestamps` parameter accepts at most 2 values (`@Size(max = 2)`) but imposes no range width constraint: [1](#0-0) 

`Bound.of()` is called with `primarySortField=false`, which means the constructor skips the `adjustedLower > adjustedUpper` validation: [2](#0-1) 

When only a lower-bound timestamp is supplied (e.g., `timestamp=gte:1`), `adjustUpperBound()` returns `Long.MAX_VALUE` because `upper` is null: [3](#0-2) 

These unbounded values are passed directly to `findByKeyBetweenAndTimestampBetween()`: [4](#0-3) 

The native SQL query uses `DISTINCT ON (key)` without a `LIMIT` applied before the DISTINCT operation. PostgreSQL must materialize and sort **all** rows matching the WHERE clause before it can emit the first distinct key: [5](#0-4) 

The table's primary key is `(owner_id, hook_id, key, consensus_timestamp)`: [6](#0-5) 

The table is partitioned by `consensus_timestamp` in v2, meaning a full-range scan crosses all partitions: [7](#0-6) 

**Root cause:** The REST Java API has no equivalent of the REST JS `maxTimestampRange` (7d) guard. The `Bound` class for timestamp in this path performs no width validation. The `limit` parameter (capped at 100) controls only the final output rows, not the intermediate result set that DISTINCT ON must process. [8](#0-7) 

### Impact Explanation

A single request with `timestamp=gte:1` and no key filter causes the database to scan every `hook_storage_change` row for the target `(owner_id, hook_id)` pair — potentially millions of rows across all time partitions — sort them by `(key, consensus_timestamp DESC)`, and apply DISTINCT. Repeated concurrent requests exhaust database CPU and connection pool resources, degrading service for all users. There is no per-user rate limiting on the hooks endpoint in rest-java (the `ThrottleManager` exists only in the web3 module). [9](#0-8) 

### Likelihood Explanation

The endpoint requires no authentication. The attacker only needs a valid `ownerId` and `hookId`, both of which are enumerable via the public hooks listing API. The exploit requires a single HTTP GET request. The only mitigating control is the `statementTimeout` of 10,000 ms, which limits individual query duration but does not prevent concurrent request flooding that saturates the connection pool. [10](#0-9) 

### Recommendation

1. **Enforce a maximum timestamp range** in `HookServiceImpl.getHookStorageChange()` or in the `Bound` class when `primarySortField=false` for the timestamp parameter on this endpoint. Reject or cap requests where `timestampUpperBound - timestampLowerBound` exceeds a configured maximum (e.g., 7 days, matching the REST JS `maxTimestampRange`).
2. **Require both a lower and upper timestamp bound** when the historical path is triggered, preventing open-ended ranges that default to `Long.MAX_VALUE`.
3. **Add rate limiting** to the hooks storage endpoint in rest-java, analogous to the `ThrottleManager` in the web3 module.
4. Consider rewriting the query to use a `LATERAL` or window-function approach that can leverage the primary key index `(owner_id, hook_id, key, consensus_timestamp)` to fetch the latest value per key without a full sort of the intermediate result set.

### Proof of Concept

```
# Step 1: Identify a valid ownerId and hookId via the public hooks listing
GET /api/v1/accounts/0.0.123/hooks

# Step 2: Send a maximally wide historical storage query (no upper timestamp bound)
GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:1

# This sets:
#   keyLowerBound  = 0x0000...0000 (MIN_KEY_BYTES, 32 zero bytes)
#   keyUpperBound  = 0xFFFF...FFFF (MAX_KEY_BYTES, 32 0xFF bytes)
#   timestampLowerBound = 1
#   timestampUpperBound = Long.MAX_VALUE (9223372036854775807)
#
# PostgreSQL executes:
#   SELECT DISTINCT ON (key) ... FROM hook_storage_change
#   WHERE owner_id = 123 AND hook_id = 1
#     AND key >= '\x00...' AND key <= '\xFF...'
#     AND consensus_timestamp BETWEEN 1 AND 9223372036854775807
#
# Result: full table scan across all time partitions for this (owner_id, hook_id),
# sort of all matching rows, then DISTINCT applied.

# Step 3: Repeat concurrently to exhaust DB connections and CPU
for i in $(seq 1 50); do
  curl -s "http://mirror-node/api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:1" &
done
wait
```

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-74)
```java
    public long adjustUpperBound() {
        if (this.upper == null) {
            return Long.MAX_VALUE;
        }

        long upperBound = this.upper.value();
        if (this.upper.operator() == RangeOperator.LT) {
            upperBound--;
        }

        return upperBound;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L169-182)
```java
    public static Bound of(TimestampParameter[] timestamp, String parameterName, Field<Long> field) {
        if (timestamp == null || timestamp.length == 0) {
            return Bound.EMPTY;
        }

        for (int i = 0; i < timestamp.length; ++i) {
            final var param = timestamp[i];
            if (param.operator() == RangeOperator.EQ) {
                timestamp[i] = new TimestampParameter(RangeOperator.LTE, param.value());
            }
        }

        return new Bound(timestamp, false, parameterName, field);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L97-114)
```java
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

**File:** importer/src/main/resources/db/migration/v2/V2.17.1__add_hooks_support.sql (L36-54)
```sql
-- Hook storage change table (historical changes)
create table if not exists hook_storage_change
(
    consensus_timestamp bigint not null,
    hook_id             bigint not null,
    owner_id            bigint not null,
    key                 bytea  not null,
    value_read          bytea  not null,
    value_written       bytea,

    primary key (owner_id, hook_id, key, consensus_timestamp)
) partition by range (consensus_timestamp);
comment on table hook_storage_change is 'Historical changes to hook storage state';

select create_distributed_table('hook_storage_change', 'owner_id', colocate_with => 'entity');
select create_time_partitions(table_name :='public.hook_storage_change',
                              partition_interval := ${partitionTimeInterval},
                              start_from := ${partitionStartDate}::timestamptz,
                              end_at := CURRENT_TIMESTAMP + ${partitionTimeInterval});
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L33-36)
```java
    // Defaults and constraints
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```

**File:** docs/configuration.md (L630-630)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```
