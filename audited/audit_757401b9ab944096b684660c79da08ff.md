### Title
Unbounded Historical Timestamp Range in `getHookStorageChange` Enables Unauthenticated DB Resource Exhaustion

### Summary
The private `getHookStorageChange` method in `HookServiceImpl` passes attacker-controlled timestamp bounds directly to native SQL queries using `DISTINCT ON (key)` against the `hook_storage_change` table. When no upper timestamp bound is supplied, `Bound.adjustUpperBound()` defaults to `Long.MAX_VALUE`, forcing PostgreSQL to scan every row for the targeted `(owner_id, hook_id)` pair before applying the `LIMIT`. No rate limiting exists on this endpoint in the `rest-java` module, allowing any unauthenticated caller to flood the database with expensive scans.

### Finding Description

**Code path:**

`HooksController` → `HookService.getHookStorage()` → `HookServiceImpl.getHookStorageChange()` (line 84) → `HookStorageChangeRepository.findByKeyBetweenAndTimestampBetween()` (line 107–114).

**Root cause 1 – Unbounded timestamp defaults:**

In `Bound.java`:
```java
public long adjustUpperBound() {
    if (this.upper == null) {
        return Long.MAX_VALUE;   // no cap
    }
    ...
}
public long getAdjustedLowerRangeValue() {
    if (this.lower == null) {
        return 0;                // epoch 0
    }
    ...
}
```
A caller supplying only `timestamp=gte:0` (or any single lower-bound operator) gets `timestampLowerBound = 0` and `timestampUpperBound = Long.MAX_VALUE`. [1](#0-0) 

**Root cause 2 – `DISTINCT ON` must materialise the full matching set before LIMIT:**

```sql
select distinct on (key)
     ...
from hook_storage_change
where owner_id = :ownerId
  and hook_id  = :hookId
  and key >= :keyLowerBound
  and key <= :keyUpperBound
  and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
```
PostgreSQL's `DISTINCT ON (key)` requires sorting and deduplicating **all** rows that satisfy the WHERE clause before the `LIMIT` clause is applied. With `consensus_timestamp BETWEEN 0 AND 9223372036854775807` and the default key range of `0x00…00` to `0xFF…FF` (set by the controller), every historical row for the targeted hook is read. [2](#0-1) 

**Root cause 3 – No rate limiting on the `rest-java` hook storage endpoint:**

The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` module and is not wired into `HooksController`. [3](#0-2) 

**Root cause 4 – No authentication:**

`HooksController` is a plain `@RestController` with no security annotation or filter. Any unauthenticated HTTP client can call `/api/v1/accounts/{ownerId}/hooks/{hookId}/storage?timestamp=gte:0`. [4](#0-3) 

**Why the primary-key index does not save you:**

The table's PK is `(owner_id, hook_id, key, consensus_timestamp)`. The index efficiently narrows to a specific `(owner_id, hook_id)` partition, but the `consensus_timestamp BETWEEN 0 AND MAX` predicate is a residual filter on the 4th index column, so every key-version row for that hook is visited. For an active hook with millions of storage-change records this is a full per-hook index scan, not a full-table scan, but the cost is proportional to the hook's entire history. [5](#0-4) 

### Impact Explanation

An attacker who identifies even one high-activity `(ownerId, hookId)` pair (all data is public on-chain) can issue concurrent GET requests with `timestamp=gte:0` and the default full key range. Each request forces a full per-hook index scan plus an in-memory sort/dedup for `DISTINCT ON`. With no rate limiting, tens of concurrent connections can saturate DB CPU and I/O, degrading or denying service to all other mirror-node consumers. The `LIMIT 100` cap only reduces result serialisation cost; it does not reduce the scan cost.

### Likelihood Explanation

- **Precondition**: zero — no account, API key, or privileged access required.
- **Discovery**: `ownerId` and `hookId` are public blockchain identifiers enumerable from the `/api/v1/accounts/{id}/hooks` endpoint.
- **Repeatability**: a simple shell loop or any HTTP load tool suffices; no cryptographic material or protocol knowledge needed.
- **Amplification**: the `hook_storage_change` table grows continuously as hooks execute; the attack becomes cheaper to sustain over time.

### Recommendation

1. **Cap the timestamp range**: reject or clamp requests where `timestampUpperBound - timestampLowerBound` exceeds a configurable maximum (e.g., 30 days in nanoseconds) inside `getHookStorageChange`, mirroring the `bindTimestampRange` guard used in the Node.js REST layer.
2. **Require both bounds for historical queries**: if `timestamp` is present but only one side is supplied, return HTTP 400.
3. **Add per-IP or global rate limiting** to the `rest-java` hook storage endpoint, analogous to `ThrottleManagerImpl` in the `web3` module.
4. **Add a covering index** on `(owner_id, hook_id, key, consensus_timestamp DESC)` so that `DISTINCT ON (key) ORDER BY key, consensus_timestamp DESC` can be satisfied by an index-only scan with early termination per key, eliminating the need to read all versions.

### Proof of Concept

```bash
# Enumerate a valid (ownerId, hookId) pair from the public API
curl "https://<mirror-node>/api/v1/accounts/0.0.1234/hooks"

# Fire concurrent historical scans with unbounded timestamp range
for i in $(seq 1 50); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1234/hooks/5678/storage?timestamp=gte:0" &
done
wait
```

Each concurrent request triggers `findByKeyBetweenAndTimestampBetween` with `timestampLowerBound=0`, `timestampUpperBound=Long.MAX_VALUE`, `keyLowerBound=0x00…00`, `keyUpperBound=0xFF…FF`, forcing PostgreSQL to scan and sort the entire history of hook `5678` for every request simultaneously. [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-97)
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

    public RangeParameter<Long> adjustLowerRange() {
        if (this.hasEqualBounds()) {
            // If the primary param has a range with a single value, rewrite it to EQ
            lower = new NumberRangeParameter(EQ, this.getAdjustedLowerRangeValue());
            upper = null;
        }

        return lower;
    }

    public long getAdjustedLowerRangeValue() {
        if (this.lower == null) {
            return 0;
        }

        long lowerBound = this.lower.value();
        if (this.lower.operator() == RangeOperator.GT) {
            lowerBound++;
        }

        return lowerBound;
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L54-103)
```java
@NullMarked
@RequestMapping(value = "/api/v1/accounts/{ownerId}/hooks", produces = APPLICATION_JSON)
@RequiredArgsConstructor
@RestController
final class HooksController {

    private static final int KEY_BYTE_LENGTH = 32;
    private static final byte[] MIN_KEY_BYTES = new byte[KEY_BYTE_LENGTH]; // A 32-byte array of 0x00
    private static final byte[] MAX_KEY_BYTES;

    private static final Function<Hook, Map<String, String>> HOOK_EXTRACTOR =
            hook -> ImmutableSortedMap.of(HOOK_ID, hook.getHookId().toString());

    private static final Function<HookStorage, Map<String, String>> HOOK_STORAGE_EXTRACTOR =
            hook -> ImmutableSortedMap.of(KEY, hook.getKey());

    static {
        MAX_KEY_BYTES = new byte[KEY_BYTE_LENGTH];
        Arrays.fill(MAX_KEY_BYTES, (byte) 0xFF); // A 32-byte array of 0xFF
    }

    private final HookService hookService;
    private final HookMapper hookMapper;
    private final HookStorageMapper hookStorageMapper;
    private final LinkFactory linkFactory;

    @GetMapping
    ResponseEntity<HooksResponse> getHooks(
            @PathVariable EntityIdParameter ownerId,
            @RequestParam(defaultValue = "", name = HOOK_ID, required = false)
                    @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    NumberRangeParameter[] hookId,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "desc") Sort.Direction order) {

        final var hooksRequest = hooksRequest(ownerId, hookId, limit, order);
        final var hooksServiceResponse = hookService.getHooks(hooksRequest);
        final var hooks = hookMapper.map(hooksServiceResponse);

        final var sort = Sort.by(order, HOOK_ID);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(hooks, pageable, HOOK_EXTRACTOR);

        final var response = new HooksResponse();
        response.setHooks(hooks);
        response.setLinks(links);

        return ResponseEntity.ok(response);
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
