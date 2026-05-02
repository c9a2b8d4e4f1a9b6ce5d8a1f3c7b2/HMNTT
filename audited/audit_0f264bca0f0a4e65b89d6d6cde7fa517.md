### Title
Unbounded Timestamp Range in Historical Hook Storage Query Enables Database Griefing

### Summary
An unprivileged user can call `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` with a single open-ended timestamp parameter (e.g., `timestamp=gte:0`) and no `key` filters, causing `getHookStorageChange()` to invoke `findByKeyBetweenAndTimestampBetween()` with `timestampLowerBound=0` and `timestampUpperBound=Long.MAX_VALUE` and key bounds spanning the full 32-byte key space. This forces PostgreSQL to evaluate a `DISTINCT ON (key)` over the entire `hook_storage_change` table partition for the given `owner_id`/`hook_id`, which can be expensive and repeatable with no authentication required.

### Finding Description

**Exact code path:**

`HooksController.getHookStorage()` (line 104–130) accepts `timestamps` with only `@Size(max = 2)` — no constraint on range width. It calls `hookStorageChangeRequest()` (line 158–198), which calls `Bound.of(timestamps, ...)` (line 186).

In `Bound.java`:
- `getAdjustedLowerRangeValue()` returns `0` when `lower == null` (line 87–89).
- `adjustUpperBound()` returns `Long.MAX_VALUE` when `upper == null` (line 63–66).

So providing only `timestamp=gte:0` sets `lower` to a `GT:0` parameter (adjusted to 1) and leaves `upper == null` → `timestampUpperBound = Long.MAX_VALUE`. Providing only `timestamp=lte:99999999999` sets `lower == null` → `timestampLowerBound = 0`.

In `HookServiceImpl.getHookStorageChange()` (line 84–118):

```java
// line 93: keys.isEmpty() && !requestHasKeys → false, so falls through to:
// line 107–114:
changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
    ownerId.getId(), hookId,
    request.getKeyLowerBound(),   // MIN_KEY_BYTES: 32×0x00
    request.getKeyUpperBound(),   // MAX_KEY_BYTES: 32×0xFF
    timestampLowerBound,          // 0
    timestampUpperBound,          // Long.MAX_VALUE
    page);
```

The resulting SQL (lines 15–31 of `HookStorageChangeRepository.java`):

```sql
SELECT DISTINCT ON (key) ...
FROM hook_storage_change
WHERE owner_id = :ownerId
  AND hook_id  = :hookId
  AND key >= '\x0000...00'   -- all keys match
  AND key <= '\xffff...ff'   -- all keys match
  AND consensus_timestamp BETWEEN 0 AND 9223372036854775807  -- all time
```

The `key` range filter is fully open (MIN to MAX), and the timestamp filter covers all history. PostgreSQL must evaluate `DISTINCT ON (key)` across every row for the given `owner_id`/`hook_id` before applying the `LIMIT`. Without a covering index ordered as `(owner_id, hook_id, key, consensus_timestamp DESC)`, this degrades to a sort of all matching rows.

**Failed assumption:** The code assumes callers will provide a meaningful, narrow timestamp range. There is no server-side validation enforcing a maximum range width or requiring both a lower and upper timestamp bound.

### Impact Explanation

For any hook with a large number of historical storage changes, each such request forces a full partition scan + sort on `hook_storage_change`. Because the endpoint is public (no `@PreAuthorize` or authentication annotation visible in the controller), any external actor can issue these requests. Repeated concurrent requests against a popular hook can saturate database I/O and CPU, degrading service for all users. The scope is limited to a single `(owner_id, hook_id)` pair per request, but an attacker can target multiple hooks simultaneously.

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond a valid `ownerId` and `hookId` (both discoverable via the public `GET /api/v1/accounts/{ownerId}/hooks` endpoint), and a single HTTP parameter (`timestamp=gte:0`). It is trivially scriptable and repeatable. Rate limiting is not visible in the controller code.

### Recommendation

1. **Require both bounds:** Reject requests where `isHistorical()` is true but only one timestamp bound is provided, or enforce a maximum allowed range (e.g., 90 days).
2. **Enforce a maximum timestamp range width:** In `hookStorageChangeRequest()` or `getHookStorageChange()`, compute `timestampUpperBound - timestampLowerBound` and throw `IllegalArgumentException` if it exceeds a configured threshold.
3. **Database index:** Ensure a covering index on `(owner_id, hook_id, key, consensus_timestamp DESC)` exists so that `DISTINCT ON (key) ORDER BY key, consensus_timestamp DESC LIMIT N` can be satisfied via an index scan rather than a full sort.
4. **Rate limiting:** Apply per-IP or per-account rate limiting on the `/hooks/{hookId}/storage` endpoint.

### Proof of Concept

```
# Step 1: Discover a valid hookId (public endpoint)
GET /api/v1/accounts/0.0.1234/hooks

# Step 2: Trigger full-history scan with no key filter and open-ended timestamp
GET /api/v1/accounts/0.0.1234/hooks/1/storage?timestamp=gte:0&limit=100

# Repeat in a loop to sustain database load:
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1234/hooks/1/storage?timestamp=gte:0&limit=100" &
done
```

This causes `findByKeyBetweenAndTimestampBetween()` to execute with `timestampLowerBound=1`, `timestampUpperBound=Long.MAX_VALUE`, `keyLowerBound=MIN_KEY_BYTES`, `keyUpperBound=MAX_KEY_BYTES` — scanning the full history for that hook on every request. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-96)
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
