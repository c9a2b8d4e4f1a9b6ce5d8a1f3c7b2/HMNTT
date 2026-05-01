### Title
Unbounded Timestamp + Key Range in `findByKeyBetweenAndTimestampBetween` Enables Unauthenticated Database Resource Exhaustion

### Summary
An unprivileged external user can call `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` with a maximum-width timestamp range and no key filters, triggering `findByKeyBetweenAndTimestampBetween()` in `HookStorageChangeRepository`. This executes a `SELECT DISTINCT ON (key)` query over the full key and timestamp range for a given owner+hook, forcing PostgreSQL to scan and sort all matching rows before applying the result `LIMIT`. No timestamp range width validation, no rate limiting, and no authentication are present in the code path.

### Finding Description

**Full code path:**

1. **Controller entry** — `HooksController.getHookStorage()` accepts `timestamp` (max 2 params, no range-width check) and `keys` (optional). With no `key=` params, `lowerBound` defaults to `MIN_KEY_BYTES` (32×`0x00`) and `upperBound` defaults to `MAX_KEY_BYTES` (32×`0xFF`). [1](#0-0) [2](#0-1) 

2. **Historical routing** — `HookServiceImpl.getHookStorage()` routes to `getHookStorageChange()` whenever `request.isHistorical()` is true, which is triggered by any non-empty timestamp parameter. [3](#0-2) 

3. **Branch selection** — Inside `getHookStorageChange()`, because no keys are provided (`requestHasKeys = false`), the code unconditionally calls `findByKeyBetweenAndTimestampBetween()` with the attacker-controlled full key range and full timestamp range. [4](#0-3) 

4. **Expensive query** — The native SQL query uses `SELECT DISTINCT ON (key)` with no narrowing on key or timestamp. PostgreSQL must scan and sort **all rows** matching `owner_id`, `hook_id`, and the timestamp range before it can apply the `LIMIT` from `Pageable`. The `LIMIT` only restricts returned rows, not the internal sort/scan work. [5](#0-4) 

**Root cause:** No validation exists on the width of the timestamp range. The `@Size(max = 2)` annotation on `timestamps` only limits the number of timestamp parameters, not the span they cover. The `@Max(MAX_LIMIT)` on `limit` only caps returned rows, not DB work. There is no authentication guard on the endpoint. [6](#0-5) 

### Impact Explanation
For any `owner_id`/`hook_id` pair with a large number of historical storage change records, each such request forces a full sequential scan + sort of all matching rows in `hook_storage_change`. Multiple concurrent requests from one or more attackers can saturate DB CPU and I/O, degrading or denying service to all other users. The impact is proportional to the number of rows stored per hook, which grows over time as the network processes transactions.

### Likelihood Explanation
The endpoint requires no authentication or API key. Any external user who can discover a valid `ownerId`/`hookId` pair (trivially enumerable via the `GET /api/v1/accounts/{ownerId}/hooks` endpoint) can immediately issue the attack. The request is a single standard HTTP GET with two query parameters. It is trivially scriptable and repeatable at high frequency.

### Recommendation
1. **Enforce a maximum timestamp range width**: Reject requests where `timestampUpperBound - timestampLowerBound` exceeds a configured maximum (e.g., 24 hours in nanoseconds).
2. **Require at least one timestamp bound to be recent**: Reject queries where the upper timestamp bound is more than N hours in the past, limiting historical scan depth.
3. **Add rate limiting** per IP and/or per `ownerId`/`hookId` at the controller or gateway layer.
4. **Ensure a covering index** on `hook_storage_change(owner_id, hook_id, key, consensus_timestamp DESC)` so `DISTINCT ON (key)` can use an index scan rather than a full sort.

### Proof of Concept

```
# Step 1: Discover a valid ownerId and hookId (unauthenticated)
GET /api/v1/accounts/0.0.1234/hooks

# Step 2: Issue the exhausting query with max timestamp and key range
GET /api/v1/accounts/0.0.1234/hooks/1/storage?timestamp=gte:0.000000000&timestamp=lte:9999999999.999999999&limit=1

# Repeat in a loop or with concurrent threads:
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1234/hooks/1/storage?timestamp=gte:0.000000000&timestamp=lte:9999999999.999999999&limit=1" &
done
```

Each request triggers `SELECT DISTINCT ON (key) ... FROM hook_storage_change WHERE owner_id=1234 AND hook_id=1 AND key >= '\x0000...00' AND key <= '\xFFFF...FF' AND consensus_timestamp BETWEEN 0 AND 9999999999999999999`, forcing a full scan and sort of all rows for that hook. Concurrent requests compound DB load, achieving the >30% resource consumption threshold without brute force.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L61-73)
```java
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-113)
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L56-59)
```java
    public HookStorageResult getHookStorage(HookStorageRequest request) {
        if (request.isHistorical()) {
            return getHookStorageChange(request);
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L103-115)
```java
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
