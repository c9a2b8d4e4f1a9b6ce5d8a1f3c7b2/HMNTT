### Title
Unbounded Timestamp Range Scan in `getHookStorage()` Enables Unauthenticated DoS via Full `hook_storage_change` Table Scan

### Summary
An unauthenticated user can supply `timestamp=gte:0` with no `key` filter to `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage`, causing `getHookStorageChange()` to issue a `DISTINCT ON (key)` query against `hook_storage_change` with `consensus_timestamp BETWEEN 0 AND Long.MAX_VALUE` and key bounds spanning the full 32-byte key space. There is no timestamp range cap or rate limiting in the rest-java path. Flooding with concurrent requests exhausts the database connection pool and degrades or denies service to the mirror node API.

### Finding Description

**Step 1 — `isHistorical()` is triggered by `timestamp=gte:0`**

In `HooksController.getHookStorage()`, the `timestamps` array is passed to `Bound.of()`: [1](#0-0) 

`Bound.of()` with a single `GTE:0` parameter sets `lower = TimestampParameter(GTE, 0)` and leaves `upper = null`: [2](#0-1) 

`Bound.isEmpty()` returns `false` because `lower != null`: [3](#0-2) 

So `HookStorageRequest.isHistorical()` returns `true`: [4](#0-3) 

**Step 2 — No key filter bypasses the early-return guard**

In `HookServiceImpl.getHookStorageChange()`, the only early-return guard is: [5](#0-4) 

This fires only when `requestHasKeys == true` AND `keysInRange` is empty. With no `key` parameter, `requestHasKeys = false`, so the guard is skipped entirely.

**Step 3 — Widest possible bounds are computed**

`getAdjustedLowerRangeValue()` with `GTE:0` returns `0`: [6](#0-5) 

`adjustUpperBound()` with `upper == null` returns `Long.MAX_VALUE`: [7](#0-6) 

Key bounds default to `MIN_KEY_BYTES` (all zeros) and `MAX_KEY_BYTES` (all `0xFF`): [8](#0-7) 

**Step 4 — Full-range query is issued**

`findByKeyBetweenAndTimestampBetween` is called with these maximal bounds: [9](#0-8) 

The resulting SQL is: [10](#0-9) 

`DISTINCT ON (key)` with `consensus_timestamp BETWEEN 0 AND 9223372036854775807` forces PostgreSQL to scan every historical change row for the given `owner_id`/`hook_id` to resolve the latest value per key. The `LIMIT` from `Pageable` caps returned rows at 100, but does not prevent the full index scan needed to satisfy `DISTINCT ON`.

**Step 5 — No mitigating controls in the rest-java path**

- No authentication or authorization on the endpoint.
- No timestamp range cap (contrast with `NetworkServiceImpl` which explicitly caps and validates timestamp ranges).
- No rate limiting in the rest-java stack (the `authHandler.js` rate limiting exists only in the Node.js REST module).
- The `statementTimeout` default of 10 seconds per the configuration provides partial protection but does not prevent concurrent connection exhaustion. [11](#0-10) 

### Impact Explanation
An attacker flooding this endpoint with concurrent requests forces repeated full-range `DISTINCT ON` scans against `hook_storage_change`. Each request holds a database connection for up to the statement timeout (10 s by default). With enough concurrent requests, the database connection pool is exhausted, causing all mirror node API requests (including unrelated endpoints) to queue or fail. The mirror node is a read-only service and does not participate in Hedera consensus, so this does not cause "total network shutdown" in the consensus sense; however, it does cause complete denial of service of the mirror node REST API, which is the primary data access layer for applications, explorers, and wallets querying Hedera state.

### Likelihood Explanation
The endpoint requires no credentials. The attacker only needs a valid `ownerId` (any Hedera account ID, publicly enumerable) and a valid `hookId` (discoverable via `GET /api/v1/accounts/{ownerId}/hooks`). The attack payload is a single HTTP GET with `?timestamp=gte:0`. It is trivially scriptable and repeatable from any HTTP client. No special knowledge of the system internals is required.

### Recommendation
1. **Enforce a maximum timestamp range** in `getHookStorageChange()` analogous to the `maxTimestampRange` enforcement in other endpoints. Reject or cap requests where `timestampUpperBound - timestampLowerBound` exceeds a configured maximum (e.g., 7 days in nanoseconds).
2. **Require an upper timestamp bound** when no key filter is provided, preventing open-ended historical scans.
3. **Add rate limiting** to the rest-java controller layer (e.g., via a Spring `HandlerInterceptor` or a gateway-level policy) for unauthenticated callers.
4. **Validate that `timestamp=gte:0` without an upper bound is rejected** or automatically capped to a sensible window.

### Proof of Concept
```
# Discover a valid ownerId and hookId
GET /api/v1/accounts/0.0.1234/hooks

# Trigger full-range scan (no authentication required)
GET /api/v1/accounts/0.0.1234/hooks/2000/storage?timestamp=gte:0

# Flood concurrently to exhaust DB connections
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1234/hooks/2000/storage?timestamp=gte:0" &
done
wait
```
Each request issues `SELECT DISTINCT ON (key) ... FROM hook_storage_change WHERE owner_id=? AND hook_id=? AND key >= '\x00...' AND key <= '\xff...' AND consensus_timestamp BETWEEN 0 AND 9223372036854775807`, holding a DB connection for up to 10 seconds. With 500 concurrent requests, the connection pool is exhausted and all subsequent API requests fail.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L110-112)
```java
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L39-61)
```java
    public Bound(RangeParameter<Long>[] params, boolean primarySortField, String parameterName, Field<Long> field) {
        this.field = field;
        this.parameterName = parameterName;

        if (ArrayUtils.isEmpty(params)) {
            return;
        }

        for (var param : params) {
            if (param.hasLowerBound()) {
                lower = param;
            } else if (param.hasUpperBound()) {
                upper = param;
            }
            cardinality.merge(param.operator(), 1, Math::addExact);
        }

        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L86-97)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L126-128)
```java
    public boolean isEmpty() {
        return lower == null && upper == null;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L66-68)
```java
    public boolean isHistorical() {
        return !timestamp.isEmpty();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L93-95)
```java
        if (keysInRange.isEmpty() && requestHasKeys) {
            return new HookStorageResult(ownerId, List.of());
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L107-114)
```java
            changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
                    ownerId.getId(),
                    hookId,
                    request.getKeyLowerBound(),
                    request.getKeyUpperBound(),
                    timestampLowerBound,
                    timestampUpperBound,
                    page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L15-31)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L33-36)
```java
    // Defaults and constraints
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```
