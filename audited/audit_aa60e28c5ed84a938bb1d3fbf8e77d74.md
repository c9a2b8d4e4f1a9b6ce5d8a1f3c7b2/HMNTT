### Title
Unbounded Duplicate `key=eq:` Parameters Inflate SQL `IN` Clause Without Deduplication (Query Amplification DoS)

### Summary
`hookStorageChangeRequest()` appends every `EQ`-operator key directly to `keyFilters` without deduplication. Because `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` permits up to 100 identical `key=eq:<slot>` parameters, an unauthenticated caller can force `getKeysInRange()` to return 100 duplicate `byte[]` entries, which are then expanded verbatim into the SQL `IN (:keys)` clause, amplifying every query by up to 100×.

### Finding Description

**Code path:**

`getHookStorage()` accepts up to `MAX_REPEATED_QUERY_PARAMETERS` (= 100) `SlotRangeParameter` entries via `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)`: [1](#0-0) 

Inside `hookStorageChangeRequest()`, every `EQ`-operator key is unconditionally appended to `keyFilters` with no duplicate check: [2](#0-1) 

`getKeysInRange()` streams the raw `keys` collection (which is `keyFilters`) and applies only a range filter — no deduplication: [3](#0-2) 

The resulting list is passed directly to the repository, which expands it into a native SQL `IN` clause: [4](#0-3) [5](#0-4) 

**Root cause:** The `@Size` constraint caps the *count* of parameters but does not enforce uniqueness. The loop at lines 170–175 of `HooksController.java` never checks whether a value is already present in `keyFilters` before calling `keyFilters.add(value)`. `getKeysInRange()` likewise performs no deduplication before returning the list to the repository layer.

**Failed assumption:** The design assumes callers supply distinct slot values; no server-side enforcement of that assumption exists.

### Impact Explanation

An attacker sending 100 copies of `key=eq:0x0000…0001` causes:
- `keyFilters` to contain 100 identical `byte[32]` objects.
- `getKeysInRange()` to return all 100 (each passes the range filter trivially).
- The JPA/JDBC layer to serialize a `WHERE key IN (val, val, …, val)` clause with 100 literal repetitions of the same 32-byte value.
- The database to receive and parse a significantly larger query string per request.

While PostgreSQL may internally deduplicate `IN` list members during planning, the overhead is incurred on every hop: HTTP parsing, Spring parameter binding, Java stream processing, JDBC serialization, and the database query planner. Repeated rapid requests multiply this overhead linearly. The amplification factor is bounded at 100× but is fully attacker-controlled up to that ceiling. [6](#0-5) 

### Likelihood Explanation

- **No authentication required.** The endpoint is a plain `@GetMapping` with no security annotation.
- **Zero preconditions.** Any network-reachable client can craft the request.
- **Trivially repeatable.** A single `curl` loop or HTTP flood tool suffices.
- **Amplification is deterministic.** The attacker fully controls the multiplier (1–100). [7](#0-6) 

### Recommendation

Deduplicate `keyFilters` before building the request. The simplest fix is to replace `ArrayList` with a `LinkedHashSet` (preserving insertion order, eliminating duplicates) in `hookStorageChangeRequest()`:

```java
// HooksController.java, line 165
final var keyFilters = new LinkedHashSet<byte[]>(/* comparator aware of byte[] */);
```

Because `byte[]` uses reference equality, a `TreeSet` with `Arrays::compareUnsigned` as comparator is more correct:

```java
final var keyFilters = new TreeSet<>(Arrays::compareUnsigned);
```

Alternatively, deduplicate in `getKeysInRange()` using `.distinct()` — but note that `Stream.distinct()` also uses reference equality for arrays, so the `TreeSet` approach in the controller is safer.

### Proof of Concept

```bash
# Build a URL with 100 identical eq: parameters for the same slot
PARAMS=$(python3 -c "print('&'.join(['key=eq:0x0000000000000000000000000000000000000000000000000000000000000001']*100))")

# Fire repeated requests (no auth needed)
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1234/hooks/1/storage?$PARAMS" &
done
wait
```

Each request causes `hookStorageChangeRequest()` to populate `keyFilters` with 100 identical entries, `getKeysInRange()` to return all 100, and the repository to issue a `WHERE key IN (<100 identical 32-byte literals>)` query against the database. At 500 concurrent requests this produces 50,000 redundant IN-clause entries hitting the database simultaneously. [8](#0-7)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-115)
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L43-52)
```java
    public List<byte[]> getKeysInRange() {
        if (keys.isEmpty()) {
            return List.of();
        }

        return keys.stream()
                .filter(key -> Arrays.compareUnsigned(key, keyLowerBound) >= 0
                        && Arrays.compareUnsigned(key, keyUpperBound) <= 0)
                .toList();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L13-14)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
            long ownerId, long hookId, List<byte[]> key, Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L54-55)
```java
                      and key in (:keys)
                      and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L36-36)
```java
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```
