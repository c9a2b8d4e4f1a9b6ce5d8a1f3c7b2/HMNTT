### Title
Unbounded SQL `IN` Clause DoS via Missing `@Validated` on `HooksController` — `getHookStorage()`

### Summary
`HooksController` lacks the `@Validated` annotation, so the `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` constraint on the `keys` request parameter is never enforced by Spring MVC's method-level validation. An unauthenticated attacker can supply an arbitrarily large number of `key=eq:…` query parameters; all EQ-operator keys are collected into `keyFilters` without any size cap, passed through `getKeysInRange()` unchanged, and forwarded directly to `findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()`, which generates a single SQL `IN (…)` clause containing every supplied key, potentially overwhelming the shared database.

### Finding Description

**Exact code path:**

1. **Controller — missing `@Validated`**
   `HooksController` is annotated with `@NullMarked`, `@RequestMapping`, `@RequiredArgsConstructor`, and `@RestController`, but **not** `@Validated`. [1](#0-0) 
   Without `@Validated`, Spring MVC never triggers Bean Validation on method parameters, so the `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` annotation on `keys` is silently ignored at runtime. [2](#0-1) 

2. **`MAX_REPEATED_QUERY_PARAMETERS = 100` — intended but unenforced cap** [3](#0-2) 

3. **All EQ keys collected without bound in `hookStorageChangeRequest()`**
   Every `key=eq:…` parameter is appended to `keyFilters` with no size check: [4](#0-3) 

4. **`getKeysInRange()` applies no size limit**
   It only filters by byte-range comparison; if all supplied keys fall within `[keyLowerBound, keyUpperBound]` (the default is `[0x00…00, 0xFF…FF]`, i.e., the full range), every key survives: [5](#0-4) 

5. **Unbounded list forwarded to repository → massive SQL `IN` clause** [6](#0-5) [7](#0-6) 

**Root cause:** `@Size` on a `@RequestParam` is a Bean Validation constraint that requires the controller class (or the specific method) to be annotated with `@Validated`. Without it, the constraint is never evaluated, leaving the list size completely unbounded.

### Impact Explanation
An attacker can craft a single HTTP GET request with tens of thousands of `key=eq:…` parameters. The resulting SQL query `WHERE key IN (val1, val2, …, valN)` with N in the tens of thousands forces the database to parse, plan, and execute an extremely large query. Because the mirror-node database is shared across all API processing paths, a sustained stream of such requests can saturate DB CPU/memory and degrade or halt ≥30% of network processing nodes without requiring any privileged access or brute-force credential guessing.

### Likelihood Explanation
The endpoint is publicly accessible with no authentication requirement. The exploit requires only a standard HTTP client capable of sending a large query string (e.g., `curl` with a generated parameter list). It is trivially repeatable and can be automated. No special knowledge of the system internals is needed beyond knowing the endpoint path, which is documented in the API spec.

### Recommendation
Add `@Validated` to `HooksController` so that all Bean Validation constraints on method parameters are enforced:

```java
@Validated   // ← add this
@NullMarked
@RequestMapping(value = "/api/v1/accounts/{ownerId}/hooks", produces = APPLICATION_JSON)
@RequiredArgsConstructor
@RestController
final class HooksController { … }
```

Additionally, add a defensive size check inside `hookStorageChangeRequest()` or `getKeysInRange()` as a belt-and-suspenders guard, and consider adding an integration test that verifies a 400 response when more than `MAX_REPEATED_QUERY_PARAMETERS` keys are supplied.

### Proof of Concept

```bash
# Generate a request with 5000 distinct EQ keys, all within the default [0x00..0, 0xFF..F] range
PARAMS=""
for i in $(seq 1 5000); do
  HEX=$(printf "%064x" $i)
  PARAMS="${PARAMS}&key=eq:${HEX}"
done

curl -v "http://<mirror-node-host>/api/v1/accounts/0.0.1001/hooks/1/storage?limit=100${PARAMS}"
```

**Expected (vulnerable) behaviour:** The server accepts the request, `hookStorageChangeRequest()` populates `keyFilters` with all 5000 entries, `getKeysInRange()` returns all 5000 (they are within the default full range), and `findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` issues a single `SELECT … WHERE key IN (…5000 values…)` query to the database, causing measurable DB load spike.

**Expected (fixed) behaviour:** Spring returns HTTP 400 Bad Request once the `keys` list exceeds 100 entries.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L54-58)
```java
@NullMarked
@RequestMapping(value = "/api/v1/accounts/{ownerId}/hooks", produces = APPLICATION_JSON)
@RequiredArgsConstructor
@RestController
final class HooksController {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L108-109)
```java
            @RequestParam(name = KEY, required = false, defaultValue = "") @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    List<SlotRangeParameter> keys,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L165-176)
```java
        final var keyFilters = new ArrayList<byte[]>();

        var lowerBound = MIN_KEY_BYTES;
        var upperBound = MAX_KEY_BYTES;

        for (final var key : keys) {
            final byte[] value = key.value();

            if (key.hasLowerBound()) {
                if (key.operator() == RangeOperator.EQ) {
                    keyFilters.add(value);
                } else if (Arrays.compareUnsigned(value, lowerBound) > 0) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L36-36)
```java
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L78-79)
```java
        final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
                ownerId.getId(), request.getHookId(), keysInRange, page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L13-14)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
            long ownerId, long hookId, List<byte[]> key, Pageable pageable);
```
