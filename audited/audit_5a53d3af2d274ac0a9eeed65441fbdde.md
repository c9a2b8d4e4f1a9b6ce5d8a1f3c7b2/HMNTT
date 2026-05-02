### Title
Unauthenticated Full-Range DB Query Flood via Unrate-Limited `getHookStorage()` Endpoint

### Summary
The `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoint in `HooksController` has no rate limiting, while the `getHookStorage()` service method issues a full key-range database query (`findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse`) whenever no `key` parameters are supplied. An unprivileged attacker can sustain a high-frequency stream of such requests, each triggering a bounded but expensive DB range scan, driving node resource consumption well above the 30% threshold.

### Finding Description
**Code path:**

- `HooksController.java` lines 104–130: `GET /{hookId}/storage` accepts `key`, `limit`, `order`, `timestamp` with no authentication or rate-limiting annotation.
- `HooksController.hookStorageChangeRequest()` lines 158–198: when `keys` list is empty, `lowerBound` stays `MIN_KEY_BYTES` (32×`0x00`) and `upperBound` stays `MAX_KEY_BYTES` (32×`0xFF`).
- `HookServiceImpl.getHookStorage()` lines 65–69: the `keys.isEmpty()` branch unconditionally calls `hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, MIN_KEY, MAX_KEY, page)`.

**Root cause:** No per-IP or per-client rate limiter is applied to `HooksController`. The grep results confirm rate-limiting infrastructure (`ThrottleManager`, `RequestFilter`) exists only in the `web3` module and `NetworkController`; it is entirely absent from `HooksController`. The only guard is `@Max(MAX_LIMIT)` on `limit`, which caps result-set size per query but does nothing to restrict request frequency.

**Why existing checks fail:**
- `@Positive @Max(MAX_LIMIT)` (line 112) limits rows returned per call, not calls per second.
- `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` (line 108) limits key-list length, but the dangerous path is triggered precisely when the list is *empty*.
- Spring's default servlet thread pool and connection pool are the only back-pressure, and they are shared across all endpoints. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
Each unauthenticated request with no `key` parameter issues a DB range scan over the entire 256-bit key space for the given `(ownerId, hookId)` pair. Even with a composite index, the DB engine must traverse the index from the minimum to the maximum key boundary and apply the `deleted=false` filter before returning up to `MAX_LIMIT` rows. Under sustained parallel flooding (e.g., hundreds of requests/second from a single host or a small botnet), this saturates DB connection pool slots, increases I/O and CPU on the database node, and degrades or denies service to legitimate users. The impact is amplified if the `hook_storage` table is large.

### Likelihood Explanation
The endpoint requires no credentials — only a valid `ownerId` (a public account ID) and any non-negative `hookId`. Both are trivially enumerable or guessable. A single attacker with a modest HTTP client (e.g., `wrk`, `ab`, or a simple script) can sustain thousands of requests per second. The attack is repeatable, requires no special knowledge, and leaves no persistent state to clean up.

### Recommendation
1. **Add rate limiting to `HooksController`**: Apply the same `ThrottleManager`/`RequestFilter` pattern already used in the `web3` module, or introduce a Spring filter / Bucket4j / Resilience4j `RateLimiter` scoped to this controller.
2. **Require a non-trivial key range**: Reject requests where `keyUpperBound - keyLowerBound` exceeds a configurable maximum, forcing callers to paginate over narrower ranges.
3. **Add a minimum key specificity requirement**: Require at least one `key` parameter or a bounded range (e.g., max 2^64 key span) to prevent full-range scans.
4. **Apply connection-pool-level query timeouts** to bound the worst-case DB impact per request.

### Proof of Concept
```bash
# No authentication required. ownerId = any valid account (e.g., 0.0.1234), hookId = 0
# Flood with empty-key requests (full key range, max limit)
wrk -t8 -c200 -d60s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.1234/hooks/0/storage?limit=100&order=asc"
```
Expected result: DB CPU and I/O rise sharply within seconds; legitimate API requests begin timing out or returning 503 errors; node resource consumption exceeds 30% above the 24-hour baseline.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L165-168)
```java
        final var keyFilters = new ArrayList<byte[]>();

        var lowerBound = MIN_KEY_BYTES;
        var upperBound = MAX_KEY_BYTES;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L65-69)
```java
        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
```
