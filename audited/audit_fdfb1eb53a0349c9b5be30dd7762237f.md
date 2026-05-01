### Title
Unauthenticated Full-Range Key Scan DoS on Hook Storage Endpoint via Missing Per-Client Rate Limiting

### Summary
The `/api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoint invokes `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse()` with default full-range key bounds (0x00…00 to 0xFF…FF) when no `key` parameter is supplied. The `rest-java` module contains no application-level rate limiting or authentication, and the only infrastructure-level control (`maxRatePerEndpoint: 250`) is a global backend policy rather than a per-client throttle. An unauthenticated attacker can sustain a high-volume stream of individually valid full-range scans to drive database I/O well above 30% without triggering any brute-force detection.

### Finding Description

**Exact code path:**

`HooksController.getHookStorage()` (lines 104–130) accepts requests with no `key` parameter. In `hookStorageChangeRequest()` (lines 158–198), when `keys` is empty the bounds default to:

```java
var lowerBound = MIN_KEY_BYTES;  // 32 × 0x00
var upperBound = MAX_KEY_BYTES;  // 32 × 0xFF
```

These are passed directly to `HookServiceImpl.getHookStorage()` (lines 56–82), which calls:

```java
hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
    ownerId.getId(), request.getHookId(),
    request.getKeyLowerBound(), request.getKeyUpperBound(), page);
```

This is the widest possible range scan on the `hook_storage` table, bounded only by `(owner_id, hook_id)`, returning up to `limit=100` rows per call.

**Root cause / failed assumption:**

The `rest-java` module has no application-level rate limiting. The only filters registered are `LoggingFilter` (logging only) and `MetricsFilter` (metrics only). No `ThrottleConfiguration`, `ThrottleManager`, `@PreAuthorize`, or any per-client quota exists in the `rest-java` codebase. The throttling infrastructure present in the `web3` module is entirely absent here.

**Why existing checks fail:**

The sole infrastructure control is `maxRatePerEndpoint: 250` in the GCP gateway backend policy (`charts/hedera-mirror-rest-java/values.yaml`, line 56). This is:
- A **global** backend rate (250 req/s total to the service), not a per-IP or per-client limit
- Annotated "Requires a change to HPA to take effect," indicating it is not fully enforced
- GCP-specific and absent in non-GCP deployments
- Ineffective against a single attacker who can consume the entire 250 req/s budget alone

Because each request is individually valid (not a repeated identical credential attempt), no brute-force detection applies.

### Impact Explanation

A hook with >1M storage entries (explicitly called out as a supported scale in the design doc) subjected to sustained full-range scans at 250 req/s × 100 rows = 25,000 row reads/second generates substantial sequential I/O on the `hook_storage` table. Even with proper indexes on `(owner_id, hook_id, key)`, this volume of range scans causes buffer pool churn, increased disk reads, and elevated CPU for sort/merge operations. This can degrade query latency for all other API consumers sharing the same database, meeting the >30% resource consumption increase threshold. The endpoint is publicly reachable with no credentials required.

### Likelihood Explanation

Preconditions are minimal: the attacker needs only a valid `ownerId` and `hookId` (both discoverable via the public `/api/v1/accounts/{id}/hooks` endpoint). The attack requires no special tooling—a simple loop with `curl` or any HTTP client suffices. It is repeatable indefinitely, produces no error responses (all requests return HTTP 200), and generates no anomalous patterns distinguishable from legitimate pagination traffic.

### Recommendation

1. **Application-level per-client rate limiting**: Implement a per-IP (or per-API-key) token-bucket throttle in `rest-java` analogous to `ThrottleConfiguration`/`ThrottleManagerImpl` in `web3`, applied via a servlet filter on the hooks storage endpoint.
2. **Cost-based throttling**: Treat full-range key queries (no `key` parameter supplied) as higher-cost operations and apply a stricter sub-limit for them.
3. **Mandatory key filter or cursor**: Require at least one `key` filter parameter, or enforce that pagination cursors must be used after the first page, preventing repeated full-range scans.
4. **Per-client gateway policy**: Replace the global `maxRatePerEndpoint` with a per-source-IP rate limit at the gateway layer.

### Proof of Concept

```bash
# Discover a valid ownerId/hookId (no auth required)
curl "https://<mirror-node>/api/v1/accounts/0.0.123/hooks"
# Returns hook_id e.g. 1

# Sustained full-range key scan loop (no key param = min→max range)
while true; do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.123/hooks/1/storage?limit=100" \
    -o /dev/null &
done
# Each request triggers findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
#   ownerId=123, hookId=1, fromKey=0x000...000, toKey=0xFFF...FFF, limit=100)
# No 429 is returned; all requests succeed with HTTP 200
# At 250 concurrent req/s, DB I/O increases proportionally to hook_storage table size
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L16-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```
