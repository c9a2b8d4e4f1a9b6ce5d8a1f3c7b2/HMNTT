### Title
Unauthenticated, Unthrottled Hook Storage Query Endpoint Enables Database Exhaustion via Repeated Reads

### Summary
The `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoint in the `rest-java` module exposes `HookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` to any unauthenticated caller with no rate limiting and no caching layer. An unprivileged external attacker can flood this endpoint with identical `ownerId`/`hookId`/`key` combinations at arbitrary frequency, forcing a live database query on every request and generating sustained, unnecessary load on the backing PostgreSQL database.

### Finding Description
**Exact code path:**

`HooksController.getHookStorage()` (lines 104–130) accepts unauthenticated `GET` requests with no `@PreAuthorize` or any security annotation. It delegates to `HookServiceImpl.getHookStorage()` (lines 56–82), which calls `hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` (lines 78–79) on every invocation.

```
GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage?key=eq:0x0000...0001
```

**Root cause — three absent controls:**

1. **No authentication**: The `rest-java` module contains only `LoggingFilter` and `MetricsFilter`. There is no `WebSecurityConfig`, no `@PreAuthorize`, and no IP-based access control on any hook endpoint. The `authHandler.js` and `ThrottleConfiguration` exist only in the `rest` (Node.js) and `web3` modules respectively — they are entirely absent from `rest-java`.

2. **No rate limiting**: The `web3` module has `ThrottleConfiguration` with bucket4j rate limiters, but `rest-java` has no equivalent. No per-IP or global request-rate enforcement exists for the hooks endpoints.

3. **No caching**: `HookStorageRepository` carries no `@Cacheable` annotation (contrast with `ContractStateRepository.findStorage()` in `web3`, which is `@Cacheable`). Every call to `findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` issues a live SQL query against the `hook_storage` table.

**Why existing checks are insufficient:**

- `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` on the `keys` parameter and `@Max(MAX_LIMIT)` on `limit` bound the cost *per request* but impose no constraint on *request frequency*.
- The `deleted` filter and key-range pre-filtering in `HookStorageRequest.getKeysInRange()` are correctness guards, not DoS mitigations.

### Impact Explanation
An attacker sending thousands of identical requests per second forces the database to execute the same indexed scan repeatedly with no cache hits. Under sustained load this degrades query latency for all users of the mirror node, potentially causing timeouts on other endpoints that share the same database connection pool. The impact is griefing/availability degradation with no economic loss to network participants — consistent with the Medium scope classification.

### Likelihood Explanation
No special privileges, credentials, or on-chain resources are required. Any internet-accessible deployment of the mirror node is reachable. The attack is trivially scriptable with `curl` or any HTTP load tool (`ab`, `wrk`, `hey`). The attacker needs only a valid `ownerId` and `hookId`, both of which are public blockchain data discoverable via the same API. The attack is fully repeatable and stateless.

### Recommendation
1. **Add per-IP rate limiting** to the `rest-java` module using a servlet filter backed by bucket4j (mirroring the pattern already used in `web3/ThrottleConfiguration`), applied globally to `/api/v1/**`.
2. **Add response caching** on `HookStorageRepository` methods using `@Cacheable` with a short TTL (e.g., 5–10 seconds), consistent with how `ContractStateRepository.findStorage()` is cached in the `web3` module.
3. **Consider a global connection-pool guard** (e.g., Resilience4j `RateLimiter` or `Bulkhead`) at the service layer to prevent database connection exhaustion under flood conditions.

### Proof of Concept
```bash
# Discover a valid ownerId/hookId via the public hooks list endpoint
curl "https://<mirror-node>/api/v1/accounts/0.0.1001/hooks"

# Flood the storage endpoint with identical parameters (no credentials needed)
while true; do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1001/hooks/2001/storage\
?key=eq:0x0000000000000000000000000000000000000000000000000000000000000001" \
    -o /dev/null &
done
```

Each iteration triggers `findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(1001, 2001, [key], pageable)` as a live database read with no cache interception, no rate gate, and no authentication barrier. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L11-14)
```java
public interface HookStorageRepository extends PagingAndSortingRepository<HookStorage, Id> {

    List<HookStorage> findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
            long ownerId, long hookId, List<byte[]> key, Pageable pageable);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L78-79)
```java
        final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
                ownerId.getId(), request.getHookId(), keysInRange, page);
```
