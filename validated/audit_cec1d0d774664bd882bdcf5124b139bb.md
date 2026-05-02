I verified each claim against the actual code. Here is my assessment:

**Verified facts:**

- `getHookStorage()` at lines 104–130 has no authentication guard. [1](#0-0) 
- When `keys` is empty, `lowerBound = MIN_KEY_BYTES` and `upperBound = MAX_KEY_BYTES` are set at lines 167–168. [2](#0-1) 
- `HookServiceImpl` lines 65–69 unconditionally call `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse` for the empty-keys path. [3](#0-2) 
- `HookStorageRepository` lines 16–17 define the full-range query method. [4](#0-3) 
- `hook_storage` primary key is `(owner_id, hook_id, key)` — `deleted` is not part of it. [5](#0-4) 
- `hook_storage` is Citus-distributed by `owner_id` at line 70. [6](#0-5) 
- `ThrottleConfiguration` / rate-limiting buckets exist only in the `web3` module, not in `rest-java`. [7](#0-6) 
- `HookStorage` entity has a `deleted` field (line 41) derived from `value` being empty. [8](#0-7) 

**One discrepancy:** The SQL migration `V2.17.1__add_hooks_support.sql` does not include a `deleted` column in the `hook_storage` table definition (lines 57–67). [9](#0-8)  The `deleted` field exists in the Java entity and is derived from `value` being empty, suggesting it is persisted via the `@Upsertable` upsert mechanism or a later migration not present in this repo snapshot. This does not invalidate the core vulnerability — the full key-range BETWEEN scan is expensive regardless of the `deleted` predicate.

---

Audit Report

## Title
Unauthenticated Full Key-Range Scan Amplification via Concurrent Multi-OwnerID Requests on Unthrottled Hook Storage Endpoint

## Summary
`GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` in the `rest-java` module is publicly accessible with no authentication and no rate limiting. When no `key` parameter is supplied (the default), the controller sets the key range to the full 32-byte space (`0x00…00` to `0xFF…FF`), causing a full index scan per request. Because `hook_storage` is Citus-distributed by `owner_id`, concurrent requests with distinct `ownerId` values fan out to separate worker shards simultaneously with no server-side concurrency bound.

## Finding Description

**Step 1 — Unauthenticated endpoint with full-range default:**
`HooksController.getHookStorage()` (lines 104–130) accepts `ownerId` as a plain path variable with no authentication annotation or security filter. When `keys` is empty (the default), lines 167–168 set `lowerBound = MIN_KEY_BYTES` (32×`0x00`) and `upperBound = MAX_KEY_BYTES` (32×`0xFF`). [10](#0-9) [2](#0-1) 

**Step 2 — Service unconditionally issues full-range query:**
`HookServiceImpl.getHookStorage()` lines 65–69 call `hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, keyLowerBound, keyUpperBound, page)` whenever `keys` is empty. [3](#0-2) 

**Step 3 — Repository generates a full-range index scan:**
Spring Data JPA generates `SELECT … WHERE owner_id=? AND hook_id=? AND key BETWEEN '\x00…' AND '\xff…' AND deleted=false ORDER BY key ASC LIMIT ?`. The primary key is `(owner_id, hook_id, key)`; `deleted` is not indexed separately, so the engine must traverse the entire key range for the `(owner_id, hook_id)` pair and filter row-by-row. [4](#0-3) [5](#0-4) 

**Step 4 — Citus sharding amplifies concurrency:**
`hook_storage` is distributed by `owner_id`. Each distinct `ownerId` in a concurrent request batch routes to a different Citus worker shard, producing N simultaneous shard-level scans for N concurrent requests. [6](#0-5) 

**Step 5 — No rate limiting in `rest-java`:**
`ThrottleConfiguration` (bucket4j token buckets) and `ThrottleManagerImpl` exist exclusively in the `web3` module and are never applied to `HooksController`. The only guards in the controller are `@Max(MAX_LIMIT)` (caps rows at 100) and `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` on key parameters — neither limits request concurrency or per-IP query rate. [11](#0-10) [12](#0-11) 

## Impact Explanation
An attacker can drive sustained parallel full-range scans across all Citus worker nodes simultaneously. Each scan traverses the entire `(owner_id, hook_id)` key space in the index. With a large `hook_storage` dataset and many concurrent requests, aggregate CPU and I/O across worker nodes rises proportionally to concurrency, potentially degrading or denying service to legitimate users.

## Likelihood Explanation
Exploitation requires only an HTTP client and a list of valid entity IDs, which are trivially enumerable from the public `/api/v1/accounts` endpoint. No credentials, tokens, or privileged access are needed. The attack is fully scriptable and can be sustained indefinitely. There is no server-side defense in `rest-java` to overcome.

## Recommendation
1. **Rate limiting:** Apply a token-bucket rate limiter (analogous to `ThrottleConfiguration` in `web3`) to `rest-java` controllers, keyed by client IP or API key.
2. **Authentication/authorization:** Require authentication for the `hooks` endpoints, restricting access to the `ownerId`'s own data.
3. **Index optimization:** Add a partial index on `hook_storage(owner_id, hook_id, key) WHERE deleted = false` (or a composite index including `deleted`) to avoid full-range row-by-row filtering.
4. **Query timeout:** Enforce a per-query statement timeout at the connection pool or datasource level to bound the maximum duration of any single scan.

## Proof of Concept
```bash
# Enumerate valid account IDs from the public accounts endpoint
OWNER_IDS=$(curl -s "https://<mirror-node>/api/v1/accounts?limit=100" \
  | jq -r '.accounts[].account')

# Fan out concurrent full-range scans, one per distinct ownerId
for OWNER_ID in $OWNER_IDS; do
  curl -s "https://<mirror-node>/api/v1/accounts/${OWNER_ID}/hooks/1/storage" &
done
wait
```
Each request omits the `key` parameter, triggering the `MIN_KEY_BYTES`→`MAX_KEY_BYTES` default and a full-range scan. With N distinct `ownerId` values, N Citus shards are scanned simultaneously with no server-side throttle.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L167-168)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L16-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
```

**File:** importer/src/main/resources/db/migration/v2/V2.17.1__add_hooks_support.sql (L57-67)
```sql
create table if not exists hook_storage
(
    created_timestamp   bigint not null,
    hook_id             bigint not null,
    modified_timestamp  bigint not null,
    owner_id            bigint not null,
    key                 bytea  not null,
    value               bytea  not null,

    primary key (owner_id, hook_id, key)
);
```

**File:** importer/src/main/resources/db/migration/v2/V2.17.1__add_hooks_support.sql (L70-70)
```sql
select create_distributed_table('hook_storage', 'owner_id', colocate_with => 'entity');
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-55)
```java
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/hook/HookStorage.java (L41-41)
```java
    private boolean deleted;
```
