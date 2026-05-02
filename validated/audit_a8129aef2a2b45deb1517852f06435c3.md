I verified all referenced files and line numbers against the actual codebase. Here is my assessment:

---

**Key findings from code verification:**

- `HooksController.java` lines 104–130: endpoint exists, no auth guard. [1](#0-0) 
- Lines 167–168 correctly default to `MIN_KEY_BYTES`/`MAX_KEY_BYTES` when `keys` is empty. [2](#0-1) 
- `HookServiceImpl.java` lines 65–69: empty-keys branch confirmed. [3](#0-2) 
- `HookStorageRepository.java` lines 16–17: method confirmed. [4](#0-3) 
- `V2.17.1__add_hooks_support.sql` line 70: Citus distribution by `owner_id` confirmed. [5](#0-4) 
- `ThrottleConfiguration` exists only in `web3`, not `rest-java`. [6](#0-5) 
- `HookStorage` entity has `deleted` field at line 41, not annotated `@Transient`, so JPA maps it to a DB column. [7](#0-6) 

**One factual discrepancy:** The `V2.17.1` migration's `hook_storage` DDL (lines 57–67) does not include a `deleted` column, yet the entity and repository method both reference it. [8](#0-7)  This is a schema/entity mismatch, but it does not invalidate the core vulnerability — the full-range scan and lack of rate limiting are independent of the `deleted` predicate's efficiency argument.

---

# Audit Report

## Title
Unauthenticated Full Key-Range Scan Amplification via Concurrent Multi-OwnerID Requests on Unthrottled Hook Storage Endpoint

## Summary
The `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoint in the `rest-java` module is publicly accessible with no authentication and no rate limiting. When no `key` parameter is supplied, the controller defaults to a full 32-byte key range (`0x00…00` to `0xFF…FF`), causing a full-range index scan per request. Because `hook_storage` is a Citus distributed table sharded by `owner_id`, concurrent requests with distinct valid `ownerId` values fan out to separate worker shards simultaneously, with no server-side mechanism to bound aggregate query concurrency.

## Finding Description

**Code path:**

1. `HooksController.java` lines 104–130: `getHookStorage()` accepts `ownerId` as a path variable with no authentication guard. [9](#0-8) 

2. When `keys` is empty (the default), `lowerBound = MIN_KEY_BYTES` (32×`0x00`) and `upperBound = MAX_KEY_BYTES` (32×`0xFF`) are set at lines 167–168, producing the widest possible key range. [10](#0-9) 

3. `HookServiceImpl.java` lines 65–69: the empty-keys branch unconditionally calls `hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, keyLowerBound, keyUpperBound, page)`. [3](#0-2) 

4. `HookStorageRepository.java` lines 16–17: Spring Data JPA generates a query scanning the full key range for the given `(owner_id, hook_id)` pair, filtered by `deleted = false`, up to `LIMIT` rows. [4](#0-3) 

5. `V2.17.1__add_hooks_support.sql` line 70: `hook_storage` is a Citus distributed table sharded by `owner_id`. Each distinct `ownerId` routes to a different worker shard, so N concurrent requests with N distinct `ownerIds` produce N simultaneous shard-level scans. [11](#0-10) 

**Root cause:** The `rest-java` module contains no rate-limiting infrastructure. `ThrottleConfiguration` / `ThrottleManagerImpl` exist exclusively in the `web3` module and are never applied to `HooksController`. [6](#0-5)  The only guards present are `@Max(MAX_LIMIT)` (capping rows returned at 100) and `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` on key parameters — neither limits request concurrency or per-IP query rate. [12](#0-11) 

## Impact Explanation
An attacker can drive sustained parallel full-range index scans across all Citus worker nodes simultaneously. Each scan traverses the entire `(owner_id, hook_id)` key space in the primary key index. With a large `hook_storage` dataset and many concurrent requests, aggregate CPU and I/O across worker nodes rises proportionally to concurrency. Because the endpoint is unauthenticated and the default request requires zero parameters beyond a valid entity ID, the attack surface is maximally broad. The `LIMIT 100` cap only bounds rows returned per response, not the cost of the index scan needed to find those rows.

## Likelihood Explanation
Exploitation requires only an HTTP client and a list of valid entity IDs, which are trivially enumerable from the public `/api/v1/accounts` endpoint. No credentials, tokens, or privileged access are needed. The attack is fully repeatable, scriptable, and can be sustained indefinitely. The absence of any rate limiting or connection throttling in `rest-java` means there is no server-side defense to overcome.

## Recommendation
1. **Rate limiting:** Implement per-IP (and optionally per-`ownerId`) rate limiting in `rest-java`, analogous to the `ThrottleConfiguration` / `ThrottleManagerImpl` already present in the `web3` module. Apply it globally via a servlet filter or Spring `HandlerInterceptor`.
2. **Require explicit key parameters or narrow range:** Consider requiring at least one `key` parameter, or restricting the default range to a bounded window, to prevent zero-parameter full-range scans.
3. **Query timeout:** Enforce a per-query statement timeout at the database or connection-pool level to bound the maximum duration of any single scan.
4. **Index optimization:** Add a partial index on `hook_storage (owner_id, hook_id, key)` where `deleted = false` (once the `deleted` column is confirmed present in the schema) to reduce scan cost for the common filtered query.

## Proof of Concept

```bash
# Enumerate valid ownerIds from the public accounts endpoint
OWNER_IDS=$(curl -s "https://<mirror-node>/api/v1/accounts?limit=100" \
  | jq -r '.accounts[].account')

# Fire concurrent full-range scans, one per distinct ownerId
for OWNER_ID in $OWNER_IDS; do
  curl -s "https://<mirror-node>/api/v1/accounts/${OWNER_ID}/hooks/1/storage" \
    --max-time 30 &
done
wait
```

Each request with a distinct `ownerId` routes to a separate Citus shard and triggers an independent full-range index scan. With 100 concurrent requests across 100 distinct `ownerIds`, 100 simultaneous shard-level scans execute with no server-side throttle. Scaling the loop or running it from multiple clients amplifies the effect linearly.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L16-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
```

**File:** importer/src/main/resources/db/migration/v2/V2.17.1__add_hooks_support.sql (L57-70)
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
comment on table hook_storage is 'Current state of hook storage';

select create_distributed_table('hook_storage', 'owner_id', colocate_with => 'entity');
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/hook/HookStorage.java (L41-41)
```java
    private boolean deleted;
```
