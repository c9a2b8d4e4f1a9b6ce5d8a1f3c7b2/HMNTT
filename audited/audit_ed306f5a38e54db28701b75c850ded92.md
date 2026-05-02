### Title
Soft-Deleted Hook Records Returned with `contractId` via Unauthenticated REST API

### Summary
`HookRepository.findByOwnerIdAndHookIdBetween()` generates a JPQL query with no `deleted = false` predicate, causing the `GET /api/v1/accounts/{ownerId}/hooks` endpoint to return soft-deleted `Hook` records. Because `HookMapper` maps all domain fields — including `contractId` — to the REST response, any unauthenticated caller can enumerate contract associations that were intended to be hidden after hook deletion.

### Finding Description
**Exact code path:**

`HookRepository` (line 15) declares:
```java
List<Hook> findByOwnerIdAndHookIdBetween(long ownerId, long lowerBound, long upperBound, Pageable pageable);
```
Spring Data JPA derives the query solely from the method name, producing `WHERE owner_id = ? AND hook_id BETWEEN ? AND ?` — no `deleted` predicate is generated. [1](#0-0) 

`HookServiceImpl.getHooks()` (line 40) calls this method directly and performs no post-fetch filtering on the `deleted` flag:
```java
return hookRepository.findByOwnerIdAndHookIdBetween(id.getId(), lowerBound, upperBound, page);
``` [2](#0-1) 

`HookMapper` maps every field of the domain `Hook` (including `contractId` and `deleted`) to the REST model with no suppression: [3](#0-2) 

The `AbstractHook` domain object carries `contractId` and `deleted` as first-class fields: [4](#0-3) 

**Root cause / failed assumption:** The developer assumed Spring Data's derived-query naming convention would be sufficient, but unlike `HookStorageRepository` — which explicitly appends `AndDeletedIsFalse` to both its query methods — `HookRepository` omits this suffix entirely. [5](#0-4) 

**Soft-delete mechanics confirmed:** `EVMHookHandler.processHookDeletion()` sets `deleted=true` and upserts the record; the row is never physically removed. [6](#0-5) 

### Impact Explanation
The `contract_id` field in the API response (defined as required in the OpenAPI schema) reveals which smart contract implements a hook's executing bytecode. [7](#0-6) 

After an account owner deletes a hook — expecting the contract association to be private — any unauthenticated caller can still retrieve the `contractId` by querying `GET /api/v1/accounts/{ownerId}/hooks`. This leaks business-sensitive contract relationships (e.g., proprietary hook implementations) that the owner believed were no longer visible. The endpoint requires no credentials, so the attack surface is the entire internet.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs to know (or enumerate) a valid `ownerId`. The endpoint is public, paginated, and supports range filters (`hook.id=gte:0`), making bulk enumeration trivial. The vulnerability is deterministic and repeatable — every soft-deleted hook is always returned.

### Recommendation
Add `AndDeletedIsFalse` to both derived-query method names in `HookRepository`, mirroring the pattern already used in `HookStorageRepository`:

```java
List<Hook> findByOwnerIdAndHookIdInAndDeletedIsFalse(long ownerId, Collection<Long> hookIds, Pageable pageable);

List<Hook> findByOwnerIdAndHookIdBetweenAndDeletedIsFalse(long ownerId, long lowerBound, long upperBound, Pageable pageable);
```

No service-layer changes are needed; Spring Data will automatically append `AND deleted = false` to the generated SQL.

### Proof of Concept
1. Create an account (`ownerId = 0.0.123`) and attach a hook pointing to contract `0.0.456`.
2. Delete the hook via `CryptoUpdateTransactionBody` with `hookIdsToDelete = [1]`. The importer sets `deleted = true` and upserts the row.
3. As an unauthenticated external user, issue:
   ```
   GET /api/v1/accounts/0.0.123/hooks
   ```
4. Observe the response contains the soft-deleted hook with `"deleted": true` **and** `"contract_id": "0.0.456"` — the contract association that was supposed to be hidden after deletion.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookRepository.java (L13-15)
```java
    List<Hook> findByOwnerIdAndHookIdIn(long ownerId, Collection<Long> hookIds, Pageable pageable);

    List<Hook> findByOwnerIdAndHookIdBetween(long ownerId, long lowerBound, long upperBound, Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L39-41)
```java
        if (request.getHookIds().isEmpty()) {
            return hookRepository.findByOwnerIdAndHookIdBetween(id.getId(), lowerBound, upperBound, page);
        } else {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/mapper/HookMapper.java (L12-14)
```java
public interface HookMapper extends CollectionMapper<Hook, org.hiero.mirror.rest.model.Hook> {
    @Mapping(source = "createdTimestamp", target = "createdTimestamp", qualifiedByName = QUALIFIER_TIMESTAMP)
    org.hiero.mirror.rest.model.Hook map(Hook source);
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/hook/AbstractHook.java (L49-57)
```java
    @Convert(converter = EntityIdConverter.class)
    @UpsertColumn(coalesce = UPSERTABLE_COLUMN_COALESCE)
    private EntityId contractId;

    @UpsertColumn(coalesce = UPSERTABLE_COLUMN_COALESCE)
    private Long createdTimestamp;

    @UpsertColumn(coalesce = UPSERTABLE_COLUMN_WITH_DEFAULT_COALESCE)
    private Boolean deleted;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L13-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
            long ownerId, long hookId, List<byte[]> key, Pageable pageable);

    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/EVMHookHandler.java (L173-182)
```java
    private void processHookDeletion(RecordItem recordItem, long entityId, List<Long> hookIdsToDeleteList) {
        hookIdsToDeleteList.forEach(hookId -> {
            final var hook = Hook.builder()
                    .deleted(true)
                    .hookId(hookId)
                    .ownerId(entityId)
                    .timestampRange(Range.atLeast(recordItem.getConsensusTimestamp()))
                    .build();
            entityListener.onHook(hook);
        });
```

**File:** rest/api/v1/openapi.yml (L1680-1683)
```yaml
        contract_id:
          allOf:
            - $ref: "#/components/schemas/EntityId"
          description: The contract entity that contains the hook's executing bytecode
```
