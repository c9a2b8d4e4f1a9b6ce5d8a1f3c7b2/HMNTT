### Title
Deleted Account Data Exposed via `entityId` Lookup Due to Missing `deleted` Filter in `getByIdAndType`

### Summary
The `account()` GraphQL query in `AccountController` routes `entityId`-based lookups through `EntityServiceImpl.getByIdAndType()`, which calls Spring Data's plain `findById()` with no filter on the `deleted` column. In contrast, alias- and evmAddress-based lookups use custom queries that explicitly exclude deleted entities (`deleted is not true`). Any unprivileged caller can therefore retrieve the full account record — including balance, key, memo, and `autoRenewPeriod` — for an account that has been deleted on-chain, simply by knowing its numeric entity ID.

### Finding Description
**Code path:**

- `AccountController.account()` (line 41–44): when `entityId != null`, calls `entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)`. [1](#0-0) 

- `EntityServiceImpl.getByIdAndType()` (line 24–26): delegates to `entityRepository.findById(entityId.getId())` — the standard Spring Data `CrudRepository.findById`, which issues `SELECT * FROM entity WHERE id = ?` with **no** `deleted` predicate. [2](#0-1) 

- `EntityRepository.findByAlias` and `findByEvmAddress` (lines 13–17) both carry `AND deleted is not true` in their native queries, so those paths correctly suppress deleted records. [3](#0-2) 

- A second bypass exists inside `getByEvmAddressAndType()` (line 37–38): when the supplied EVM address is a long-form address (first 4 bytes = 0, next 8 bytes = 0), the code falls back to `entityRepository.findById(buffer.getLong())` — again without a deleted filter. [4](#0-3) 

**Root cause:** The design assumes `findById` is equivalent to the filtered custom queries, but Spring Data's `findById` emits no `WHERE deleted …` clause. The `deleted` field is part of the mapped `Entity` domain object and is surfaced directly in the GraphQL `Account` view model (confirmed by the `deleted` field in the test schema at line 75). [5](#0-4) 

### Impact Explanation
Any caller (no credentials required — the GraphQL endpoint is public) can retrieve the full persisted state of a deleted account: balance at deletion time, cryptographic key material, memo, `autoRenewPeriod`, `expirationTimestamp`, and the explicit `deleted: true` flag. This breaks the intended invariant that deleted accounts are invisible to the API, leaking historical financial and key data that the account owner may have expected to be inaccessible post-deletion. The inconsistency also allows enumeration: an attacker can iterate numeric entity IDs and identify which accounts are deleted versus active, building a map of account lifecycle events without any privilege.

### Likelihood Explanation
Exploitation requires zero privileges and zero special tooling — a standard GraphQL query with a known or guessed entity ID is sufficient. Entity IDs on Hedera are sequential integers, making enumeration trivial. The endpoint is publicly reachable by design. Any external party aware of the API can reproduce this immediately and repeatedly.

### Recommendation
Replace the bare `findById` call in `getByIdAndType` with a custom repository method that includes the deleted filter, consistent with the other two lookup paths:

```sql
-- Add to graphql EntityRepository:
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Apply the same fix to the `findById` fallback inside `getByEvmAddressAndType` (line 38 of `EntityServiceImpl`). Both call sites must use the filtered query to restore consistent behaviour across all three lookup strategies.

### Proof of Concept
**Precondition:** Account with entity ID `1234` exists in the mirror node database with `deleted = true`.

**Trigger:**
```graphql
query {
  account(input: { entityId: { shard: 0, realm: 0, num: 1234 } }) {
    id
    deleted
    balance
    key
    memo
    expirationTimestamp
  }
}
```

**Result:** The API returns the full account record with `deleted: true` and all associated financial/key fields populated, whereas the same account queried via its alias or EVM address would return `null`. No authentication, no special headers, no elevated role required.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L41-44)
```java
        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L37-38)
```java
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-17)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/controller/AccountControllerTest.java (L75-76)
```java
                            deleted
                            entityId { shard, realm, num }
```
