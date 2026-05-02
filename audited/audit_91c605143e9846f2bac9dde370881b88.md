### Title
Deleted Entity Data Exposed via `getByIdAndType()` Due to Missing `deleted` Filter in `findById()` Lookup

### Summary
`EntityServiceImpl.getByIdAndType()` uses the inherited Spring Data `CrudRepository.findById()` which applies no `deleted is not true` filter, unlike the sibling methods `getByAliasAndType()` and `getByEvmAddressAndType()` which use custom queries that explicitly exclude deleted entities. Any unprivileged user can query the GraphQL API with a known numeric entity ID and receive full account data for a deleted entity, creating an inconsistent and incorrect representation of ledger state.

### Finding Description

**Exact code path:**

`EntityServiceImpl.getByIdAndType()` at line 25: [1](#0-0) 

calls `entityRepository.findById()` — the standard Spring Data `CrudRepository` method — which generates `SELECT * FROM entity WHERE id = ?` with **no** `deleted` predicate.

In contrast, the custom queries in `EntityRepository` for alias and EVM address both include `deleted is not true`: [2](#0-1) 

The only filter applied after `findById()` is a type check (`e.getType() == type`), which does not exclude deleted entities.

**Second affected path:** `getByEvmAddressAndType()` also falls back to `findById()` when the EVM address is a "long-zero" address (zero shard/realm prefix), inheriting the same missing filter: [3](#0-2) 

**Caller:** `AccountController.account()` routes `entityId` input directly to `getByIdAndType()`: [4](#0-3) 

**Root cause:** The assumption that `findById()` is equivalent to the custom `findByAlias`/`findByEvmAddress` queries is false. The custom queries explicitly guard against deleted entities; the inherited `findById()` does not.

### Impact Explanation

An unprivileged caller receives full `Account` data (balance, keys, memo, auto-renew settings, staking info, etc.) for an entity that has been deleted via a submitted `CryptoDelete` transaction. The GraphQL schema exposes a `deleted` field on `Account`: [5](#0-4) 

However, the entity is returned rather than filtered to `null`, meaning the API presents deleted accounts as queryable objects. This creates an **inconsistent ledger state view**: the same deleted entity returns `null` when queried by alias or EVM address, but returns full data when queried by numeric ID. Downstream consumers that do not inspect the `deleted` field will treat the account as active, leading to incorrect transaction state representation.

### Likelihood Explanation

- **No privileges required.** The GraphQL endpoint is publicly accessible.
- **Precondition is trivially met.** Numeric entity IDs of deleted accounts are observable from historical transaction records (e.g., `CryptoDelete` transactions visible in the REST API).
- **Fully repeatable.** The behavior is deterministic: every query by numeric ID for a deleted entity will return data.
- **No rate limiting or authentication** is applied to this GraphQL query path.

### Recommendation

Replace the `findById()` call in `getByIdAndType()` with a custom repository method that includes the `deleted is not true` predicate, consistent with `findByAlias` and `findByEvmAddress`. Add a method to `EntityRepository`:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then update `EntityServiceImpl.getByIdAndType()`:

```java
return entityRepository.findByIdAndNotDeleted(entityId.getId())
    .filter(e -> e.getType() == type);
```

Apply the same fix to the `findById()` fallback inside `getByEvmAddressAndType()` for long-zero EVM addresses.

### Proof of Concept

1. Identify a deleted account. Submit a `CryptoDelete` transaction on the network, or find one via the REST API: `GET /api/v1/transactions?transactiontype=CRYPTODELETE`. Note the deleted account's shard/realm/num (e.g., `0.0.12345`).

2. Query the GraphQL endpoint as an unprivileged user:
```graphql
query {
  account(input: { entityId: { shard: 0, realm: 0, num: 12345 } }) {
    entityId { shard realm num }
    deleted
    balance
    memo
    key
  }
}
```

3. **Expected (correct) result:** `null` — entity is deleted, should not be returned.

4. **Actual result:** Full `Account` object is returned with `deleted: true` and all associated fields populated, identical to what an active account would return.

5. Confirm the inconsistency by querying the same entity by alias (if it has one) — that query correctly returns `null` due to the `deleted is not true` guard in `findByAlias`.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L37-39)
```java
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-17)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L41-45)
```java
        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L23-25)
```text
    "Whether the entity still exists in consensus node state."
    deleted: Boolean

```
