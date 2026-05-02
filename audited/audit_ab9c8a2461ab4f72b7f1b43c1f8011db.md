### Title
Deleted Account `pendingReward` Exposed via GraphQL `account(entityId:)` Query Due to Missing Deleted Filter

### Summary
The GraphQL `account()` resolver in `AccountController` calls `EntityServiceImpl.getByIdAndType()`, which uses the Spring Data `CrudRepository.findById()` method. Unlike the `findByAlias` and `findByEvmAddress` repository methods, `findById` has no `deleted is not true` predicate, so deleted accounts are returned. Any unprivileged caller can then read the stale `pendingReward` field from a deleted account's `entity_stake` record.

### Finding Description

**Exact code path:**

`AccountController.account()` dispatches to `entityService.getByIdAndType()` when the caller supplies an `entityId`: [1](#0-0) 

`EntityServiceImpl.getByIdAndType()` resolves the entity with the bare `findById()` call: [2](#0-1) 

`findById` is the undecorated `CrudRepository` default — the GraphQL module's `EntityRepository` adds no `deleted` predicate for this method: [3](#0-2) 

By contrast, the alias and evmAddress paths both carry an explicit `deleted is not true` guard: [4](#0-3) 

The same gap exists in `getByEvmAddressAndType` for "long-zero" EVM addresses (first 12 bytes zero), which also falls back to `findById`: [5](#0-4) 

Once the deleted `Entity` is returned, `AccountMapper.map()` converts it to an `Account` view-model, and the `pendingReward` field (populated from the `entity_stake` table at deletion time) is serialised into the GraphQL response: [6](#0-5) 

The schema exposes `pendingReward` with no access restriction: [7](#0-6) 

**Root cause:** `CrudRepository.findById()` performs a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` filter. The assumption that only live accounts are reachable via the `entityId` input path is false.

**Failed assumption:** The developer applied `deleted is not true` to alias/evmAddress lookups but forgot to apply the same constraint to the `findById` path, creating an inconsistent access-control boundary.

### Impact Explanation
Any caller (no credentials required) can issue:
```graphql
query {
  account(input: { entityId: { shard: 0, realm: 0, num: <deleted_account_num> } }) {
    deleted
    pendingReward
    balance
    stakedAccount { entityId }
  }
}
```
and receive the stale `pendingReward` value that was recorded in `entity_stake` at the moment the account was deleted. This value no longer reflects on-chain state: the account's stake has been unwound, rewards have been forfeited or paid out, and the figure is meaningless. Applications or off-chain tooling that consume this field without checking `deleted: true` will act on incorrect reward data. The `balance` field is similarly stale. Severity is **Medium**: no funds can be moved, but stale financial data is disclosed to unauthenticated users, violating the principle that deleted entities should be invisible to the API.

### Likelihood Explanation
The exploit requires zero privileges and zero special tooling — a standard GraphQL HTTP POST is sufficient. The attacker only needs to know (or enumerate) a deleted account number, which is public information on any Hedera block explorer. The bug is deterministic and 100% reproducible on every deleted account in the database.

### Recommendation
Add a `deleted` filter to the `findById` path in one of two ways:

**Option A** — Add a named query to the GraphQL `EntityRepository`:
```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndDeletedIsNotTrue(long id);
```
Then use it in `EntityServiceImpl.getByIdAndType()` and `getByEvmAddressAndType()` instead of `findById()`.

**Option B** — Add a post-fetch filter in `getByIdAndType()`:
```java
return entityRepository.findById(entityId.getId())
    .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
    .filter(e -> e.getType() == type);
```
Option A is preferred because it avoids fetching the deleted row at all. Also add a test case analogous to the existing `findByAlias`/`findByEvmAddress` deleted-account tests in `EntityRepositoryTest`.

### Proof of Concept
**Preconditions:** A deleted account exists in the mirror node database (e.g., account `0.0.12345` with `deleted = true` and a non-zero `pending_reward` in `entity_stake`).

**Steps:**
1. Send an unauthenticated HTTP POST to the GraphQL endpoint (e.g., `https://<mirror-node>/graphql/alpha`):
```json
{
  "query": "query { account(input: { entityId: { shard: 0, realm: 0, num: 12345 } }) { deleted pendingReward balance } }"
}
```
2. Observe the response:
```json
{
  "data": {
    "account": {
      "deleted": true,
      "pendingReward": 500000000,
      "balance": 0
    }
  }
}
```
3. The `pendingReward` value of `500000000` tinybars is stale data from before deletion and does not reflect the current on-chain state. The same query using `alias` or `evmAddress` input would return `null` (correctly filtered), confirming the inconsistency.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L37-39)
```java
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/mapper/AccountMapper.java (L10-12)
```java
public interface AccountMapper {
    Account map(Entity source);
}
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L57-61)
```text
    """
    The pending reward the account will receive in the next reward payout. Note the value is updated at the end of each
    staking period and there may be delay to reflect the changes in the past staking period. Defaults to tinybars.
    """
    pendingReward(unit: HbarUnit = TINYBAR): Long
```
