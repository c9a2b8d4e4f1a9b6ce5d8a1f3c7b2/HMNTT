All code references check out exactly. Here is the verified audit report:

---

Audit Report

## Title
Soft-Deleted Account Data Exposed via `entityId` Lookup in GraphQL `account()` Query

## Summary
The GraphQL `account()` query exposes full `Entity` records for soft-deleted accounts when queried by numeric `entityId`. The `findById` path in `EntityServiceImpl.getByIdAndType()` carries no `deleted is not true` predicate, while the `findByAlias` and `findByEvmAddress` paths explicitly enforce it. Any unauthenticated caller can retrieve deleted account data by supplying a numeric account ID.

## Finding Description
The code path is confirmed exactly as described:

**`AccountController.java` lines 41–44** routes `entityId`-based lookups to `entityService.getByIdAndType()`: [1](#0-0) 

**`EntityServiceImpl.java` line 25** calls `entityRepository.findById()` and filters only by `EntityType`, not deletion status: [2](#0-1) 

**`EntityRepository.java` lines 13–17** defines only two custom queries, both with `deleted is not true`. `findById` is inherited from `CrudRepository<Entity, Long>` with no override and no deletion predicate: [3](#0-2) 

**`AccountMapper.java`** performs a plain structural mapping with no deletion check: [4](#0-3) 

The `Entity` class itself carries no JPA `@Where` or `@SQLRestriction` annotation that would globally filter deleted rows: [5](#0-4) 

**Secondary path confirmed:** `getByEvmAddressAndType()` line 38 also calls `entityRepository.findById()` for long-zero EVM addresses, with the same missing deletion guard: [6](#0-5) 

**Root cause:** The `findByAlias` and `findByEvmAddress` queries explicitly enforce `deleted is not true` at the SQL layer, establishing clear intent that deleted accounts should not be returned. The `findById` path enforces no such constraint at any layer — SQL, JPA, or application.

## Impact Explanation
A caller querying a deleted account by numeric ID receives the full `Entity` record, including cryptographic keys, memo field, expiration timestamp, auto-renew account settings, and proxy account ID — data the system's own alias/EVM-address paths would refuse to return for the same account. The `AccountMapper` maps all fields without any deletion check.

## Likelihood Explanation
The GraphQL endpoint requires no authentication. Hedera account IDs are sequential integers (e.g., `0.0.12345`) and are publicly observable on-chain. An attacker can trivially iterate numeric IDs and identify deleted accounts by the presence of a `deleted: true` field in the response. No special privileges, credentials, or tooling are required.

## Recommendation
Add a deletion guard in `EntityServiceImpl.getByIdAndType()` consistent with the other lookup paths:

```java
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findById(entityId.getId())
            .filter(e -> e.getType() == type)
            .filter(e -> !Boolean.TRUE.equals(e.getDeleted())); // add this
}
```

Apply the same fix to the `findById` branch inside `getByEvmAddressAndType()` (line 38). Alternatively, add a dedicated `findById` override in `EntityRepository` with an explicit `deleted is not true` predicate, matching the pattern already used for `findByAlias` and `findByEvmAddress`.

## Proof of Concept
```graphql
# Query a known-deleted account by its numeric ID
query {
  account(input: { entityId: { shard: 0, realm: 0, num: 12345 } }) {
    id
    deleted
    key
    memo
    expirationTimestamp
  }
}
```
If account `0.0.12345` is soft-deleted in the mirror node database, this query returns its full record including `deleted: true` and all associated fields, while an equivalent alias-based query for the same account would return `null`.

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

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/Entity.java (L9-13)
```java
@Data
@jakarta.persistence.Entity
@NoArgsConstructor
@SuperBuilder(toBuilder = true)
public class Entity extends AbstractEntity {
```
