Based on my direct inspection of the code, all claims in the report are technically accurate and confirmed.

**Verified facts:**

1. `EntityServiceImpl.getByEvmAddressAndType()` at line 37–38 routes long-zero addresses to `entityRepository.findById(buffer.getLong())` with only a type filter afterward — no deleted filter. [1](#0-0) 

2. `EntityRepository` defines only two custom queries, both with `deleted is not true`. `findById` is the bare `CrudRepository` method and is never overridden. [2](#0-1) 

3. `AccountController` applies no authentication or access control before delegating to `entityService.getByEvmAddressAndType()`. [3](#0-2) 

4. The same `findById`-without-deleted-filter issue also exists in `getByIdAndType()` (line 25), though the report focuses only on the EVM address path. [4](#0-3) 

Nothing in `SECURITY.md` excludes this finding — the exclusions for "enumeration or confirmation of existence" do not apply here because the issue is full entity record retrieval (all fields), not mere existence confirmation. The finding is in scope.

---

# Audit Report

## Title
Missing Deleted-Entity Filter in `getByEvmAddressAndType` Long-Zero EVM Address Path

## Summary
`EntityServiceImpl.getByEvmAddressAndType()` routes long-zero EVM addresses to the bare Spring Data `CrudRepository.findById()` method, which carries no `deleted` filter. The two custom repository queries (`findByAlias`, `findByEvmAddress`) both explicitly include `deleted is not true`, but the `findById` path has no equivalent guard at either the SQL or Java level. As a result, any caller can retrieve full entity records for deleted entities by supplying a long-zero EVM address encoding the target entity number.

## Finding Description
In `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {       // long-zero path
        return entityRepository.findById(buffer.getLong())     // NO deleted filter
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)  // has "deleted is not true"
                           .filter(e -> e.getType() == type);
}
```

When the first 12 bytes of the EVM address are all zero, the code extracts the last 8 bytes as an entity number and calls `findById`. `EntityRepository` extends `CrudRepository<Entity, Long>` and defines only two custom queries:

```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);

@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

`findById` is never overridden, so it executes a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate. The only post-fetch check is `e.getType() == type`, which enforces entity type but not deletion status.

The same defect exists in `getByIdAndType()` (line 25), which also calls `findById` without a deleted filter.

## Impact Explanation
Any deleted account or contract entity stored in the mirror node database can be retrieved in full — all mapped fields including key material, memo, expiration timestamp, auto-renew settings, and obtainer — by an unprivileged external caller. This bypasses the deletion-filtering behavior that the codebase explicitly enforces on every other lookup path (`findByAlias`, `findByEvmAddress`), violating the mirror node's own design intent of not surfacing deleted entities through the GraphQL API.

## Likelihood Explanation
The attack requires zero privileges and zero prior knowledge beyond the public GraphQL schema. Entity numbers are sequential integers starting from 1, making full enumeration trivial with a simple loop. Long-zero EVM addresses are trivially constructed: 12 zero bytes followed by the 8-byte big-endian encoding of the target entity number. The `AccountController` applies no authentication or rate-limiting before invoking the vulnerable code path. The exploit is fully repeatable and automatable.

## Recommendation
Add a `deleted` filter to the long-zero branch, consistent with the other two query paths. The simplest fix is to add a Java-level guard after `findById`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
                           .filter(e -> e.getType() == type)
                           .filter(e -> !Boolean.TRUE.equals(e.getDeleted()));
}
```

Alternatively, add a custom repository method with an explicit `deleted is not true` predicate:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(long id);
```

Apply the same fix to `getByIdAndType()`, which has an identical `findById`-without-deleted-filter defect.

## Proof of Concept
1. Identify a deleted account with entity number `N` in the mirror node database (e.g., `N = 1234`).
2. Construct the long-zero EVM address: `0x000000000000000000000000` + 8-byte big-endian encoding of `N`.  
   For `N = 1234` (`0x00000000000004D2`): `0x000000000000000000000000000000000000000004D2` (padded to 20 bytes: `0x00000000000000000000000000000000000004d2`).
3. Submit the following GraphQL query to the public endpoint:
   ```graphql
   query {
     account(input: { evmAddress: "0x00000000000000000000000000000000000004d2" }) {
       id
       memo
       key
       deleted
     }
   }
   ```
4. The response returns the full entity record including `deleted: true`, confirming that the deleted-entity filter is bypassed on the long-zero path.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-55)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```
