### Title
Soft-Deleted Entity Disclosure via Zero-Prefix EVM Address in GraphQL `getByEvmAddressAndType()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when an EVM address has its first 12 bytes set to zero (the Hedera long-form numeric encoding), the code routes to `entityRepository.findById()` — a standard Spring Data `CrudRepository` method that carries **no** `deleted` filter. The alternate path (`findByEvmAddress()`) explicitly enforces `deleted is not true` in SQL. Any unauthenticated user can craft a zero-prefix EVM address encoding a known deleted entity's numeric ID and retrieve that entity through the GraphQL API.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        // ← NO deleted filter; uses CrudRepository.findById()
        return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
    }
    // ← deleted is not true enforced in SQL
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

**Root cause:**

`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, lines 12–17:

```java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
    // findById() is inherited from CrudRepository — no deleted filter
}
```

`findByEvmAddress()` enforces `deleted is not true` at the SQL level. `findById()` (inherited from `CrudRepository<Entity, Long>`) issues a plain `SELECT * FROM entity WHERE id = ?` with no such constraint. The only post-query filter applied in the zero-prefix branch is a type check (`e.getType() == type`), which does not check the `deleted` field.

**Exploit flow:**

1. Attacker identifies a deleted entity's numeric ID (Hedera entity IDs are sequential and publicly observable from ledger history).
2. Attacker encodes it as a 20-byte zero-prefix EVM address: bytes 0–3 = `0x00000000`, bytes 4–11 = `0x0000000000000000`, bytes 12–19 = the 8-byte big-endian entity ID.
3. Attacker submits a GraphQL query:
   ```graphql
   query { account(input: { evmAddress: "0x000000000000000000000000000000000000ABCD" }) { ... } }
   ```
4. `buffer.getInt() == 0 && buffer.getLong() == 0` evaluates to `true`, routing to `findById(0xABCD)`.
5. The deleted entity is returned in full.

**Why existing checks fail:**

The only post-retrieval filter is `.filter(e -> e.getType() == type)`. There is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` guard anywhere in the zero-prefix branch. The `deleted` field on the returned `Entity` object may be `true` or `null` (both meaning "deleted"), and neither is rejected.

### Impact Explanation

Any soft-deleted entity (account, contract, token, etc.) whose numeric ID is known or guessable can be retrieved in full via the public GraphQL API. This violates the API's stated access-control invariant that deleted entities are inaccessible. In a ledger context the data was once public, but the mirror node API is explicitly designed to hide deleted entities (as evidenced by the `deleted is not true` guards on every other lookup path). Severity: **Medium** — information disclosure of data the system intends to suppress.

### Likelihood Explanation

- No authentication or special privilege is required; the GraphQL endpoint is public.
- Hedera entity IDs are sequential integers, making enumeration trivial.
- The crafted EVM address format (`0x000000000000000000000000<id>`) is documented Hedera behavior, so any informed user knows it.
- The attack is fully repeatable and scriptable.

### Recommendation

Add a `deleted` check in the zero-prefix branch, consistent with all other lookup paths:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
        .filter(e -> e.getType() == type);
}
```

Alternatively, add a dedicated repository method `findByIdAndDeletedIsNotTrue(Long id)` with an explicit `@Query` (mirroring `findByEvmAddress`) and use it here, making the constraint visible and consistent at the repository layer.

### Proof of Concept

**Precondition:** Entity with numeric ID `12345` (`0x3039`) exists in the database with `deleted = true`.

**Crafted EVM address:** `0x0000000000000000000000000000000000003039`
- Bytes 0–3: `00 00 00 00` → `buffer.getInt() == 0` ✓
- Bytes 4–11: `00 00 00 00 00 00 00 00` → `buffer.getLong() == 0` ✓
- Bytes 12–19: `00 00 00 00 00 00 30 39` → `buffer.getLong() == 12345`

**GraphQL request:**
```graphql
query {
  account(input: { evmAddress: "0x0000000000000000000000000000000000003039" }) {
    entityId { shard realm num }
    deleted
    type
  }
}
```

**Result:** The deleted entity is returned with `deleted: true` — bypassing the soft-delete filter that `findByEvmAddress()` would have enforced. [1](#0-0) [2](#0-1)

### Citations

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
