### Title
Deleted Entity Disclosure via Long-Zero EVM Address in GraphQL `getByEvmAddressAndType`

### Summary
In `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, the `getByEvmAddressAndType()` method routes long-zero EVM addresses (first 12 bytes all zero) to `entityRepository.findById()`, which is the standard Spring Data `CrudRepository.findById()` and carries **no** `deleted is not true` filter. Any unprivileged caller can craft such an address encoding a deleted entity's numeric ID and receive the deleted entity back from the GraphQL API, bypassing the deletion-visibility contract enforced by `findByEvmAddress`.

### Finding Description
**Exact code path:**

`EntityServiceImpl.java` lines 34–41: [1](#0-0) 

```
if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // first 12 bytes == 0
    return entityRepository.findById(buffer.getLong())         // last 8 bytes = entity ID
               .filter(e -> e.getType() == type);              // only type check, NO deleted check
}
return entityRepository.findByEvmAddress(evmAddressBytes)      // has "deleted is not true"
           .filter(e -> e.getType() == type);
```

**Root cause:** `EntityRepository` extends `CrudRepository<Entity, Long>`: [2](#0-1) 

The custom `findByEvmAddress` explicitly adds `deleted is not true`: [3](#0-2) 

But `findById` is the inherited Spring Data method — it generates `SELECT * FROM entity WHERE id = ?` with no deletion predicate. The only post-fetch filter is `.filter(e -> e.getType() == type)`, which checks entity type only. [4](#0-3) 

**Exploit flow:**
1. Attacker identifies (or enumerates) the numeric ID of a deleted entity (e.g., ID = `N`).
2. Attacker constructs a 20-byte long-zero EVM address: bytes 0–11 all `0x00`, bytes 12–19 = `N` as big-endian `long`.
3. Attacker submits a GraphQL query using this address as the EVM address input.
4. `buffer.getInt() == 0 && buffer.getLong() == 0` evaluates to `true` → `findById(N)` is called.
5. Spring Data returns the deleted entity row unconditionally.
6. The `.filter(e -> e.getType() == type)` passes if the type matches.
7. The deleted entity is returned in the GraphQL response.

**Why existing checks fail:** The only guard after `findById` is a type-equality check. There is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` or equivalent. The `deleted is not true` SQL predicate exists only in `findByEvmAddress` and `findByAlias`, not in the `findById` code path. [5](#0-4) 

### Impact Explanation
An attacker can read the full record of any deleted Hashgraph entity (account, contract, token, topic, file) through the public GraphQL endpoint. This violates the mirror node's historical-record integrity guarantee: entities marked deleted should not be visible to external consumers. Sensitive metadata stored on deleted entities (keys, memo fields, balances at deletion time) is exposed. Severity: **Medium–High** (information disclosure, no authentication required, affects data integrity of the historical record).

### Likelihood Explanation
No privileges are required. The GraphQL endpoint is publicly accessible. Entity numeric IDs are sequential and easily enumerable. The long-zero address format is a well-known Hedera convention (documented in HIPs and widely used by EVM tooling), so any developer familiar with Hedera EVM addressing can craft the payload trivially. The attack is fully repeatable and scriptable.

### Recommendation
Add a deletion check after `findById` in the long-zero branch, mirroring the SQL filter used by `findByEvmAddress`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))  // add this
        .filter(e -> e.getType() == type);
}
```

Alternatively, add a dedicated repository method `findByIdAndDeletedIsNotTrue(Long id)` with an explicit `@Query` containing `deleted is not true`, consistent with how `findByAlias` and `findByEvmAddress` are defined, and use that in place of `findById` in this branch. [4](#0-3) 

### Proof of Concept
**Precondition:** A deleted entity exists with numeric ID `12345` (`0x3039`) and type `ACCOUNT`.

**Craft the address** (Python):
```python
import struct
entity_id = 12345
evm_address = "0x" + "00" * 12 + struct.pack(">q", entity_id).hex()
# Result: 0x000000000000000000000000000000000000003039
```

**GraphQL query:**
```graphql
query {
  account(input: { evmAddress: "0x000000000000000000000000000000000000003039" }) {
    id
    memo
    deleted
  }
}
```

**Expected (correct) result:** empty / not found.

**Actual result:** The deleted account record is returned, with `deleted: true` visible in the response, confirming the bypass.

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
