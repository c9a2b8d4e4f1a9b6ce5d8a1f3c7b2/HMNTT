### Title
Deleted Entity Bypass via Long-Zero EVM Address in GraphQL `getByEvmAddressAndType`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, a long-zero EVM address (first 12 bytes all zero, last 8 bytes = entity ID) routes to `entityRepository.findById()`, which is the raw Spring Data `CrudRepository.findById()` with no `deleted is not true` SQL filter. The two custom query methods `findByEvmAddress` and `findByAlias` both carry that filter, but `findById` does not. Any unauthenticated caller can therefore resolve a deleted (destroyed) smart contract entity through the GraphQL API by supplying its long-zero address.

### Finding Description
**Exact code path:**

`EntityServiceImpl.java` lines 34–41:
```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 == 0
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 = entity ID
                               .filter(e -> e.getType() == type);  // only type check, no deleted check
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)      // has "deleted is not true"
                           .filter(e -> e.getType() == type);
}
```

**Root cause:**

`EntityRepository` (graphql) extends `CrudRepository<Entity, Long>` and defines only two custom queries, both with `deleted is not true`:

```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);

@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

`findById` is inherited from `CrudRepository` and issues a plain `SELECT * FROM entity WHERE id = ?` — no `deleted` predicate.

**Exploit flow:**

1. A smart contract with Hedera entity ID `N` is destroyed on-chain; the mirror node sets `deleted = true` for that row.
2. The attacker constructs the long-zero EVM address: `0x` + 12 zero bytes + big-endian 8-byte encoding of `N` (e.g., entity 1234 → `0x0000000000000000000000000000000000000004D2`).
3. The attacker sends a GraphQL query such as:
   ```graphql
   { contract(input: { evmAddress: "0x0000000000000000000000000000000000000004D2" }) { ... } }
   ```
4. `decodeEvmAddress` returns the 20-byte array; `buffer.getInt()` reads bytes 0–3 = 0, `buffer.getLong()` reads bytes 4–11 = 0 → condition is true.
5. `entityRepository.findById(1234)` executes `SELECT * FROM entity WHERE id = 1234` — returns the deleted row.
6. The `.filter(e -> e.getType() == CONTRACT)` passes because the type is still `CONTRACT`.
7. The GraphQL response returns the deleted contract as if it were active.

**Why existing checks fail:**

The only post-fetch check is `e.getType() == type` (line 38). There is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` guard. The `deleted is not true` protection exists only inside the SQL of `findByEvmAddress` and `findByAlias`, neither of which is called on the long-zero path.

### Impact Explanation
Any consumer of the GraphQL API (dApps, wallets, indexers) that queries a contract by its long-zero EVM address will receive a non-empty response for a destroyed contract, making the contract appear active. This can cause callers to believe a contract is live when it has been self-destructed, leading to incorrect application logic, erroneous UI state, or downstream protocol decisions based on stale/invalid contract metadata. The scope classification of "unintended smart contract behavior with no concrete funds at direct risk" is accurate: no funds are moved, but the integrity of contract-state data served by the mirror node is violated.

### Likelihood Explanation
The attack requires zero privileges — the GraphQL endpoint is public. The attacker only needs to know (or enumerate) the numeric entity ID of a deleted contract, which is public information on Hedera (entity IDs are sequential and visible in block explorers). The crafted address is deterministic and the exploit is trivially repeatable for any deleted contract entity.

### Recommendation
Add a `deleted` check on the `findById` branch, either:

1. **In-Java filter (minimal change):**
   ```java
   return entityRepository.findById(buffer.getLong())
       .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
       .filter(e -> e.getType() == type);
   ```

2. **Preferred — add a dedicated repository method with the SQL guard:**
   ```java
   @Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
   Optional<Entity> findByIdAndNotDeleted(long id);
   ```
   and call `findByIdAndNotDeleted(buffer.getLong())` in the service.

Option 2 is consistent with the pattern used by `findByAlias` and `findByEvmAddress` and keeps the deleted-filtering logic in one place (the repository layer).

### Proof of Concept
**Preconditions:**
- Mirror node GraphQL endpoint is reachable.
- A smart contract with Hedera entity ID `1234` (`0x4D2`) exists in the `entity` table with `deleted = true` and `type = 'CONTRACT'`.

**Steps:**
1. Encode the long-zero address: bytes = `[0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0x04,0xD2]` → hex `0x0000000000000000000000000000000000000004D2`.
2. Send the GraphQL query:
   ```graphql
   query {
     contract(input: { evmAddress: "0x0000000000000000000000000000000000000004D2" }) {
       id
       deleted
       type
     }
   }
   ```
3. **Expected (correct) result:** `null` / empty — contract is deleted.
4. **Actual result:** The contract entity is returned with `deleted: true` and `type: CONTRACT`, because `findById` bypasses the `deleted is not true` filter.

**Contrast:** Querying the same contract via its stored `evm_address` column (non-long-zero) correctly returns nothing because `findByEvmAddress` includes `and deleted is not true` in its SQL. [1](#0-0) [2](#0-1)

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
