The code has been verified against the actual repository. All claims check out exactly.

---

# Audit Report

## Title
Deleted Entity Bypass via Long-Zero EVM Address in GraphQL `getByEvmAddressAndType`

## Summary
`EntityServiceImpl.getByEvmAddressAndType()` routes long-zero EVM addresses to the inherited `CrudRepository.findById()`, which issues a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate. Every other lookup path uses custom queries that include `AND deleted is not true`. An unauthenticated caller can therefore retrieve a deleted (destroyed) contract entity through the public GraphQL API by supplying its long-zero EVM address.

## Finding Description
**Exact location:** `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41. [1](#0-0) 

The long-zero branch at line 38 calls `entityRepository.findById(buffer.getLong())`. `EntityRepository` extends `CrudRepository<Entity, Long>` and defines only two custom queries: [2](#0-1) 

Both custom queries carry `AND deleted is not true`. The inherited `findById` does not. The only post-fetch guard on the long-zero path is `.filter(e -> e.getType() == type)` — there is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))`.

**ByteBuffer layout for a 20-byte EVM address:**
- `buffer.getInt()` → bytes 0–3 (must be 0)
- `buffer.getLong()` → bytes 4–11 (must be 0)
- `buffer.getLong()` → bytes 12–19 = entity ID

The condition at line 37 therefore correctly identifies a long-zero address, and the subsequent `findById` call at line 38 returns the row regardless of its `deleted` flag.

**Secondary instance:** `getByIdAndType` at line 25 has the identical pattern — `findById` with only a type filter and no deleted check — though that method requires the caller to already know the numeric `EntityId`. [3](#0-2) 

## Impact Explanation
Any GraphQL consumer (dApp, wallet, indexer) querying a contract by its long-zero EVM address will receive a non-empty, well-formed response for a destroyed contract, making it appear active. This violates the integrity of contract-state data served by the mirror node and can cause incorrect application logic, erroneous UI state, or downstream protocol decisions based on stale metadata. No funds are directly at risk.

## Likelihood Explanation
The GraphQL endpoint requires zero authentication. Hedera entity IDs are sequential and publicly visible in block explorers. The long-zero address for any entity ID `N` is deterministic: `0x` + 12 zero bytes + big-endian 8-byte encoding of `N`. The exploit is trivially repeatable for any deleted contract entity with no special tooling required.

## Recommendation
Add a `deleted` guard on the `findById` path in `EntityServiceImpl.getByEvmAddressAndType()`:

```java
return entityRepository.findById(buffer.getLong())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
        .filter(e -> e.getType() == type);
```

Alternatively, add a dedicated repository method with an explicit SQL predicate:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(long id);
```

Apply the same fix to `getByIdAndType` (line 25), which has the identical missing guard.

## Proof of Concept
1. Identify a destroyed contract with Hedera entity ID `N` (e.g., `N = 1234`; `deleted = true` in the `entity` table).
2. Construct the long-zero EVM address: `0x` + 24 hex zeros + zero-padded big-endian 8-byte encoding of `N` → `0x0000000000000000000000000000000000000004D2`.
3. Send the GraphQL query:
   ```graphql
   { contract(input: { evmAddress: "0x0000000000000000000000000000000000000004D2" }) { contractId deleted } }
   ```
4. `decodeEvmAddress` returns the 20-byte array; `buffer.getInt()` = 0, `buffer.getLong()` = 0 → long-zero branch taken.
5. `entityRepository.findById(1234)` executes `SELECT * FROM entity WHERE id = 1234` — returns the deleted row.
6. `.filter(e -> e.getType() == CONTRACT)` passes; no deleted filter exists.
7. The GraphQL response returns the deleted contract as if it were active, with `deleted: true` visible in the payload — confirming the bypass.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L33-41)
```java
    @Override
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
