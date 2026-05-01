### Title
Deleted CONTRACT Entity Exposed via Long-Zero EVM Address Path in `getByEvmAddressAndType()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when a "long-zero" EVM address is supplied (first 12 bytes all zero), the code routes to `entityRepository.findById()`, which is the unfiltered Spring Data `CrudRepository` default and applies no `deleted` check. The custom-EVM-address path uses `entityRepository.findByEvmAddress()`, which explicitly filters `deleted is not true`. Any unprivileged user can exploit this asymmetry to retrieve full metadata for a deleted CONTRACT entity by encoding its numeric ID as a long-zero address, receiving a populated GraphQL response where the custom-EVM-address path would return nothing.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // long-zero branch
        return entityRepository.findById(buffer.getLong())         // ← NO deleted filter
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)      // ← deleted is not true
                           .filter(e -> e.getType() == type);
}
```

`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, lines 16–17:

```java
@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

`findById()` is the inherited `CrudRepository.findById(Long id)` — it generates `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate. The repository does not override it.

**Root cause:** The long-zero branch assumes that a numeric-ID lookup is safe without a deletion guard, while the custom-EVM-address branch explicitly guards against deleted rows. The only post-fetch filter applied in both branches is a type check (`.filter(e -> e.getType() == type)`), which does not check `deleted`.

**Exploit flow:**
1. A CONTRACT entity with `id = N` is deleted on-chain; the mirror node sets `deleted = true` in the `entity` table.
2. The attacker constructs the long-zero EVM address for entity N: 20 bytes where bytes 0–11 are `0x00` and bytes 12–19 are the big-endian encoding of N (e.g., for N=100: `0x0000000000000000000000000000000000000064`).
3. The attacker sends a GraphQL query: `contract(input: { evmAddress: "0x0000000000000000000000000000000000000064" })`.
4. `buffer.getInt() == 0` (bytes 0–3) and `buffer.getLong() == 0` (bytes 4–11) → long-zero branch taken.
5. `findById(100L)` returns the deleted entity; `.filter(e -> e.getType() == CONTRACT)` passes.
6. The full entity record — including `key`, `memo`, `adminKey`, `expirationTimestamp`, `obtainerId`, etc. — is returned in the GraphQL response, with `deleted: true` present but the record fully populated.

**Why existing checks are insufficient:** The `.filter(e -> e.getType() == type)` guard only enforces entity type, not lifecycle state. There is no `deleted` check anywhere in the long-zero branch. The `findByAlias` path also has `deleted is not true` (line 13 of `EntityRepository.java`), making the long-zero branch the sole unguarded lookup in the service.

### Impact Explanation

A dApp or smart contract tooling layer that uses the GraphQL mirror node API to resolve a contract by its long-zero EVM address before dispatching an on-chain call will receive a fully populated response for a deleted contract. If the client does not explicitly inspect the `deleted` field (a common omission when the same address format returns empty for the custom-EVM path), it may treat the deleted contract as live and proceed with on-chain interactions — resulting in failed transactions, incorrect state assumptions, or misleading UI state. The inconsistency between the two address-format paths for the same underlying entity is the direct protocol-level defect: the same deleted contract returns data via one path and nothing via the other, violating the principle of least surprise and creating divergent client behavior depending solely on address encoding.

### Likelihood Explanation

No authentication or privilege is required. The attacker needs only to know (or enumerate) the numeric entity ID of a deleted contract — IDs are sequential and publicly observable from any block explorer or mirror node REST API. The exploit is a single GraphQL POST request, fully repeatable, and requires no special tooling beyond a standard HTTP client. Any deleted contract that was ever assigned a numeric ID is permanently exploitable via this path.

### Recommendation

Add a `deleted` guard to the long-zero branch in `getByEvmAddressAndType()`, consistent with the custom-EVM-address path. The simplest fix is to add a custom repository method with an explicit filter:

```java
// In EntityRepository.java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then replace line 38 in `EntityServiceImpl.java`:

```java
// Before
return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
// After
return entityRepository.findByIdAndNotDeleted(buffer.getLong()).filter(e -> e.getType() == type);
```

The same fix should be applied to `getByIdAndType()` (line 25) for consistency, since it also uses the unfiltered `findById()`.

### Proof of Concept

**Precondition:** A CONTRACT entity with `id = 100` exists in the mirror node DB with `deleted = true`.

**Step 1 — Verify the entity is deleted (custom EVM address path returns nothing):**
```graphql
# Assuming the contract has a custom EVM address stored in evm_address column
POST /graphql/alpha
{
  contract(input: { evmAddress: "<custom_evm_address_of_contract_100>" }) {
    deleted
    memo
    key
  }
}
# Result: { "data": { "contract": null } }
```

**Step 2 — Query via long-zero address (bypasses deleted filter):**
```graphql
POST /graphql/alpha
{
  contract(input: { evmAddress: "0x0000000000000000000000000000000000000064" }) {
    deleted
    memo
    key
    expirationTimestamp
  }
}
# Result: { "data": { "contract": { "deleted": true, "memo": "...", "key": "...", "expirationTimestamp": ... } } }
```

The long-zero address `0x0000000000000000000000000000000000000064` encodes entity ID 100 (`0x64`). The response is fully populated despite `deleted: true`, while the custom-EVM-address path returns `null` for the same entity. [1](#0-0) [2](#0-1)

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
