### Title
Deleted Entity Disclosure via Long-Zero EVM Address in GraphQL `getByEvmAddressAndType()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when the input EVM address has its first 12 bytes all zero (a "long-zero" address), the code routes to `entityRepository.findById()` — a plain Spring Data `CrudRepository` method with no `deleted is not true` filter. Any unauthenticated user who knows a deleted entity's numeric ID can craft such an address and retrieve the deleted entity through the GraphQL API, bypassing the deletion filter that protects the `findByEvmAddress()` path.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, `getByEvmAddressAndType()`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // first 12 bytes == 0
        return entityRepository.findById(buffer.getLong())         // ← NO deleted filter
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)      // ← has deleted filter
                           .filter(e -> e.getType() == type);
}
```

**Root cause:**

`entityRepository` is the GraphQL-module `EntityRepository` which extends `CrudRepository<Entity, Long>`. The `findById()` call at line 38 is the standard Spring Data method — it generates `SELECT * FROM entity WHERE id = ?` with no additional predicate. In contrast, `findByEvmAddress()` at line 40 is a custom `@Query` that explicitly appends `AND deleted is not true`:

```java
// graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java, line 16-17
@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

The `findById()` branch has no equivalent guard.

**Exploit flow:**

1. Attacker learns (or enumerates) the numeric entity ID of a deleted Hashgraph entity (e.g., ID = `1234`).
2. Attacker constructs a long-zero EVM address: 12 zero bytes followed by the 8-byte big-endian representation of `1234` → `0x000000000000000000000000000004D2`.
3. Attacker sends a GraphQL query using this address (e.g., querying an account or contract by EVM address).
4. The `buffer.getInt() == 0 && buffer.getLong() == 0` check at line 37 passes, routing to `findById(1234)`.
5. Spring Data executes `SELECT * FROM entity WHERE id = 1234` — no `deleted` filter — and returns the deleted entity.
6. The only remaining check is `.filter(e -> e.getType() == type)`, which only validates entity type, not deletion status.

### Impact Explanation

Any deleted Hashgraph entity — accounts, contracts, tokens, topics — that should be hidden from the public historical record can be retrieved in full by any unauthenticated external caller via the GraphQL endpoint. This directly violates the integrity of the mirror node's view of Hashgraph history: entities that were deleted and should no longer be visible are exposed, enabling information disclosure about the state of the network at any point in time.

### Likelihood Explanation

No privileges are required. Entity IDs are sequential integers and are publicly observable from the Hashgraph network and mirror node REST API. An attacker can trivially enumerate IDs, construct the corresponding long-zero EVM address, and query the GraphQL endpoint. The attack is fully repeatable and requires no special tooling beyond a standard HTTP client.

### Recommendation

Replace `entityRepository.findById()` in the long-zero branch with a query that also enforces `deleted is not true`. The simplest fix is to add a custom repository method analogous to `findByEvmAddress`:

```java
// In EntityRepository (graphql module):
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(long id);
```

Then update `getByEvmAddressAndType()` line 38:

```java
return entityRepository.findByIdAndNotDeleted(buffer.getLong())
                       .filter(e -> e.getType() == type);
```

Also audit `getByIdAndType()` (line 24–26) for the same issue, as it also calls `findById()` without a deletion filter.

### Proof of Concept

**Precondition:** A deleted entity exists in the mirror node DB with `id = 1234` and `deleted = true`.

**Step 1 — Construct the long-zero EVM address:**
```
bytes[0..11]  = 0x000000000000000000000000   (12 zero bytes)
bytes[12..19] = 0x00000000000004D2            (1234 in big-endian 8 bytes)
Full address  = 0x000000000000000000000000000004D2  (pad to 20 bytes if needed)
```

**Step 2 — Send GraphQL query (example for account type):**
```graphql
query {
  account(input: { evmAddress: "0x000000000000000000000000000004D2" }) {
    id
    deleted
    balance
  }
}
```

**Step 3 — Observe result:**
The deleted entity is returned with its full data, including `deleted: true`, confirming the bypass. The `findByEvmAddress()` path would have returned empty for the same entity. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-12)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```
