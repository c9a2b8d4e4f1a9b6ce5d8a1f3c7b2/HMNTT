### Title
Deleted Entity Exposure via Long-Zero EVM Address Bypass of `deleted is not true` Filter

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when a "long-zero" EVM address is supplied (first 12 bytes all zero), the code falls back to `entityRepository.findById()` (inherited from `CrudRepository`) instead of `entityRepository.findByEvmAddress()`. The `findById` path carries no `deleted is not true` filter, while `findByEvmAddress` does. An unprivileged attacker can therefore retrieve deleted entities through the GraphQL API by crafting a long-zero EVM address from any known Hedera account/contract numeric ID.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 all zero
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 = entity ID
                               .filter(e -> e.getType() == type); // NO deleted filter
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)      // has deleted filter
                           .filter(e -> e.getType() == type);
}
```

**Root cause:**

`findByEvmAddress` is defined in `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` line 16–17 with an explicit SQL guard:

```sql
select * from entity where evm_address = ?1 and deleted is not true
```

But the long-zero branch calls `CrudRepository.findById()`, which issues a plain `SELECT * FROM entity WHERE id = ?` with no deleted predicate. The `Entity` domain class (`common/src/main/java/org/hiero/mirror/common/domain/entity/Entity.java`) carries no JPA-level `@SQLRestriction` or `@Where` annotation, so no automatic filtering occurs.

The only post-query check is `.filter(e -> e.getType() == type)`, which tests entity type but never tests `deleted`.

**Exploit flow:**

1. Attacker identifies a deleted Hedera account/contract by its numeric ID (e.g., ID = 12345, publicly visible on-chain).
2. Attacker constructs a 20-byte long-zero EVM address: bytes 0–11 = `0x00`, bytes 12–19 = big-endian encoding of 12345 → `0x0000000000000000000000000000000000003039`.
3. Attacker sends a GraphQL query:
   ```graphql
   query { account(input: { evmAddress: "0000000000000000000000000000000000003039" }) { id deleted balance key } }
   ```
4. `decodeEvmAddress` decodes the hex; `buffer.getInt()` = 0, `buffer.getLong()` = 0 → long-zero branch taken.
5. `entityRepository.findById(12345)` returns the deleted entity (no filter).
6. `.filter(e -> e.getType() == ACCOUNT)` passes if the entity is an account.
7. `AccountController` maps and returns the full deleted entity to the caller.

### Impact Explanation

A deleted account or contract that should be invisible to the outside world is fully returned by the GraphQL API, including its key material, balance history, memo, and other fields. This directly misrepresents the current state of the Hashgraph: callers receive a non-null account object for an entity that has been deleted, which can be used to mislead downstream systems about account existence, balances, or key ownership. Severity is **medium-high**: no authentication is required, the data returned is real historical ledger data, and the bypass is complete (no partial mitigation exists in the long-zero path).

### Likelihood Explanation

Hedera account and contract IDs are sequential integers that are publicly broadcast in every transaction. Any observer of the network can enumerate deleted account IDs. Constructing the corresponding long-zero EVM address requires only basic hex encoding. The attack requires zero privileges, no special tooling, and is trivially repeatable for any known deleted entity ID.

### Recommendation

Add an explicit deleted-status check in the long-zero branch, mirroring the filter already present in `findByEvmAddress`. The simplest fix is to add `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` after `findById`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
            .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
            .filter(e -> e.getType() == type);
}
```

Alternatively, replace `findById` with a dedicated repository method that mirrors the SQL guard:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

### Proof of Concept

**Precondition:** Entity with ID 12345 exists in the database with `deleted = true` and `type = 'ACCOUNT'`.

**Step 1 – Construct the long-zero address:**
```
bytes 0-11:  000000000000000000000000  (12 zero bytes)
bytes 12-19: 0000000000003039          (big-endian 12345)
full hex:    0000000000000000000000000000000000003039
```

**Step 2 – Send GraphQL request:**
```graphql
query {
  account(input: { evmAddress: "0000000000000000000000000000000000003039" }) {
    id
    deleted
    balance
    key
  }
}
```

**Expected result (correct behavior):** `"account": null`

**Actual result (vulnerable behavior):** Full account object returned with `"deleted": true`, exposing the entity's fields.

**Verification that `findByEvmAddress` would block it:** Querying with the entity's actual stored `evm_address` value (if different) returns null because `deleted is not true` filters it out — confirming the bypass is specific to the long-zero path.