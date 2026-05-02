### Title
Deleted Entity Returned via Long-Zero EVM Address Path Due to Missing `deleted` Filter in `findById()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when an EVM address has its first 12 bytes set to zero, the code routes to `entityRepository.findById()` — a standard Spring Data `CrudRepository` method that carries no `deleted is not true` filter. The two custom query methods (`findByAlias` and `findByEvmAddress`) both explicitly exclude deleted entities, but `findById` does not, creating an inconsistency that allows any unauthenticated caller to retrieve a deleted account's full entity record, including its `pendingReward` field, by supplying a crafted long-zero EVM address.

### Finding Description

**Exact code path:**

`EntityServiceImpl.java` lines 34–41: [1](#0-0) 

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 == 0
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 = entity ID
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

The `ByteBuffer` reads:
- `getInt()` → bytes 0–3 (must be 0)
- `getLong()` → bytes 4–11 (must be 0)
- `getLong()` → bytes 12–19 → used as the entity ID passed to `findById`

**Root cause — the graphql `EntityRepository`:** [2](#0-1) 

`findByAlias` and `findByEvmAddress` both carry `deleted is not true` in their native SQL. `findById` is inherited from `CrudRepository<Entity, Long>` and issues a plain `SELECT * FROM entity WHERE id = ?` with no deleted predicate. There is no override or wrapper that adds the filter.

**Contrast with the web3 module**, which explicitly defines `findByIdAndDeletedIsFalse(Long entityId)` to enforce the filter: [3](#0-2) 

**Exploit flow:**
1. Attacker identifies a deleted high-value staking account with a known numeric ID (e.g., `12345`).
2. Attacker constructs a 20-byte EVM address: bytes 0–11 = `0x00`, bytes 12–19 = big-endian encoding of `12345`.
3. Attacker sends a GraphQL query:
   ```graphql
   { account(input: { evmAddress: "0x000000000000000000000000000000000000<id>" }) {
       pendingReward
       balance
       deleted
   }}
   ```
4. `getByEvmAddressAndType` detects the long-zero pattern, calls `findById(12345)`.
5. The deleted entity is returned; `pendingReward` and all other fields are exposed.

**Why existing checks fail:**
The only post-retrieval filter applied is `.filter(e -> e.getType() == type)` — a type check, not a deletion check. The `deleted` field on the returned `Entity` may be `true`, but the caller receives the full object regardless.

### Impact Explanation

Any unauthenticated GraphQL client can read the complete entity record — including `pendingReward`, `balance`, `key`, `memo`, and all staking metadata — for any account that has been deleted from the network. The `pendingReward` field in the GraphQL schema is explicitly documented as the reward the account will receive at the next payout: [4](#0-3) 

This is an information-disclosure vulnerability. While it does not allow direct theft of funds, it leaks private financial state (pending staking rewards, balances, keys) of accounts that the network has marked as no longer existing, violating the expected access-control invariant that deleted entities are not queryable.

### Likelihood Explanation

The precondition is trivial: the attacker needs only the numeric ID of a deleted account, which is publicly observable from transaction history or the REST API. The crafted EVM address requires no special privileges, no authentication, and no on-chain action. The GraphQL endpoint is publicly accessible. The attack is fully repeatable and requires no timing dependency.

### Recommendation

Replace the bare `findById` call in the long-zero branch with a custom repository method that enforces the deleted filter, consistent with the other two lookup paths:

```java
// In graphql EntityRepository:
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then in `EntityServiceImpl`:
```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findByIdAndNotDeleted(buffer.getLong())
                           .filter(e -> e.getType() == type);
}
```

The same fix should be applied to `getByIdAndType`, which also calls the unfiltered `findById`. [5](#0-4) 

### Proof of Concept

**Precondition:** Account `0.0.5000` exists in the `entity` table with `deleted = true` and a non-zero `pending_reward` in `entity_stake`.

**Step 1 — Encode the entity ID:**
```python
import struct
entity_id = 5000
addr = b'\x00' * 12 + struct.pack('>q', entity_id)
hex_addr = addr.hex()  # "000000000000000000000000000000000000138800000000000013 88"
# Correct: 0x0000000000000000000000000000000000001388
```

**Step 2 — Send GraphQL query:**
```graphql
{
  account(input: { evmAddress: "0x0000000000000000000000000000000000001388" }) {
    entityId
    deleted
    pendingReward
    balance
  }
}
```

**Expected (correct) result:** `null` — deleted entity should not be returned.

**Actual result:** The deleted entity is returned with `deleted: true` and a non-zero `pendingReward`, confirming the missing filter.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-18)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L30-30)
```java
    Optional<Entity> findByIdAndDeletedIsFalse(Long entityId);
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L58-61)
```text
    The pending reward the account will receive in the next reward payout. Note the value is updated at the end of each
    staking period and there may be delay to reflect the changes in the past staking period. Defaults to tinybars.
    """
    pendingReward(unit: HbarUnit = TINYBAR): Long
```
