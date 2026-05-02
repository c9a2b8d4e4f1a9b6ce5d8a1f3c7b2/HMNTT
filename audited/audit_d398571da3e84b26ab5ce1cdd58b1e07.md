### Title
Deleted Entity Returned via Long-Zero EVM Address in `getByEvmAddressAndType()`

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when the input EVM address matches the Hedera "long-zero" format (first 12 bytes are zero, last 8 bytes encode a numeric entity ID), the code dispatches to `entityRepository.findById()` — a plain Spring Data `CrudRepository` method with no `deleted` filter. In contrast, the non-long-zero path calls `entityRepository.findByEvmAddress()`, which explicitly enforces `deleted is not true`. Any unprivileged caller can craft a long-zero address encoding a deleted account's ID and receive the deleted entity back as if it were active.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
@Override
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        // ← dispatches to findById — NO deleted filter
        return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
    }
    // ← dispatches to findByEvmAddress — has "deleted is not true"
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

**Root cause:**

`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`:

```java
// Filters deleted:
@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);

// findById() — inherited from CrudRepository<Entity, Long>
// Executes: SELECT * FROM entity WHERE id = ?
// NO deleted filter whatsoever.
```

The `findById` method is the standard Spring Data `CrudRepository` method. It performs a plain `SELECT * FROM entity WHERE id = ?` with no predicate on the `deleted` column. The only post-fetch filter applied is `.filter(e -> e.getType() == type)` — a type check, not a deletion check.

**Exploit flow:**

1. Attacker identifies (or enumerates) the numeric ID of a deleted account, e.g., ID `12345`.
2. Constructs the long-zero EVM address: 12 zero bytes followed by the 8-byte big-endian encoding of `12345` → `0x0000000000000000000000000000000000003039`.
3. Sends a GraphQL query to the public `/graphql/alpha` endpoint:
   ```graphql
   { account(input: { evmAddress: "0x0000000000000000000000000000000000003039" }) {
       deleted entityId { num } balance key
   }}
   ```
4. `AccountController` calls `entityService.getByEvmAddressAndType(evmAddress, ACCOUNT)`.
5. `getByEvmAddressAndType` detects the long-zero pattern (`getInt()==0 && getLong()==0`), calls `entityRepository.findById(12345)`.
6. Spring Data returns the deleted entity row with no filtering.
7. The `.filter(e -> e.getType() == type)` passes (type is still ACCOUNT).
8. The deleted entity is returned to the caller.

**Why existing checks fail:**

The only guard after `findById` is `.filter(e -> e.getType() == type)`. There is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` or equivalent. The `findByEvmAddress` path has the deletion guard baked into SQL, but the long-zero path entirely bypasses it. [1](#0-0) [2](#0-1) 

### Impact Explanation

The GraphQL API is a public read-only mirror node interface used by wallets, dApps, and integrations to resolve EVM addresses to Hedera account data. When a deleted account is returned as a non-null result, callers that do not explicitly inspect the `deleted` field (which is optional in the schema) will treat the account as active. This can cause:

- A wallet or dApp to display a deleted account as a valid recipient and prompt the user to send funds to it. The Hedera network will reject the transaction, but the user experience is broken and funds may be locked in a failed transaction flow.
- Smart contract tooling or bridges that use the mirror node to resolve addresses before constructing transactions may route calls to deleted accounts.
- The inconsistency between the two lookup paths (long-zero returns deleted; regular EVM address does not) violates the API contract and creates unpredictable behavior for any caller that uses both paths. [3](#0-2) 

### Likelihood Explanation

- **No privileges required.** The `/graphql/alpha` endpoint is publicly accessible. Any user can submit a GraphQL query.
- **Trivial to craft.** The long-zero address format is a well-known Hedera convention. Encoding any numeric ID into the last 8 bytes of a 20-byte zero-padded address is a one-line operation.
- **Deleted account IDs are discoverable.** The mirror node's own REST API exposes historical account data including deleted accounts, making target ID enumeration straightforward.
- **Repeatable.** The bug is deterministic: every long-zero address for a deleted account will return that account.

### Recommendation

Add a deleted-entity guard in the long-zero branch of `getByEvmAddressAndType`, mirroring the SQL filter already present in `findByEvmAddress`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))  // ← add this
        .filter(e -> e.getType() == type);
}
```

Alternatively, introduce a dedicated repository method `findByIdAndDeletedIsNotTrue(Long id)` with an explicit `@Query` (consistent with the pattern already used in the `web3` module's `EntityRepository.findByIdAndDeletedIsFalse`), and use that in both the long-zero branch here and in `getByIdAndType`. [4](#0-3) [5](#0-4) 

### Proof of Concept

**Preconditions:**
- A Hedera account with numeric ID `N` exists in the mirror node database with `deleted = true`.

**Steps:**

1. Compute the long-zero EVM address for ID `N`:
   ```python
   import struct
   N = 12345  # target deleted account ID
   addr = b'\x00' * 12 + struct.pack('>q', N)  # 20 bytes
   hex_addr = '0x' + addr.hex()
   # → "0x0000000000000000000000000000000000003039"
   ```

2. Send the GraphQL query (no authentication required):
   ```bash
   curl -X POST https://<mirror-node>/graphql/alpha \
     -H 'Content-Type: application/json' \
     -d '{"query":"{ account(input: { evmAddress: \"0x0000000000000000000000000000000000003039\" }) { deleted entityId { num } balance } }"}'
   ```

3. **Expected (correct) response:** `{ "data": { "account": null } }` — deleted account should not be returned.

4. **Actual response:**
   ```json
   {
     "data": {
       "account": {
         "deleted": true,
         "entityId": { "num": 12345 },
         "balance": 0
       }
     }
   }
   ```

The deleted account is returned. Any caller that checks only for a non-null `account` response (without inspecting `deleted`) will treat this as an active account. [1](#0-0) [3](#0-2)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-54)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
```
