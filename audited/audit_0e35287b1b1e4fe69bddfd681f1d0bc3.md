### Title
Deleted Entity Disclosure via Long-Zero EVM Address Bypassing `deleted is not true` Filter

### Summary
`EntityServiceImpl.getByEvmAddressAndType()` contains two distinct lookup branches: a long-zero address branch that calls `entityRepository.findById()` (Spring Data's unfiltered `CrudRepository.findById()`), and a normal EVM address branch that calls `entityRepository.findByEvmAddress()` which enforces `deleted is not true`. An unprivileged attacker can craft a long-zero EVM address encoding any deleted entity's numeric ID to force the `findById()` branch, retrieving a deleted entity that the `findByEvmAddress()` branch would have suppressed.

### Finding Description
**Exact code path:**

`EntityServiceImpl.getByEvmAddressAndType()` — [1](#0-0) 

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
}
return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
```

The long-zero detection reads bytes 0–3 as an `int` and bytes 4–11 as a `long`; if both are zero, bytes 12–19 are read as a `long` and passed directly to `findById()`. [2](#0-1) 

**Root cause — asymmetric deletion filtering:**

`findByEvmAddress()` explicitly enforces `deleted is not true`: [3](#0-2) 

`findById()` is the bare Spring Data `CrudRepository.findById()` — it issues a plain `SELECT * FROM entity WHERE id = ?` with no deletion predicate. There is no post-call deleted check anywhere in `EntityServiceImpl`, `EntityService`, or `AccountController`. [4](#0-3) 

**Exploit flow:**

1. Attacker learns (or enumerates) the numeric entity ID of a deleted account (e.g., `12345`).
2. Attacker constructs a 20-byte long-zero EVM address: `0x000000000000000000000000000000000000<ID_as_8_bytes>` — e.g., `0x0000000000000000000000000000000000003039` for ID 12345.
3. Attacker sends a GraphQL `account(input: {evmAddress: "0x0000000000000000000000000000000000003039"})` query.
4. `getByEvmAddressAndType()` detects bytes 0–11 are zero, calls `findById(12345)`.
5. Spring Data returns the deleted entity row without any deletion filter.
6. The entity is mapped to an `Account` view model and returned to the attacker.

### Impact Explanation
The attacker receives the full `Entity` record for a deleted account — including fields such as account balance at deletion time, key material, memo, and any other fields exposed by the GraphQL `Account` type. If the GraphQL schema exposes transaction history through the `Account` type (consistent with the described scope of "reorganizing transaction history"), historical transaction data for deleted accounts becomes accessible to any unauthenticated caller. This is an information-disclosure vulnerability with no authentication requirement.

### Likelihood Explanation
No privileges are required. The GraphQL endpoint is publicly accessible. Entity numeric IDs are sequential and trivially enumerable. The long-zero address format is a well-known Hedera convention (documented in HIPs), so any attacker familiar with Hedera's addressing scheme will know to attempt it. The attack is fully repeatable and requires only a single crafted GraphQL query per target entity.

### Recommendation
Add an explicit `deleted is not true` guard in the `findById()` branch of `getByEvmAddressAndType()`. The simplest fix is a post-fetch filter:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> e.getType() == type)
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted())); // add this
}
```

Alternatively, introduce a dedicated repository method analogous to `findByEvmAddress` that includes the deletion predicate:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

and use it in both the long-zero and `getByIdAndType()` branches for consistency.

### Proof of Concept
**Precondition:** Entity with numeric ID `N` exists in the `entity` table with `deleted = true`.

**Step 1 — Encode the long-zero address:**
```
bytes[0..3]  = 0x00000000
bytes[4..11] = 0x0000000000000000
bytes[12..19] = N as big-endian 8-byte long
```
For N = 1000 (0x3E8): address = `0x00000000000000000000000000000000000003E8`

**Step 2 — Send GraphQL query:**
```graphql
query {
  account(input: { evmAddress: "0x00000000000000000000000000000000000003E8" }) {
    id
    balance
    memo
  }
}
```

**Expected (correct) result:** `null` (entity is deleted).

**Actual result:** The deleted entity's data is returned, because `findById()` at line 38 of `EntityServiceImpl.java` has no deletion filter. [5](#0-4)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
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
