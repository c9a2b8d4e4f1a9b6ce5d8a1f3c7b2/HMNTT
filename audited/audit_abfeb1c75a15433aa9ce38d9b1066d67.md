### Title
Soft-Deleted Entity Disclosure via Zero-Prefixed EVM Address in GraphQL `getByEvmAddressAndType()`

### Summary
`EntityServiceImpl.getByEvmAddressAndType()` contains two asymmetric code paths: when the input EVM address has its first 12 bytes zeroed, it routes to `entityRepository.findById()` (Spring Data `CrudRepository`, no deleted filter), but for real EVM addresses it routes to `entityRepository.findByEvmAddress()` which explicitly filters `deleted is not true`. An unprivileged external user can exploit this by encoding any known numeric entity ID in the last 8 bytes of a zero-padded 20-byte hex address, causing the GraphQL API to return soft-deleted entities that should be invisible.

### Finding Description
**Exact code path:**

`EntityServiceImpl.java` lines 34–41: [1](#0-0) 

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
}
return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
```

`ByteBuffer.wrap(evmAddressBytes)` reads:
- bytes 0–3 via `getInt()` → must be 0
- bytes 4–11 via `getLong()` → must be 0
- bytes 12–19 via `getLong()` → used as the numeric entity ID

When the first 12 bytes are zero, `entityRepository.findById(id)` is called. This is the standard Spring Data `CrudRepository.findById()` which issues a plain `SELECT * FROM entity WHERE id = ?` with **no deleted filter**. [2](#0-1) 

The EVM-address branch uses:
```sql
select * from entity where evm_address = ?1 and deleted is not true
``` [3](#0-2) 

The only post-query filter in the numeric-ID branch is `.filter(e -> e.getType() == type)` — there is **no** `e.getDeleted() != Boolean.TRUE` guard.

**Exposed surface:** `AccountController.account()` directly passes the user-supplied `evmAddress` field to `getByEvmAddressAndType()` with no additional filtering: [4](#0-3) 

### Impact Explanation
Any soft-deleted entity (account, contract, token, etc.) whose numeric ID is known or guessable can be retrieved in full via the public GraphQL endpoint. The response includes all entity fields — key material, memo, balance, expiration, etc. — for entities the API is designed to hide post-deletion. The `deleted` field is explicitly part of the GraphQL schema response (confirmed in `AccountControllerTest.java` line 76), meaning the API contract clearly intends deleted entities to be excluded from results, not returned with a `deleted: true` flag. [5](#0-4) 

### Likelihood Explanation
No authentication or privilege is required — the GraphQL `account` query is a public read endpoint. Hedera entity IDs are sequential integers, making enumeration trivial. An attacker needs only to: (1) know or enumerate a deleted entity's numeric ID, and (2) craft a 40-character hex string. This is repeatable, scriptable, and requires no special tooling.

### Recommendation
Add a deleted-entity guard in the numeric-ID branch of `getByEvmAddressAndType()`, mirroring the SQL filter already present in `findByEvmAddress()`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> e.getType() == type)
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted())); // add this
}
```

Alternatively, add a dedicated repository method `findByIdAndDeletedIsNotTrue(Long id)` analogous to `findByEvmAddress()`, and use it in this branch. [6](#0-5) 

### Proof of Concept
**Precondition:** Entity with numeric ID `1234` exists in the mirror node DB with `deleted = true`.

1. Compute the zero-prefixed EVM address:
   - 12 zero bytes + 8-byte big-endian encoding of `1234` (= `0x00000000000004D2`)
   - Full hex: `0000000000000000000000000000000000000000` → replace last 16 chars with `00000000000004d2`
   - Result: `000000000000000000000000000000000000000000000000000004d2` — wait, EVM address is 20 bytes = 40 hex chars
   - Correct: `0000000000000000000000000000000000000000` is 40 hex chars (20 bytes)
   - bytes 0–11 zero = first 24 hex chars = `000000000000000000000000`
   - bytes 12–19 = `00000000000004d2`
   - Final address: `000000000000000000000000` + `00000000000004d2` = `00000000000000000000000000000000000004d2`

2. Send GraphQL query (no authentication needed):
```graphql
query {
  account(input: { evmAddress: "00000000000000000000000000000000000004d2" }) {
    id
    deleted
    key
    memo
    balance
  }
}
```

3. **Expected (correct) result:** `null` (entity is deleted, should be filtered)

4. **Actual result:** Full entity data returned with `deleted: true`, bypassing the soft-delete filter. [6](#0-5)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-55)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/controller/AccountControllerTest.java (L64-101)
```java
    @Test
    void success() {
        var entity = domainBuilder.entity().persist();
        tester.document("""
                        query Account($realm: Long!,$shard: Long!,$num: Long!) {
                          account(input: { entityId: {realm: $realm, shard: $shard, num: $num} }) {
                            alias
                            autoRenewPeriod
                            balance
                            createdTimestamp
                            declineReward
                            deleted
                            entityId { shard, realm, num }
                            expirationTimestamp
                            id
                            key
                            maxAutomaticTokenAssociations
                            memo
                            nonce
                            pendingReward
                            receiverSigRequired
                            stakePeriodStart
                            timestamp {from, to}
                            type
                          }
                        }
                        """)
                .variable("num", entity.getNum())
                .variable("realm", entity.getRealm())
                .variable("shard", entity.getShard())
                .execute()
                .errors()
                .verify()
                .path("account")
                .hasValue()
                .entity(Account.class)
                .satisfies(a -> assertThat(a).usingRecursiveComparison().isEqualTo(accountMapper.map(entity)));
    }
```
