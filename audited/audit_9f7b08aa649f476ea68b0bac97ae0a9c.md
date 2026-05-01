### Title
Long-Zero EVM Address Bypass Returns Entity With Mismatched Real EVM Address

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when the first 4 bytes (shard) and next 8 bytes (realm) of a supplied EVM address are zero, the code skips the EVM address database lookup and instead performs a direct entity-ID lookup using the last 8 bytes. There is no subsequent check that the entity found by ID actually lacks a real EVM address. An unprivileged attacker can craft a long-zero address encoding any known entity ID and receive back an entity whose stored EVM address is entirely different from the queried address, causing the mirror node to export incorrect EVM-address-to-entity mappings.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-3 and 4-11
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 as entity ID
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

**Root cause:** The branch taken when `shard==0 && realm==0` calls `findById()` and returns whatever entity has that numeric ID, with no guard verifying that the returned entity's `evmAddress` field is null/empty. The long-zero format is only semantically valid for entities that have *no* real EVM address. Entities created via CREATE2 (or any contract with an explicit EVM address stored in the `evm_address` column) have a real, distinct EVM address. Returning such an entity for a crafted long-zero query is incorrect.

**Failed assumption:** The code assumes that if the first 12 bytes are zero, the address must be a long-zero alias for an entity that has no real EVM address. This assumption is never enforced.

**Exploit flow:**
1. Attacker identifies a target entity (e.g., a CREATE2 contract) with entity ID `0.0.N` and real EVM address `0xABCD…`. Both pieces of information are public on Hedera.
2. Attacker constructs the long-zero address: `0x` + 24 hex zeros + `N` zero-padded to 16 hex digits (e.g., for N=1000: `0x00000000000000000000000000000000000003E8`).
3. Attacker sends a GraphQL query to the mirror node:
   ```graphql
   { account(input: { evmAddress: "0x00000000000000000000000000000000000003E8" }) { ... } }
   ```
4. `getByEvmAddressAndType` sees bytes 0–11 are zero, calls `findById(1000)`, and returns the entity for `0.0.1000`.
5. The returned entity has `evmAddress = 0xABCD…`, not `0x000…03E8`. The mirror node has exported an incorrect record: it asserts that `0x000…03E8` maps to this entity, which is false.

**Why existing checks are insufficient:** The only filter applied after `findById` is `e.getType() == type` (line 38). There is no check on `e.getEvmAddress()`. The `@Pattern` constraint on the GraphQL input (`^(0x)?[a-fA-F0-9]{40}$`) only validates hex format, not semantic correctness. The test `getByIdAsEvmAddressAndTypeFound` in `EntityServiceTest.java` (lines 147–155) uses `domainBuilder.entity().get()` which generates entities with random real EVM addresses, yet asserts the entity is returned — confirming the test itself validates the buggy behavior.

### Impact Explanation
The mirror node returns an entity record for an EVM address that does not match the entity's actual stored EVM address. Any downstream system (wallets, DeFi protocols, block explorers) that trusts the mirror node's EVM-address-to-entity mapping will receive incorrect data. In EVM-compatible tooling, this can cause incorrect contract address resolution: a tool querying `0x000…03E8` would be told it corresponds to a contract whose real address is `0xABCD…`, breaking address-based access control assumptions and potentially misdirecting funds or calls.

### Likelihood Explanation
Exploitation requires zero privileges — only a valid GraphQL HTTP request. Entity IDs are public and enumerable from the Hedera ledger. The attacker needs only to know that a target entity has a real EVM address (also public). The crafted address is trivially constructed. The attack is repeatable for any entity with a real EVM address in the system.

### Recommendation
After `findById` succeeds in the long-zero branch, add a guard that rejects the result if the entity has a non-empty real EVM address:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
            .filter(e -> e.getType() == type)
            .filter(e -> e.getEvmAddress() == null || e.getEvmAddress().length == 0);
}
```

This ensures the long-zero lookup only succeeds for entities that genuinely have no real EVM address, which is the only case where the long-zero format is semantically valid.

### Proof of Concept
**Precondition:** A contract entity exists in the mirror node DB with entity ID `0.0.1000` and a real EVM address `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`.

**Step 1 – Craft the long-zero address:**
```
Entity ID 1000 = 0x3E8
Long-zero address = 0x00000000000000000000000000000000000003E8
```

**Step 2 – Send GraphQL query (no authentication required):**
```graphql
{
  account(input: { evmAddress: "0x00000000000000000000000000000000000003E8" }) {
    entityId { shard realm num }
    id
    type
  }
}
```

**Step 3 – Observe result:**
The mirror node returns the entity for `0.0.1000` (whose real EVM address is `0xdeadbeef…`), incorrectly asserting it corresponds to `0x000…03E8`. No error is raised. The exported record is incorrect.

**Relevant code locations:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-55)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/service/EntityServiceTest.java (L147-155)
```java
    void getByIdAsEvmAddressAndTypeFound() {
        var entity = domainBuilder.entity().get();
        ByteBuffer evmBuffer = ByteBuffer.allocate(EVM_ADDRESS_BYTE_LENGTH);
        evmBuffer.putLong(EVM_ADDRESS_BYTE_LENGTH - Long.BYTES, entity.getId());
        when(entityRepository.findById(entity.getId())).thenReturn(Optional.of(entity));
        assertThat(entityService.getByEvmAddressAndType(Hex.encodeHexString(evmBuffer), entity.getType()))
                .get()
                .isEqualTo(entity);
    }
```
