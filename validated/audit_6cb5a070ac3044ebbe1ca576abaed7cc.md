All referenced code has been verified against the actual repository. Here is the result:

---

Audit Report

## Title
Missing Non-Negative Validation on EVM Long-Zero Address Entity Num Allows Cross-Shard Entity Confusion

## Summary
`getByEvmAddressAndType()` in `EntityServiceImpl` correctly identifies a "long-zero" EVM address by checking that the shard (bytes 0–3) and realm (bytes 4–11) fields are zero, but passes bytes 12–19 directly to `entityRepository.findById()` without validating the extracted `long` is non-negative. Because `EntityId.encode()` produces negative `long` values for entities with non-zero shard or realm, a crafted address with bytes 12–19 set to a negative encoded ID will resolve to a completely different entity than the address implies.

## Finding Description

**Exact code path — `EntityServiceImpl.java` lines 34–41:**

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        return entityRepository.findById(buffer.getLong())   // no non-negative check
                .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
``` [1](#0-0) 

The long-zero branch is intended to resolve `0.0.<num>` entity IDs. For such entities, `EntityId.encode(0, 0, num)` returns `num` directly (always non-negative). However, the code never validates that the raw `long` extracted from bytes 12–19 is ≥ 0 before passing it to `findById()`.

**Why negative IDs exist:** `EntityId.encode()` packs shard (10 bits), realm (16 bits), and num (38 bits) into a signed `long`. When shard is non-zero, the high bits are set, producing a negative value: [2](#0-1) 

This is confirmed by `EntityIdTest.java`:
- `EntityId.of(1023, 65535, 274877906943)` → encoded id = **-1**
- `EntityId.of(1023, 0, 0)` → encoded id = **-18014398509481984** [3](#0-2) 

`EntityRepositoryTest.java` line 18 confirms entities with negative IDs are persisted and retrievable: [4](#0-3) 

**Existing checks are insufficient:**
- The GraphQL `@Pattern` annotation on `evmAddress` (account.graphqls line 96) only validates hex format and length — it does not constrain the semantic value of bytes 12–19. [5](#0-4) 

- `decodeEvmAddress()` in `GraphQlUtils.java` only strips the `0x` prefix and hex-decodes — no range validation. [6](#0-5) 

- `EntityId.encode()` validates `num >= 0`, but it is **never called** in this code path; the raw `long` from `ByteBuffer` bypasses it entirely. [7](#0-6) 

## Impact Explanation
An attacker can resolve any entity whose encoded ID is negative (i.e., any entity with non-zero shard or realm) by supplying a crafted "long-zero" EVM address. The GraphQL response presents that entity's account/contract data as if it were the entity at `0.0.<negative-num>`, which is not a valid entity. This constitutes entity confusion: the caller receives authoritative-looking state for an entity that does not correspond to the supplied address. In multi-shard/multi-realm deployments (which the codebase explicitly supports), this allows enumeration and retrieval of any entity by its encoded ID, bypassing the intended address-to-entity resolution semantics.

## Likelihood Explanation
No privileges are required. The attack requires only the ability to send a GraphQL query with a crafted hex string — available to any user of the public mirror node API. The encoded IDs of target entities are deterministically computable from their `shard.realm.num` values using the documented encoding formula. The attack is trivially repeatable and scriptable, constrained only to deployments where entities with non-zero shard/realm exist.

## Recommendation
Add a non-negative check on the extracted `num` before calling `findById()`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    long num = buffer.getLong();
    if (num < 0) {
        return Optional.empty();
    }
    return entityRepository.findById(num).filter(e -> e.getType() == type);
}
```

This ensures the long-zero branch only resolves valid `0.0.<num>` entities, rejecting crafted addresses whose byte 12–19 value encodes a non-zero shard or realm.

## Proof of Concept

1. Craft EVM address: `000000000000000000000000FFFFFFFFFFFFFFFF`
   - Bytes 0–3: `00000000` → `buffer.getInt() == 0` ✓
   - Bytes 4–11: `0000000000000000` → `buffer.getLong() == 0` ✓
   - Bytes 12–19: `FFFFFFFFFFFFFFFF` → `buffer.getLong() == -1L`
2. The long-zero branch is taken.
3. `entityRepository.findById(-1L)` executes `SELECT * FROM entity WHERE id = -1`.
4. This returns the entity `1023.65535.274877906943` — confirmed by `EntityIdTest.java` line 31 — a completely different entity from what the address format implies.

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

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L75-85)
```java
    private static long encode(long shard, long realm, long num) {
        if (shard > SHARD_MASK || shard < 0 || realm > REALM_MASK || realm < 0 || num > NUM_MASK || num < 0) {
            throw new InvalidEntityException("Invalid entity ID: " + shard + "." + realm + "." + num);
        }

        if (shard == 0 && realm == 0) {
            return num;
        }

        return (num & NUM_MASK) | (realm & REALM_MASK) << NUM_BITS | (shard & SHARD_MASK) << (REALM_BITS + NUM_BITS);
    }
```

**File:** common/src/test/java/org/hiero/mirror/common/domain/entity/EntityIdTest.java (L31-32)
```java
        "1023, 65535, 274877906943, -1",
        "1023, 0, 0, -18014398509481984"
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/repository/EntityRepositoryTest.java (L18-19)
```java
        var entity = domainBuilder.entity(-2, domainBuilder.timestamp()).persist();
        assertThat(entityRepository.findById(entity.getId())).contains(entity);
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L96-96)
```text
    evmAddress: String @Pattern(regexp: "^(0x)?[a-fA-F0-9]{40}$")
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L87-98)
```java
    public static byte[] decodeEvmAddress(String evmAddress) {
        if (evmAddress == null) {
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        try {
            evmAddress = Strings.CS.removeStart(evmAddress, HEX_PREFIX);
            return Hex.decodeHex(evmAddress);
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Unable to decode evmAddress: " + evmAddress);
        }
    }
```
