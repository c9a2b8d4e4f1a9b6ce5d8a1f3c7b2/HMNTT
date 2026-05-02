All referenced code has been verified against the actual repository. Here is my assessment:

---

Audit Report

## Title
Missing Non-Negative Validation on EVM Long-Zero Address Entity Num Allows Cross-Shard Entity Confusion

## Summary
`getByEvmAddressAndType()` in `EntityServiceImpl` correctly identifies a "long-zero" EVM address by verifying bytes 0–3 (shard) and bytes 4–11 (realm) are zero, but passes bytes 12–19 directly to `entityRepository.findById()` without validating the value is non-negative. Because `EntityId.encode()` legitimately produces negative `long` values for entities with non-zero shard/realm, a crafted address can resolve to a real entity that has no relationship to the supplied address.

## Finding Description

The vulnerable code path is confirmed at: [1](#0-0) 

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        return entityRepository.findById(buffer.getLong())   // no >= 0 check
                .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

The long-zero branch is intended to resolve `0.0.<num>` entities. The `num` field of a valid `0.0.<num>` entity must be non-negative, but no such constraint is enforced on the raw `long` extracted from bytes 12–19.

**Why negative IDs exist:** `EntityId.encode()` packs shard (10 bits), realm (16 bits), and num (38 bits) into a single `long`. For non-zero shard/realm values, the result is negative: [2](#0-1) 

- `EntityId.of(1023, 65535, 274877906943)` → encoded id = **-1**
- `EntityId.of(1023, 0, 0)` → encoded id = **-18014398509481984**

These negative IDs are real, persisted entities confirmed by: [3](#0-2) [4](#0-3) 

**Existing defenses are insufficient:**

- The GraphQL schema `@Pattern` annotation only validates hex format and length, not the semantic value of bytes 12–19: [5](#0-4) 

- `decodeEvmAddress()` only strips the `0x` prefix and hex-decodes — no range validation: [6](#0-5) 

- `EntityId.encode()` validates `num >= 0`, but it is **never called** in this code path; the raw `long` from `ByteBuffer` bypasses it entirely: [7](#0-6) 

## Impact Explanation
A caller supplying EVM address `000000000000000000000000FFFFFFFFFFFFFFFF` passes the shard/realm zero checks and triggers `entityRepository.findById(-1L)`, which returns entity `1023.65535.274877906943`. The GraphQL response presents that entity's data as if it belongs to the address `0x000000000000000000000000FFFFFFFFFFFFFFFF` (implying `0.0.-1`, which is not a valid entity). This is entity confusion: the response is authoritative-looking but semantically incorrect. In multi-shard/multi-realm deployments, any entity whose encoded ID is negative is reachable this way.

## Likelihood Explanation
No authentication is required. The attack requires only a GraphQL query with a crafted 40-character hex string. The encoded IDs of target entities are deterministically computable from their `shard.realm.num` values using the documented encoding formula. The attack is trivially scriptable and repeatable against any deployment where entities with non-zero shard or realm exist.

## Recommendation
Add a non-negative guard on the extracted `num` before calling `findById()`:

```java
long num = buffer.getLong();
if (num < 0) {
    return Optional.empty();
}
return entityRepository.findById(num).filter(e -> e.getType() == type);
```

This mirrors the validation already enforced inside `EntityId.encode()` and ensures the long-zero branch can only resolve entities in the `0.0.*` namespace.

## Proof of Concept
1. Craft EVM address: `000000000000000000000000FFFFFFFFFFFFFFFF`
   - Bytes 0–3: `00000000` → `buffer.getInt() == 0` ✓
   - Bytes 4–11: `0000000000000000` → `buffer.getLong() == 0` ✓
   - Bytes 12–19: `FFFFFFFFFFFFFFFF` → `buffer.getLong() == -1L`
2. The long-zero branch is taken.
3. `entityRepository.findById(-1L)` executes `SELECT * FROM entity WHERE id = -1`.
4. Returns entity `1023.65535.274877906943` — confirmed by `EntityIdTest` line 31 that `-1` is the valid encoded ID for that entity.
5. The GraphQL response presents `1023.65535.274877906943`'s data under the address `0x000000000000000000000000FFFFFFFFFFFFFFFF`.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L33-41)
```java
    @Override
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** common/src/test/java/org/hiero/mirror/common/domain/entity/EntityIdTest.java (L31-32)
```java
        "1023, 65535, 274877906943, -1",
        "1023, 0, 0, -18014398509481984"
```

**File:** importer/src/test/java/org/hiero/mirror/importer/repository/EntityRepositoryTest.java (L111-113)
```java
    void findById() {
        var entity = domainBuilder.entity(-2, domainBuilder.timestamp()).persist();
        assertThat(entityRepository.findById(entity.getId())).contains(entity);
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/repository/EntityRepositoryTest.java (L17-19)
```java
    void find() {
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
