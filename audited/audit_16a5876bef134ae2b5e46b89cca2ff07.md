### Title
`BufferUnderflowException` in `getByEvmAddressAndType` via Under-Length EVM Address Input

### Summary
`GraphQlUtils.decodeEvmAddress` performs no length validation and accepts any even-length hex string. `EntityServiceImpl.getByEvmAddressAndType` wraps the decoded bytes in a `ByteBuffer` and unconditionally reads 4 + 8 + 8 = 20 bytes, assuming a 20-byte EVM address. An unprivileged user supplying a 16-byte (32 hex char) all-zero hex string satisfies the first two reads (`getInt()==0`, `getLong()==0`) but leaves only 4 bytes for the third `getLong()`, throwing an unhandled `BufferUnderflowException`.

### Finding Description
**Code path:**

- `GraphQlUtils.decodeEvmAddress` — [1](#0-0)  strips the `0x` prefix and calls `Hex.decodeHex`, returning a byte array of whatever length the input encodes. No length check exists.

- `EntityServiceImpl.getByEvmAddressAndType` — [2](#0-1)  wraps the result in `ByteBuffer` and performs three sequential reads totalling 20 bytes (4 + 8 + 8), with no guard on `buffer.remaining()`.

**Root cause:** The code assumes `evmAddressBytes` is always 20 bytes. `decodeEvmAddress` never enforces this. The existing `invalidEvmAddress` test only rejects odd-length hex and non-hex characters — short even-length inputs pass through, as confirmed by the test suite itself accepting 5-byte inputs: [3](#0-2) 

**Exploit flow:**
1. Attacker sends a GraphQL `account` query with `evmAddress: "0x00000000000000000000000000000000"` (32 hex chars = 16 bytes, all zeros).
2. `decodeEvmAddress` returns a 16-byte array — no exception.
3. `buffer.getInt()` reads bytes 0–3 → `0`, position=4, remaining=12.
4. `buffer.getLong()` reads bytes 4–11 → `0`, position=12, remaining=4.
5. Condition `== 0 && == 0` is true; code enters the branch.
6. `buffer.getLong()` attempts to read 8 bytes with only 4 remaining → `BufferUnderflowException` thrown.
7. Exception is unhandled at the application layer and propagates to the Spring GraphQL framework.

### Impact Explanation
`BufferUnderflowException` is an unchecked `RuntimeException`. Spring GraphQL catches it at the framework boundary and returns a GraphQL error response rather than crashing the JVM. However: (a) the exception is completely unhandled in application code, (b) internal stack traces may be exposed in error responses depending on configuration, and (c) the condition is trivially and repeatably triggerable by any caller with no authentication. The service remains available but behaves incorrectly for all such inputs.

### Likelihood Explanation
No authentication or privilege is required. The GraphQL `account` query accepts `evmAddress` as a plain `String` with no schema-level length constraint. The attacker needs only to know the API exists and submit a single crafted query. The attack is deterministic and repeatable with zero cost.

### Recommendation
Add an explicit length check in `decodeEvmAddress` or at the start of `getByEvmAddressAndType`:

```java
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
}
```

Alternatively, enforce the constraint at the GraphQL schema level using a custom scalar or a `@Size` / `@Pattern` constraint on the `evmAddress` field of `AccountInput`.

### Proof of Concept
```graphql
# Submit via any GraphQL client to the /graphql endpoint (no auth required)
query {
  account(input: { evmAddress: "0x00000000000000000000000000000000" }) {
    entityId { shard realm num }
  }
}
```

**Expected (buggy) result:** `BufferUnderflowException` thrown at `EntityServiceImpl.java:38`, propagated as a GraphQL error response.

**Byte-level trace:**
- Input: `00000000 00000000 00000000 00000000` (16 bytes)
- `getInt()` → `0x00000000` = 0 ✓ (position → 4)
- `getLong()` → `0x0000000000000000` = 0 ✓ (position → 12)
- `getLong()` → only 4 bytes remain, needs 8 → **`BufferUnderflowException`**

### Citations

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

**File:** graphql/src/test/java/org/hiero/mirror/graphql/util/GraphQlUtilsTest.java (L93-97)
```java
             0000AaAaAa, 5, 11184810
             0x0000000000000000000000000000000000000001, 20, 1
             0x000000000000000000000000000000000000fafa, 20, 64250
             0x0000000000000000000000000000000000FafafA, 20, 16448250
             0x0000AaAaAa, 5, 11184810
```
