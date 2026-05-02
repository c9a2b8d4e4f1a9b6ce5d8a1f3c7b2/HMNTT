### Title
BufferUnderflowException via Under-Length EVM Address in `getByEvmAddressAndType`

### Summary
`decodeEvmAddress` performs no length validation on the decoded byte array, accepting any even-length hex string. `getByEvmAddressAndType` wraps the result in a `ByteBuffer` and unconditionally calls `getInt()` + `getLong()` + `getLong()` (consuming 4+8+8=20 bytes), but the third `getLong()` on line 38 is only reached when the first two reads return zero — meaning an attacker can craft a 14-byte (28 hex char) input whose first 12 bytes are zero, causing the third `getLong()` to throw an unchecked `BufferUnderflowException` that is never caught.

### Finding Description

**`decodeEvmAddress` — no length check:** [1](#0-0) 

`Hex.decodeHex` only rejects odd-length hex strings (throws `DecoderException`). Any even-length hex string — including 28 chars (14 bytes) — is decoded and returned without any size assertion.

**`getByEvmAddressAndType` — unchecked sequential reads:** [2](#0-1) 

The code assumes `evmAddressBytes` is always 20 bytes. The reads consume:
- `buffer.getInt()` → 4 bytes (position = 4)
- `buffer.getLong()` → 8 bytes (position = 12)
- `buffer.getLong()` → needs 8 more bytes (position 12→20)

With a 14-byte buffer, only 2 bytes remain at position 12. The third `getLong()` on line 38 throws `java.nio.BufferUnderflowException` (unchecked, not caught anywhere in this method or its callers).

**Trigger condition:** The third `getLong()` is only reached when `getInt() == 0 && getLong() == 0`, i.e., the first 12 bytes are all zero. A 14-byte input with bytes 0–11 = `0x00` and bytes 12–13 = any value satisfies this.

### Impact Explanation
Every GraphQL request that reaches `getByEvmAddressAndType` with a crafted address throws an unhandled `BufferUnderflowException`. Depending on the Spring for GraphQL exception-handling configuration, this surfaces as a 500-level error or a GraphQL `INTERNAL_ERROR` response. Repeated calls constitute a trivially repeatable, zero-authentication denial-of-service against any GraphQL query that resolves an entity by EVM address. Stack traces may also be leaked in error responses, aiding further reconnaissance.

### Likelihood Explanation
The GraphQL EVM address input field is externally exposed and requires no authentication. The attacker needs only to know the field name and supply a 28-hex-char string whose first 24 chars are `0`. This is trivially discoverable via GraphQL introspection and requires no special privileges or knowledge of internal state. The attack is fully repeatable.

### Recommendation
Add an explicit length check in `decodeEvmAddress` or at the top of `getByEvmAddressAndType`:

```java
byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("EVM address must be exactly 20 bytes");
}
```

Alternatively, enforce the length constraint inside `decodeEvmAddress` itself so all callers are protected uniformly.

### Proof of Concept

**Precondition:** GraphQL endpoint is reachable (no authentication required).

**Crafted input:** `00000000000000000000000000ff`
- Length: 28 hex chars = 14 bytes
- Bytes 0–3: `0x00000000` → `getInt()` returns 0 ✓
- Bytes 4–11: `0x0000000000000000` → first `getLong()` returns 0 ✓
- Bytes 12–13: `0xff` (2 bytes) → second `getLong()` needs 8 bytes → **`BufferUnderflowException`**

**Steps:**
1. Send a GraphQL query that resolves an account/contract by EVM address, e.g.:
   ```graphql
   { account(input: { evmAddress: "00000000000000000000000000ff" }) { id } }
   ```
2. The server calls `getByEvmAddressAndType("00000000000000000000000000ff", ACCOUNT)`.
3. `decodeEvmAddress` returns a 14-byte array without error.
4. `ByteBuffer.wrap(14-byte array)` is created.
5. `getInt()` → 0, `getLong()` → 0 (condition is true).
6. `buffer.getLong()` on line 38 throws `BufferUnderflowException`.
7. Server returns HTTP 500 / GraphQL `INTERNAL_ERROR`. Repeatable indefinitely.

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
