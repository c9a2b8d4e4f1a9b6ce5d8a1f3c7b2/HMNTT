I have all the code I need. Let me analyze the claim against the actual source.

The technical claims are all verifiable in the actual source. Here is my assessment:

**Verified facts:**

- `GraphQlUtils.decodeEvmAddress` (lines 87–98): no length check, returns whatever `Hex.decodeHex` produces. [1](#0-0) 
- `EntityServiceImpl.getByEvmAddressAndType` (lines 34–41): unconditionally reads 4 + 8 + 8 = 20 bytes from the buffer with no `remaining()` guard. [2](#0-1) 
- The `decodeEvmAddress` test suite explicitly accepts 5-byte inputs (`0000AaAaAa`), and `invalidEvmAddress` only rejects odd-length hex and non-hex characters — short even-length inputs pass. [3](#0-2) 
- No `AccountInput` class with Bean Validation constraints on `evmAddress` was found in the repository.

The exploit path is deterministic and correct. A 16-byte (32 hex char) all-zero input satisfies both the `getInt()==0` and first `getLong()==0` checks, then the second `getLong()` throws `BufferUnderflowException` with only 4 bytes remaining.

---

## Audit Report

## Title
`BufferUnderflowException` in `EntityServiceImpl.getByEvmAddressAndType` via Under-Length EVM Address Input

## Summary
`GraphQlUtils.decodeEvmAddress` accepts any even-length hex string without enforcing a 20-byte length. `EntityServiceImpl.getByEvmAddressAndType` wraps the decoded bytes in a `ByteBuffer` and unconditionally reads 4 + 8 + 8 = 20 bytes. A 16-byte (32 hex char) all-zero input satisfies the first two reads but causes an unhandled `BufferUnderflowException` on the third.

## Finding Description
**`GraphQlUtils.decodeEvmAddress`** strips the `0x` prefix and delegates directly to `Hex.decodeHex`, returning a byte array of whatever length the input encodes. No length validation exists. [1](#0-0) 

**`EntityServiceImpl.getByEvmAddressAndType`** wraps the result in `ByteBuffer.wrap(evmAddressBytes)` and performs three sequential reads totalling 20 bytes (`getInt()` + `getLong()` + `getLong()`), with no guard on `buffer.remaining()` before any read. [2](#0-1) 

The `invalidEvmAddress` test confirms that only odd-length hex strings and non-hex characters are rejected; short even-length inputs (e.g., 5-byte `0000AaAaAa`) pass through `decodeEvmAddress` without error. [4](#0-3) 

## Impact Explanation
`BufferUnderflowException` is an unchecked `RuntimeException`. Spring GraphQL catches it at the framework boundary and returns a GraphQL error response; the JVM does not crash and the service remains available. However, the exception is entirely unhandled in application code, meaning: (a) no meaningful validation error is returned to the caller, (b) internal stack traces may be included in error responses depending on Spring GraphQL error-handling configuration, and (c) the condition is trivially and repeatably triggerable by any unauthenticated caller.

## Likelihood Explanation
No authentication or privilege is required. The GraphQL `account` query accepts `evmAddress` as a plain `String` with no schema-level or Bean Validation length constraint. The attack requires only knowledge that the API exists and submission of a single crafted query. It is deterministic and repeatable at zero cost.

## Recommendation
Add an explicit length check in `GraphQlUtils.decodeEvmAddress` (or at the top of `getByEvmAddressAndType`) that throws `IllegalArgumentException` when the decoded byte array is not exactly 20 bytes. For example:

```java
// In decodeEvmAddress or getByEvmAddressAndType
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("EVM address must be exactly 20 bytes");
}
```

This aligns with the existing pattern used in `DomainUtils.fromTrimmedEvmAddress`, which already checks `evmAddress.length > EVM_ADDRESS_LENGTH`. [5](#0-4) 

## Proof of Concept
Send the following GraphQL query to `/graphql/alpha`:

```graphql
{
  account(input: { evmAddress: "0x00000000000000000000000000000000" }) {
    id
  }
}
```

**Step-by-step:**
1. `decodeEvmAddress("0x00000000000000000000000000000000")` strips `0x`, decodes 32 hex chars → 16-byte array `[0x00 * 16]`. No exception.
2. `ByteBuffer.wrap(evmAddressBytes)` → buffer of capacity 16.
3. `buffer.getInt()` → reads bytes 0–3, returns `0`. Position=4, remaining=12.
4. `buffer.getLong()` → reads bytes 4–11, returns `0`. Position=12, remaining=4.
5. Condition `0 == 0 && 0 == 0` is `true`; enters the if-branch.
6. `buffer.getLong()` → attempts to read 8 bytes with only 4 remaining → **`java.nio.BufferUnderflowException`** thrown.
7. Exception propagates unhandled through `EntityServiceImpl` and `AccountController` to the Spring GraphQL framework, which returns a GraphQL error response.

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

**File:** graphql/src/test/java/org/hiero/mirror/graphql/util/GraphQlUtilsTest.java (L89-118)
```java
    @CsvSource(textBlock = """
             '', 0, 0
             0000000000000000000000000000000000000001, 20, 1
             0000000000000000000000000000000000FAfAfA, 20, 16448250
             0000AaAaAa, 5, 11184810
             0x0000000000000000000000000000000000000001, 20, 1
             0x000000000000000000000000000000000000fafa, 20, 64250
             0x0000000000000000000000000000000000FafafA, 20, 16448250
             0x0000AaAaAa, 5, 11184810
            """)
    @ParameterizedTest
    void decodeEvmAddress(String evmAddress, int expectedLength, long output) {
        var decodedEvmAddress = GraphQlUtils.decodeEvmAddress(evmAddress);
        assertThat(decodedEvmAddress).hasSize(expectedLength).satisfies(e -> assertThat(
                        output > 0 ? new BigInteger(e).longValue() : output)
                .isEqualTo(output));
    }

    @NullAndEmptySource
    @ValueSource(
            strings = {"000000000000000000000000000000000000001", "f5a56e2d52c817161883f50c441c3228cfe54d9fa", "xyzabc"
            })
    @ParameterizedTest
    void invalidEvmAddress(String evmAddress) {
        assertThat(evmAddress)
                .satisfiesAnyOf(
                        e -> assertThatThrownBy(() -> GraphQlUtils.decodeEvmAddress(e))
                                .isInstanceOf(IllegalArgumentException.class),
                        e -> assertThat(GraphQlUtils.decodeEvmAddress(e)).isEmpty());
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java (L299-308)
```java
    public static EntityId fromTrimmedEvmAddress(final byte[] evmAddress) {
        if (evmAddress == null || evmAddress.length > EVM_ADDRESS_LENGTH) {
            return null;
        } else if (evmAddress.length == EVM_ADDRESS_LENGTH) {
            return fromEvmAddress(evmAddress);
        }

        var padding = new byte[EVM_ADDRESS_LENGTH - evmAddress.length];

        return fromEvmAddress(Bytes.concat(padding, evmAddress));
```
