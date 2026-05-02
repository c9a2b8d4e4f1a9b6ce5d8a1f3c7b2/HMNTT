All three code paths are confirmed in the repository. The technical claims are accurate.

**Verification summary:**

- `decodeEvmAddress()` performs no length check on the decoded byte array. [1](#0-0) 
- `getByEvmAddressAndType()` wraps the raw bytes in a `ByteBuffer` and calls `getInt()` + `getLong()` (consuming 12 bytes) in the condition, then calls `getLong()` again (needing 8 more bytes) inside the branch. [2](#0-1) 
- `CustomExceptionResolver.resolveToSingleError()` only handles `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`, returning `null` for everything else. `BufferUnderflowException` matches none of these. [3](#0-2) 
- The existing test suite allocates a 20-byte buffer (`EVM_ADDRESS_BYTE_LENGTH = 20`) for all EVM address tests, so the short-input case is never exercised. [4](#0-3) 

---

# Audit Report

## Title
Missing EVM Address Length Validation Causes `BufferUnderflowException` via Crafted Short Hex Input

## Summary
`getByEvmAddressAndType()` in `EntityServiceImpl.java` wraps the decoded EVM address bytes in a `ByteBuffer` without first validating that exactly 20 bytes are present. A crafted 26-hex-character (13-byte) input whose first 12 bytes are zero satisfies the `getInt()==0 && getLong()==0` branch condition, then causes the subsequent `getLong()` call to throw an uncaught `java.nio.BufferUnderflowException`. The `CustomExceptionResolver` does not handle this exception type, so it propagates as an opaque internal server error rather than a proper `ValidationError` GraphQL response.

## Finding Description

**Root cause — `decodeEvmAddress()` in `GraphQlUtils.java` (lines 87–98):**

```java
public static byte[] decodeEvmAddress(String evmAddress) {
    if (evmAddress == null) {
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }
    try {
        evmAddress = Strings.CS.removeStart(evmAddress, HEX_PREFIX);
        return Hex.decodeHex(evmAddress);   // no length check
    } catch (DecoderException e) {
        throw new IllegalArgumentException("Unable to decode evmAddress: " + evmAddress);
    }
}
```

`Hex.decodeHex()` succeeds for any even-length hex string. A 26-char input decodes to 13 bytes with no exception.

**Trigger — `getByEvmAddressAndType()` in `EntityServiceImpl.java` (lines 34–41):**

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);   // 13 bytes
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {     // consumes 12 bytes; position=12
        return entityRepository.findById(buffer.getLong())   // needs 8 bytes, only 1 remains → BufferUnderflowException
                .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

Step-by-step for input `"0x" + "00".repeat(13)` (26 hex chars after prefix):
| Call | Bytes consumed | Position after | Returns |
|---|---|---|---|
| `buffer.getInt()` | 0–3 | 4 | 0 ✓ |
| `buffer.getLong()` (condition) | 4–11 | 12 | 0 ✓ |
| `buffer.getLong()` (line 38) | needs 12–19 | only 1 byte left | **`BufferUnderflowException`** |

**Why the exception resolver does not catch it — `CustomExceptionResolver.java` (lines 16–29):**

```java
if (ex instanceof IllegalStateException
        || ex instanceof IllegalArgumentException
        || ex instanceof MirrorNodeException) {
    // returns ValidationError
} else {
    return null;   // BufferUnderflowException falls here
}
```

`java.nio.BufferUnderflowException` extends `RuntimeException` directly and matches none of the three handled types. Returning `null` causes Spring GraphQL to fall back to its default internal-error handler, producing a 500-class response with no `ValidationError` classification.

## Impact Explanation
Any unauthenticated caller can send a single GraphQL request with a 26-hex-char EVM address to trigger an unhandled `BufferUnderflowException`. The service process does **not** crash — Spring GraphQL's default handler catches the propagated exception. The concrete impacts are:
- The caller receives an opaque internal server error instead of a proper `ValidationError` response, bypassing the intended error-handling contract.
- Each such request generates an unhandled-exception log entry, creating noise that can mask legitimate errors.
- The defect is fully repeatable and requires no authentication.

## Likelihood Explanation
No authentication or special privilege is required. The GraphQL endpoint is publicly reachable. The attacker only needs to supply a hex string of non-standard length; the specific 26-char all-zero payload is trivially discoverable through source inspection or fuzzing. The condition (`getInt()==0 && getLong()==0`) is satisfied by any input whose first 12 bytes are zero, making the trigger space large.

## Recommendation
Add an explicit length check in `decodeEvmAddress()` or at the top of `getByEvmAddressAndType()`:

```java
// In GraphQlUtils.decodeEvmAddress(), after decoding:
byte[] decoded = Hex.decodeHex(evmAddress);
if (decoded.length != 20) {
    throw new IllegalArgumentException(
        "EVM address must be exactly 20 bytes, got: " + decoded.length);
}
return decoded;
```

This throws `IllegalArgumentException`, which `CustomExceptionResolver` already handles and converts to a `ValidationError` response. Alternatively, add the check directly in `getByEvmAddressAndType()` before wrapping in `ByteBuffer`. Either way, the fix ensures only 20-byte inputs reach the `ByteBuffer` read sequence.

## Proof of Concept

GraphQL request:
```graphql
{
  account(input: { evmAddress: "0x00000000000000000000000000" }) {
    id
  }
}
```

The 26 hex chars after `0x` decode to 13 bytes. The first 12 are zero, satisfying the branch condition. The third `buffer.getLong()` call throws `BufferUnderflowException`, which propagates past `CustomExceptionResolver` and returns an internal server error response instead of a `ValidationError`.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/CustomExceptionResolver.java (L16-29)
```java
    protected GraphQLError resolveToSingleError(Throwable ex, DataFetchingEnvironment env) {
        if (ex instanceof IllegalStateException
                || ex instanceof IllegalArgumentException
                || ex instanceof MirrorNodeException) {
            return GraphqlErrorBuilder.newError()
                    .errorType(ErrorType.ValidationError)
                    .message(ex.getMessage())
                    .path(env.getExecutionStepInfo().getPath())
                    .location(env.getField().getSourceLocation())
                    .build();
        } else {
            return null;
        }
    }
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/service/EntityServiceTest.java (L28-28)
```java
    private static final int EVM_ADDRESS_BYTE_LENGTH = 20;
```
