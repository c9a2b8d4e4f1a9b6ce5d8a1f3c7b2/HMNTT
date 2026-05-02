### Title
Missing EVM Address Length Validation Causes `BufferUnderflowException` via Crafted Short Hex Input

### Summary
`getByEvmAddressAndType()` in `EntityServiceImpl.java` passes the decoded EVM address bytes directly into a `ByteBuffer` without validating that the buffer contains exactly 20 bytes. An unauthenticated attacker can supply a 13-byte (26 hex char) input whose first 12 bytes are zero, causing `buffer.getInt()` and the first `buffer.getLong()` to both return 0 (satisfying the branch condition), while the second `buffer.getLong()` call finds only 1 byte remaining and throws an uncaught `BufferUnderflowException`. The custom GraphQL exception resolver does not handle this exception type, so it propagates as an unhandled internal server error on every such request.

### Finding Description

**Exact code path:**

`decodeEvmAddress()` in `GraphQlUtils.java` performs no length check on the decoded byte array: [1](#0-0) 

It strips the optional `0x` prefix and calls `Hex.decodeHex()`, returning whatever length byte array results. A 26-hex-char input decodes to 13 bytes with no error.

Back in `getByEvmAddressAndType()`: [2](#0-1) 

- Line 36: `ByteBuffer.wrap(evmAddressBytes)` — wraps the 13-byte array.
- Line 37: `buffer.getInt()` — reads bytes 0–3 (4 bytes), position advances to 4. Returns 0 for the crafted input. ✓
- Line 37: `buffer.getLong()` — reads bytes 4–11 (8 bytes), position advances to 12. Returns 0 for the crafted input. ✓
- Line 38: `buffer.getLong()` — attempts to read bytes 12–19 (8 bytes), but only 1 byte remains at position 12. **Throws `java.nio.BufferUnderflowException`.**

**Why existing checks fail:**

The `CustomExceptionResolver` only handles `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`: [3](#0-2) 

`BufferUnderflowException` extends `RuntimeException` directly and matches none of these. `resolveToSingleError()` returns `null`, meaning the Spring GraphQL framework falls back to its default internal-error handling. The exception is never converted to a proper `ValidationError` response.

### Impact Explanation

Every GraphQL request that supplies a 13-byte EVM address with the first 12 bytes being zero triggers an unhandled `BufferUnderflowException`. The affected request receives an opaque internal server error response instead of a proper validation error. The JVM and service process itself do **not** crash — Spring GraphQL's default handler catches the propagated exception and returns a 500-class response. The impact is therefore: unexpected internal server errors for crafted inputs, bypassing the intended validation-error path, and potential noise in server logs. The severity is **not** "total network shutdown" as originally framed, but it is a real, reproducible input-validation defect exploitable by any unauthenticated caller.

### Likelihood Explanation

No authentication or special privilege is required. The GraphQL endpoint is publicly reachable. The attacker only needs to know the EVM address field accepts a hex string and can trivially discover the 26-char zero-prefixed payload through fuzzing or source inspection. The condition (`getInt()==0 && getLong()==0`) is trivially satisfied by any all-zero prefix. The attack is fully repeatable.

### Recommendation

Add an explicit length check in `decodeEvmAddress()` or at the top of `getByEvmAddressAndType()` before wrapping in a `ByteBuffer`:

```java
// In GraphQlUtils.decodeEvmAddress or at call site:
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException(
        "Invalid evmAddress length: expected 20 bytes, got " + evmAddressBytes.length);
}
```

`IllegalArgumentException` is already handled by `CustomExceptionResolver` and maps to a `ValidationError`, which is the correct response. The test class already defines `EVM_ADDRESS_BYTE_LENGTH = 20` as the expected constant: [4](#0-3) 

### Proof of Concept

```
# GraphQL mutation/query that passes evmAddress as a hex string
# Payload: 26 hex chars, first 24 = zeros, last 2 = any valid hex byte
# e.g. "000000000000000000000000ab"  (13 bytes, bytes 0-11 = 0x00)

POST /graphql
Content-Type: application/json

{
  "query": "{ account(input: { evmAddress: \"000000000000000000000000ab\" }) { id } }"
}

# Expected (correct): ValidationError - invalid address length
# Actual: BufferUnderflowException propagates, returns internal server error
```

Steps:
1. Identify the GraphQL field that accepts `evmAddress` (routes to `getByEvmAddressAndType`).
2. Send the 26-char hex string `"000000000000000000000000ab"` as the `evmAddress` value.
3. `decodeEvmAddress` returns a 13-byte array with no error.
4. `ByteBuffer.wrap` wraps 13 bytes.
5. `getInt()` → 0, `getLong()` → 0 (branch taken).
6. Second `getLong()` throws `BufferUnderflowException`.
7. `CustomExceptionResolver.resolveToSingleError` returns `null` (not handled).
8. Response is an internal server error instead of a validation error.

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
