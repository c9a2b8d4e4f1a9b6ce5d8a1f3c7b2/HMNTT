### Title
`BufferUnderflowException` from Under-Length EVM Address Bypasses Exception Handler in `EntityServiceImpl`

### Summary
`GraphQlUtils.decodeEvmAddress()` performs no length validation on the decoded byte array, allowing any valid even-length hex string shorter than 40 hex chars (20 bytes) to be passed to `EntityServiceImpl.getByEvmAddressAndType()`. The subsequent `ByteBuffer` reads (`getInt()` + `getLong()`) throw an uncaught `java.nio.BufferUnderflowException` that is not handled by `CustomExceptionResolver`, causing Spring GraphQL to emit a generic `INTERNAL_ERROR` response instead of a clean validation error. Any unauthenticated user can trigger this repeatedly.

### Finding Description

**Exact code path:**

`AccountController.account()` passes the raw `evmAddress` string directly to `entityService.getByEvmAddressAndType()`: [1](#0-0) 

Inside `EntityServiceImpl.getByEvmAddressAndType()`, `decodeEvmAddress` is called and the result is immediately wrapped and read: [2](#0-1) 

`decodeEvmAddress` strips the `0x` prefix and hex-decodes whatever remains — with **no check that the result is 20 bytes**: [3](#0-2) 

The test suite itself confirms that short inputs (e.g. `0x0000AaAaAa` → 5 bytes) are accepted as valid by `decodeEvmAddress`: [4](#0-3) 

**Root cause:** `ByteBuffer.wrap(evmAddressBytes)` at line 36 succeeds for any length, but `buffer.getInt()` at line 37 requires ≥ 4 bytes and `buffer.getLong()` requires ≥ 8 more bytes. Any input shorter than 4 bytes throws `BufferUnderflowException` on `getInt()`; inputs of 4–11 bytes throw on the first `getLong()`; inputs of 12–19 bytes with a zero prefix throw on the second `getLong()`.

**Why the existing handler is insufficient:** `CustomExceptionResolver.resolveToSingleError()` only catches `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`: [5](#0-4) 

`java.nio.BufferUnderflowException` extends `RuntimeException` directly and matches none of those types, so the resolver returns `null` and Spring GraphQL falls back to a generic `INTERNAL_ERROR` response.

### Impact Explanation
Every request with a short evmAddress produces an unhandled internal exception rather than a clean `ValidationError`. This leaks the fact that an unhandled runtime exception occurred (visible in server logs and potentially in the GraphQL error `extensions` block depending on configuration), and degrades observability by polluting error metrics/logs with `INTERNAL_ERROR` noise. Severity matches the stated scope: griefing with no economic damage.

### Likelihood Explanation
No authentication is required. The GraphQL endpoint is publicly reachable. The payload is trivial — a single-character hex string like `0x01` suffices. The attack is fully repeatable and scriptable, making it suitable for sustained griefing or log flooding.

### Recommendation
Add an explicit length check in `decodeEvmAddress` or at the top of `getByEvmAddressAndType`:

```java
// In GraphQlUtils.decodeEvmAddress or EntityServiceImpl.getByEvmAddressAndType
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException(
        "evmAddress must decode to exactly 20 bytes, got " + evmAddressBytes.length);
}
```

`IllegalArgumentException` is already handled by `CustomExceptionResolver` and will produce a proper `ValidationError` GraphQL response instead of an `INTERNAL_ERROR`.

### Proof of Concept

Send the following GraphQL query to the mirror node GraphQL endpoint (no credentials needed):

```graphql
{
  account(input: { evmAddress: "0x01" }) {
    balance
  }
}
```

**Step-by-step:**
1. `evmAddress = "0x01"` → `decodeEvmAddress` strips `0x`, hex-decodes `"01"` → `byte[]{0x01}` (1 byte)
2. `ByteBuffer.wrap(new byte[]{0x01})` → buffer with 1 byte remaining
3. `buffer.getInt()` attempts to read 4 bytes from a 1-byte buffer → throws `java.nio.BufferUnderflowException`
4. `CustomExceptionResolver.resolveToSingleError` receives `BufferUnderflowException`, matches no handled type, returns `null`
5. Spring GraphQL returns `{"errors":[{"message":"INTERNAL_ERROR","extensions":{"classification":"INTERNAL_ERROR"}}]}`

Any even-length hex string between 2 and 38 hex characters (1–19 bytes) triggers the same path. The `0x` prefix is optional.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-55)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
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

**File:** graphql/src/test/java/org/hiero/mirror/graphql/util/GraphQlUtilsTest.java (L89-105)
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
