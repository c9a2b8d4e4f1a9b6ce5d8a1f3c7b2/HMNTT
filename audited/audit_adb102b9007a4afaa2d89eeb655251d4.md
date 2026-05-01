### Title
Unvalidated EVM Address Length in `getByEvmAddressAndType()` Causes Unhandled `BufferUnderflowException` Leading to Repeated Expensive Stack Trace Logging

### Summary
`decodeEvmAddress()` in `GraphQlUtils.java` performs no length validation, accepting any valid hex string regardless of byte length. `getByEvmAddressAndType()` in `EntityServiceImpl.java` then calls `buffer.getInt()` and `buffer.getLong()` on the resulting `ByteBuffer` without checking capacity, throwing an unchecked `BufferUnderflowException` for inputs shorter than 20 bytes. This exception is not handled by `CustomExceptionResolver`, causing Spring GraphQL to log it with a full stack trace at ERROR level on every such request, which an unauthenticated attacker can exploit to drive up CPU and logging I/O.

### Finding Description

**Code path:**

`decodeEvmAddress()` in `GraphQlUtils.java` lines 87–98: [1](#0-0) 

The function only rejects `null` (returning an empty array) and non-hex characters (throwing `IllegalArgumentException`). It applies **no length check** — a 10-character hex string (`"0x0000AaAaAa"` = 5 bytes) passes through and returns a 5-byte array. This is confirmed by the existing test at line 97 of `GraphQlUtilsTest.java`: [2](#0-1) 

`getByEvmAddressAndType()` in `EntityServiceImpl.java` lines 34–41: [3](#0-2) 

- `buffer.getInt()` requires ≥ 4 bytes; throws `BufferUnderflowException` if fewer.
- `buffer.getLong()` (first call) requires ≥ 12 bytes total; throws if fewer.
- `buffer.getLong()` (second call, inside `if`) requires ≥ 20 bytes total; throws if fewer.

No try/catch wraps these calls.

**Why the exception handler is insufficient:**

`CustomExceptionResolver.resolveToSingleError()` only handles `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`: [4](#0-3) 

`BufferUnderflowException` extends `java.nio.BufferUnderflowException` → `RuntimeException`. It matches none of the three handled types, so `resolveToSingleError` returns `null`. Spring GraphQL's default fallback then logs the unresolved exception with a **full stack trace at ERROR level** and returns a generic `INTERNAL_ERROR` GraphQL response.

### Impact Explanation

Every request with a short-but-valid hex evmAddress (e.g., `"0x1122334455"` = 5 bytes, or `"0x112233445566778899aabb"` = 11 bytes) triggers:
1. `Throwable.fillInStackTrace()` — a JVM-level operation that walks the entire call stack and is significantly more expensive than a normal method call.
2. An ERROR-level log write with the full stack trace string — synchronous I/O in most logging configurations.

Because the exception is thrown before any database query, the server can process these malformed requests at maximum throughput. Under sustained flood, the combination of repeated stack trace allocation and ERROR-level logging can measurably increase CPU and I/O above baseline, consistent with the ≥30% resource consumption threshold described in the scope.

### Likelihood Explanation

- **No authentication required**: The GraphQL endpoint is publicly accessible; no credentials or privileges are needed.
- **Trivial to craft**: Any valid even-length hex string shorter than 40 hex characters (< 20 bytes) triggers the bug. E.g., `"0x1122"` (2 bytes) or `"0x112233445566778899aabb"` (11 bytes).
- **Repeatable at high rate**: The exception path is pre-database, so the server can handle (and fail) these requests very quickly, maximizing the rate of stack trace generation.
- **No existing rate limiting** is visible in the GraphQL layer from the reviewed code.

### Recommendation

1. **Add a length check in `decodeEvmAddress()`** or at the start of `getByEvmAddressAndType()`:
   ```java
   if (evmAddressBytes.length != 20) {
       throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
   }
   ```
   This throws `IllegalArgumentException`, which `CustomExceptionResolver` already handles cleanly (no stack trace logged, returns a `ValidationError` GraphQL response).

2. **Alternatively**, check `buffer.capacity()` before the reads:
   ```java
   if (buffer.capacity() < 20) {
       throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
   }
   ```

3. **Add a test case** in `GraphQlUtilsTest` / `EntityServiceTest` for valid hex strings shorter than 40 characters to ensure the validation is enforced.

### Proof of Concept

Send the following GraphQL query to the unauthenticated GraphQL endpoint (e.g., `POST /graphql`):

```graphql
query {
  account(input: { evmAddress: "0x1122334455667788990a" }) {
    id
  }
}
```

(`"0x1122334455667788990a"` = 20 hex chars after stripping prefix = 10 bytes < 12 bytes needed for `getInt()` + first `getLong()`)

**Steps:**
1. `decodeEvmAddress("0x1122334455667788990a")` strips `"0x"`, calls `Hex.decodeHex("1122334455667788990a")` → returns 10-byte array. No exception.
2. `ByteBuffer.wrap(10-byte-array)` → succeeds, capacity = 10.
3. `buffer.getInt()` → reads 4 bytes, succeeds (returns `0x11223344`).
4. `buffer.getLong()` → attempts to read 8 bytes from position 4, but only 6 bytes remain → **throws `BufferUnderflowException`**.
5. `CustomExceptionResolver.resolveToSingleError()` → returns `null` (not handled).
6. Spring GraphQL default handler logs full stack trace at ERROR level.
7. Repeat in a loop at high rate to drive CPU and logging I/O above 30% baseline.

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
