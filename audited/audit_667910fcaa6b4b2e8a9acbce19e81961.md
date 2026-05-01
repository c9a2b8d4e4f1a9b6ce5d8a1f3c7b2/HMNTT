### Title
`BufferUnderflowException` via Short EVM Address in `getByEvmAddressAndType()` Causes Unhandled Server Error

### Summary
`EntityServiceImpl.getByEvmAddressAndType()` wraps the decoded EVM address bytes in a `ByteBuffer` and performs three sequential reads (one `getInt()` + two `getLong()`), assuming exactly 20 bytes. Neither `decodeEvmAddress()` nor `getByEvmAddressAndType()` validates the byte length. An unauthenticated user can supply a 24-hex-char (12-byte) all-zero address, satisfying the `getInt() == 0 && getLong() == 0` branch condition while leaving zero bytes for the third read, causing `java.nio.BufferUnderflowException`. The `CustomExceptionResolver` does not handle this exception type, so it propagates as an unresolved internal error.

### Finding Description

**Exact code path:**

`AccountController.account()` receives the raw `evmAddress` string from the GraphQL input and passes it directly to `entityService.getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)` with no length pre-check. [1](#0-0) 

`decodeEvmAddress()` strips the optional `0x` prefix and hex-decodes the string with no length validation: [2](#0-1) 

`getByEvmAddressAndType()` then performs three sequential buffer reads assuming 20 bytes: [3](#0-2) 

**Root cause / failed assumption:** The code assumes `evmAddressBytes.length == 20`. With a 12-byte input:
- `buffer.getInt()` consumes bytes 0–3 (4 bytes of zeros → returns 0)
- `buffer.getLong()` consumes bytes 4–11 (8 bytes of zeros → returns 0)
- The `if` condition is `true`, so `buffer.getLong()` is called a third time with **0 bytes remaining** → `java.nio.BufferUnderflowException`

**Why existing checks fail:** `CustomExceptionResolver.resolveToSingleError()` only handles `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`. `BufferUnderflowException` (a `RuntimeException` from `java.nio`) is not listed, so `resolveToSingleError` returns `null`, leaving Spring GraphQL to emit a generic internal error. [4](#0-3) 

### Impact Explanation
Any unauthenticated caller can trigger a repeatable unhandled server-side exception on the GraphQL `account` query endpoint. The response is an opaque internal error rather than a proper entity lookup or a clean validation error. Depending on framework configuration this may also leak stack-trace details. Repeated calls constitute a low-cost denial-of-service against this query path.

### Likelihood Explanation
No authentication or special privilege is required. The GraphQL endpoint is publicly reachable. The payload is trivial: a 24-character hex string of all zeros (`000000000000000000000000`). The condition is deterministic and 100% reproducible.

### Recommendation
1. Add a length guard in `decodeEvmAddress()` or at the top of `getByEvmAddressAndType()`:
   ```java
   if (evmAddressBytes.length != 20) {
       throw new IllegalArgumentException("EVM address must be 20 bytes");
   }
   ```
   `IllegalArgumentException` is already handled by `CustomExceptionResolver` and will produce a clean `ValidationError` GraphQL response.
2. Alternatively, add a `@Pattern(regexp = "^(0x)?[0-9a-fA-F]{40}$")` Bean Validation constraint on the `evmAddress` field of `AccountInput`.

### Proof of Concept

Send the following GraphQL request to the mirror-node GraphQL endpoint (no authentication needed):

```graphql
{
  account(input: { evmAddress: "000000000000000000000000" }) {
    balance
  }
}
```

**Step-by-step:**
1. `decodeEvmAddress("000000000000000000000000")` → `byte[12]` all zeros (no length check)
2. `ByteBuffer.wrap(byte[12])` → buffer with 12 bytes
3. `buffer.getInt()` → reads 4 bytes, returns `0`; 8 bytes remain
4. `buffer.getLong()` → reads 8 bytes, returns `0`; 0 bytes remain
5. `if (0 == 0 && 0 == 0)` → `true`
6. `buffer.getLong()` → **`BufferUnderflowException`** (0 bytes remaining, needs 8)
7. `CustomExceptionResolver` returns `null` for this exception type → unhandled internal server error response

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-54)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/CustomExceptionResolver.java (L16-26)
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
```
