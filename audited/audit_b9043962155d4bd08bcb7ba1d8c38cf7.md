### Title
Missing Length Validation in `getByEvmAddressAndType` Causes Unhandled `BufferUnderflowException`

### Summary
`decodeEvmAddress()` performs no length check on the decoded byte array, so any hex string between 12 and 19 bytes (24–38 hex chars) whose first 12 bytes are all zeros will pass both short-circuit conditions in the `if` statement and then cause `ByteBuffer.getLong()` to throw `BufferUnderflowException`. The custom exception resolver does not handle this exception type, so Spring GraphQL propagates it as an unresolved internal error rather than a clean validation error.

### Finding Description
**Code path:**

`AccountController.account()` → `entityService.getByEvmAddressAndType(evmAddress, ...)` → `decodeEvmAddress(evmAddress)` → `ByteBuffer` reads.

`decodeEvmAddress()` only strips the `0x` prefix and calls `Hex.decodeHex()`. No length check is performed: [1](#0-0) 

The caller immediately wraps the result in a `ByteBuffer` and performs three sequential reads that together require exactly 20 bytes: [2](#0-1) 

- `buffer.getInt()` consumes bytes 0–3 (needs ≥ 4 bytes)
- First `buffer.getLong()` consumes bytes 4–11 (needs ≥ 12 bytes total)
- Second `buffer.getLong()` consumes bytes 12–19 (needs exactly 20 bytes total)

**Root cause:** The failed assumption is that `evmAddress` always decodes to exactly 20 bytes. No such invariant is enforced anywhere before the `ByteBuffer` reads.

**Exploit flow:**
1. Attacker sends a GraphQL `account` query with `evmAddress: "000000000000000000000000"` (24 hex chars = 12 bytes, all zeros).
2. `decodeEvmAddress` returns a 12-byte array without error.
3. `buffer.getInt()` returns `0` → condition is `true`.
4. First `buffer.getLong()` returns `0` → condition is `true`; the `if` branch is entered.
5. Second `buffer.getLong()` finds 0 remaining bytes → throws `java.nio.BufferUnderflowException`.

**Why the note about 11 bytes in the question is slightly off:** With 11 bytes the *first* `getLong()` (not the second) throws, because only 7 bytes remain after `getInt()`. The actual trigger window is **12–19 bytes** with the first 12 bytes all zero.

**Why existing checks are insufficient:**
`CustomExceptionResolver.resolveToSingleError` only handles `IllegalStateException`, `IllegalArgumentException`, and `MirrorNodeException`: [3](#0-2) 

`BufferUnderflowException` is none of these; the resolver returns `null`, causing Spring GraphQL to fall back to its default INTERNAL_ERROR handler instead of a clean validation error.

### Impact Explanation
Every request with a crafted short all-zero hex address triggers an unhandled `BufferUnderflowException`. The service thread itself is not killed (Spring GraphQL catches unresolved exceptions at the framework level), so this does **not** cause a total network shutdown. The realistic impact is: (a) the caller receives a generic INTERNAL_ERROR response leaking the exception type, and (b) an attacker can repeatedly trigger this to generate noise in logs and degrade observability. Severity is **Medium** — it is a reliable, unauthenticated error injection, but not a crash or data-exposure issue.

### Likelihood Explanation
No authentication is required. The `evmAddress` field is a plain string input accepted by the public GraphQL endpoint. The payload is trivial to construct (e.g., `"000000000000000000000000"`). Any external user can reproduce it deterministically and repeatedly.

### Recommendation
Add an explicit length check in `decodeEvmAddress` or at the top of `getByEvmAddressAndType`:

```java
byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException(
        "evmAddress must be exactly 20 bytes, got " + evmAddressBytes.length);
}
```

`IllegalArgumentException` is already handled by `CustomExceptionResolver` and will produce a clean `ValidationError` response instead of an unhandled internal exception. [2](#0-1) 

### Proof of Concept
```
POST /graphql/alpha HTTP/1.1
Content-Type: application/json

{
  "query": "{ account(input: { evmAddress: \"000000000000000000000000\" }) { id } }"
}
```

**Expected (correct) response:** `{"errors":[{"message":"evmAddress must be exactly 20 bytes","extensions":{"classification":"ValidationError"}}]}`

**Actual response (before fix):** `{"errors":[{"message":"INTERNAL_ERROR","extensions":{"classification":"INTERNAL_ERROR"}}]}` with a `BufferUnderflowException` stack trace in server logs.

Any hex string of 24–38 characters whose first 24 characters are `000000000000000000000000` will trigger the same path. Strings of 12–22 hex chars (6–11 bytes) will throw on the *first* `getLong()` instead, which is also unhandled.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/CustomExceptionResolver.java (L16-28)
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
```
