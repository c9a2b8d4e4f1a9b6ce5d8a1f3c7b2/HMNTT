### Title
Unsanitized User Input Reflected in GraphQL Error Response via `decodeEvmAddress()`

### Summary
`GraphQlUtils.decodeEvmAddress()` performs no character-set validation before passing the user-supplied EVM address string to `Hex.decodeHex()`. When the input contains whitespace (or any non-hex character), a `DecoderException` is caught and rethrown as an `IllegalArgumentException` whose message directly embeds the raw user-supplied string. `CustomExceptionResolver` then forwards `ex.getMessage()` verbatim into the GraphQL error response returned to the caller, with no authentication required.

### Finding Description
**Exact code path:**

`AccountController.account()` receives the `evmAddress` field from the GraphQL input and passes it directly to `entityService.getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)`. [1](#0-0) 

`EntityServiceImpl.getByEvmAddressAndType()` immediately delegates to `decodeEvmAddress(evmAddress)` with no prior format check. [2](#0-1) 

Inside `decodeEvmAddress()`, the only guard is a null check. After stripping the optional `0x` prefix, the string is handed to `Hex.decodeHex()`. Any non-hex character (including space `0x20`, tab `0x09`, newline `0x0a`, etc.) causes `DecoderException`. The catch block constructs the error message by string-concatenating the still-user-controlled `evmAddress` variable: [3](#0-2) 

`CustomExceptionResolver` matches `IllegalArgumentException` and calls `ex.getMessage()` directly as the GraphQL error `message` field, returning it to the caller: [4](#0-3) 

**Root cause:** The failed assumption is that `evmAddress` will only ever contain valid hex characters. No allowlist/regex validation is applied before `Hex.decodeHex()`, and the raw (post-prefix-strip) input is concatenated into the exception message that is surfaced to the client.

**Why existing checks fail:** The only check is `if (evmAddress == null)`. There is no regex guard (compare `EntityIdEvmAddressParameter`, which uses `EVM_ADDRESS_PATTERN = Pattern.compile("^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$")` before decoding). [5](#0-4) 

### Impact Explanation
**Reflected input in API error responses:** The GraphQL error response body will contain the exact attacker-controlled string (e.g., `"Unable to decode evmAddress: abc def\nFAKE LOG ENTRY"`). While spaces/tabs alone are cosmetically harmless in a JSON string, the same unsanitized path accepts `\n`, `\r\n`, and other control characters, enabling **log injection**: if the server logs the exception message (standard Spring behavior), an attacker can forge structured log lines. Additionally, any downstream system that parses or displays the error message receives attacker-controlled content.

### Likelihood Explanation
Exploitation requires zero authentication and zero special privileges — a single unauthenticated GraphQL HTTP POST is sufficient. The GraphQL endpoint is publicly reachable by design. The attack is trivially repeatable and requires no tooling beyond `curl`. The same input path is exercised by any client querying `account(input: { evmAddress: "..." })`.

### Recommendation
Apply an allowlist regex validation on `evmAddress` before calling `Hex.decodeHex()`, matching the pattern already used in `EntityIdEvmAddressParameter`:

```java
private static final Pattern EVM_ADDRESS_PATTERN =
    Pattern.compile("^(?:0x)?[0-9a-fA-F]{40}$");

public static byte[] decodeEvmAddress(String evmAddress) {
    if (evmAddress == null) return ArrayUtils.EMPTY_BYTE_ARRAY;
    if (!EVM_ADDRESS_PATTERN.matcher(evmAddress).matches()) {
        throw new IllegalArgumentException("Invalid evmAddress format");
        // Note: do NOT echo evmAddress back in the message
    }
    try {
        evmAddress = Strings.CS.removeStart(evmAddress, HEX_PREFIX);
        return Hex.decodeHex(evmAddress);
    } catch (DecoderException e) {
        throw new IllegalArgumentException("Invalid evmAddress format");
    }
}
```

The error message must **not** include the user-supplied value.

### Proof of Concept
```bash
curl -s -X POST http://<mirror-node-host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "{ account(input: { evmAddress: \"0xabcd efgh1234567890123456789012\" }) { balance } }"
  }'
```

**Expected response (no fix applied):**
```json
{
  "errors": [{
    "message": "Unable to decode evmAddress: abcd efgh1234567890123456789012",
    "locations": [...],
    "path": ["account"],
    "extensions": { "classification": "ValidationError" }
  }]
}
```

The attacker-supplied whitespace-embedded string appears verbatim in the `message` field of the error response. Substituting `\n` for the space demonstrates log injection in server logs.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-54)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-35)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/CustomExceptionResolver.java (L16-25)
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
```
