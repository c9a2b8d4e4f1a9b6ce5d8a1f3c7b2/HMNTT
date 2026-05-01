### Title
`BufferUnderflowException` via Under-Length EVM Address in `getByEvmAddressAndType()`

### Summary
`EntityServiceImpl.getByEvmAddressAndType()` wraps the decoded EVM address bytes in a `ByteBuffer` and unconditionally calls `getInt()` + `getLong()` + `getLong()` (consuming exactly 20 bytes), but `decodeEvmAddress()` performs no length validation and will happily return fewer than 20 bytes for any even-length hex string shorter than 40 chars. An unauthenticated attacker can supply a 38-hex-char (19-byte) address whose first 12 bytes are zero, satisfying both zero-checks and then triggering a `BufferUnderflowException` on the third read, producing an internal-error GraphQL response instead of the expected entity record.

### Finding Description

**Exact code path:**

`AccountController.account()` passes the raw `evmAddress` string directly to `EntityServiceImpl.getByEvmAddressAndType()`: [1](#0-0) 

`decodeEvmAddress()` strips the optional `0x` prefix and calls `Hex.decodeHex()` with **no length check**: [2](#0-1) 

`Hex.decodeHex` only rejects odd-length strings (throws `DecoderException`); a 38-char string is even and decodes to 19 bytes without error. The test suite confirms `decodeEvmAddress` returns variable-length arrays (e.g., 5 bytes for `"0000AaAaAa"`): [3](#0-2) 

`getByEvmAddressAndType()` then wraps the result in a `ByteBuffer` and reads 4 + 8 + 8 = 20 bytes unconditionally: [4](#0-3) 

**Root cause:** No assertion that `evmAddressBytes.length == 20` exists anywhere between `decodeEvmAddress()` and the three `ByteBuffer` reads.

**Exploit flow:**
1. Attacker sends a 38-hex-char address whose first 24 chars are `0` (12 zero bytes), e.g. `"00000000000000000000000000000000000000"` (38 zeros).
2. `decodeEvmAddress()` returns a 19-byte array — no exception.
3. `buffer.getInt()` consumes bytes 0–3 (all zero) → returns `0`, condition passes.
4. First `buffer.getLong()` consumes bytes 4–11 (all zero) → returns `0`, condition passes.
5. Second `buffer.getLong()` attempts to read bytes 12–19 but only 7 bytes (12–18) remain → **`BufferUnderflowException`** thrown.
6. No `try/catch` in the controller or service catches this unchecked exception; Spring GraphQL returns an internal-error response.

**Why existing checks fail:**
- `decodeEvmAddress()` only rejects null, odd-length hex, and non-hex characters — not under-length even-length strings.
- The `invalidEvmAddress` test only covers 37-char (odd) and 41-char (too long) inputs, not 38-char inputs.
- The GraphQL schema defines `evmAddress` as a plain `String` with no length constraint.
- `@Valid` on `AccountInput` in the controller provides no protection unless `AccountInput.evmAddress` carries a `@Size`/`@Pattern` annotation, which is not present in the code.

### Impact Explanation
Any unauthenticated caller of the public GraphQL endpoint (`/graphql/alpha`) can trigger an unhandled `BufferUnderflowException`, causing the server to return an internal-error GraphQL response instead of the correct entity record. This constitutes incorrect behavior (wrong error class surfaced to the caller) and a trivially repeatable denial-of-service against the account-lookup path. No data is leaked, but availability and correctness of the API are impaired.

### Likelihood Explanation
The GraphQL endpoint is publicly accessible with no authentication required. The trigger requires only crafting a hex string of exactly 38 characters with 24 leading zeros — trivial for any attacker. The attack is deterministic and 100% reproducible. No special privileges, tokens, or knowledge of internal state are needed.

### Recommendation
Add an explicit length check in `getByEvmAddressAndType()` immediately after decoding:

```java
byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("EVM address must be exactly 20 bytes");
}
```

Alternatively, enforce the constraint in `decodeEvmAddress()` itself, or add a `@Pattern(regexp = "^(0x)?[0-9a-fA-F]{40}$")` Bean Validation annotation to `AccountInput.evmAddress`.

### Proof of Concept

Send the following GraphQL request to `/graphql/alpha` (no authentication required):

```graphql
POST /graphql/alpha
Content-Type: application/json

{
  "query": "{ account(input: { evmAddress: \"00000000000000000000000000000000000000\" }) { entityId { num } } }"
}
```

The `evmAddress` value is 38 hex chars (19 bytes), first 24 chars are `0`.

**Expected (correct) result:** A validation error such as `"Invalid EVM address length"`.

**Actual result:** An internal server error GraphQL response caused by an unhandled `java.nio.BufferUnderflowException` thrown at `EntityServiceImpl.java:38` (`buffer.getLong()`), because only 7 bytes remain in the buffer when 8 are required.

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
