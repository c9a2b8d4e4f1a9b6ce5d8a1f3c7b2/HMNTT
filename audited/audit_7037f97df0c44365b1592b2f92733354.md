### Title
`BufferUnderflowException` via Under-Length EVM Address in `getByEvmAddressAndType`

### Summary
`getByEvmAddressAndType` in `EntityServiceImpl.java` wraps the decoded EVM address bytes in a `ByteBuffer` and performs three sequential reads (4 + 8 + 8 = 20 bytes) without first validating that the input is exactly 20 bytes. An unauthenticated caller can supply a 16-byte hex string whose first 12 bytes are zero, satisfying the `if` condition and triggering an unhandled `BufferUnderflowException` on the third read, where only 4 bytes remain but 8 are required.

### Finding Description
**Code path:**

- `GraphQlUtils.decodeEvmAddress` ( [1](#0-0) ) strips the `0x` prefix and calls `Hex.decodeHex`. It validates only that the string is valid hex — **no length check is performed on the resulting byte array**.

- `EntityServiceImpl.getByEvmAddressAndType` ( [2](#0-1) ) then does:
  ```java
  var buffer = ByteBuffer.wrap(evmAddressBytes);          // wraps whatever length arrived
  if (buffer.getInt() == 0 && buffer.getLong() == 0) {   // consumes 4 + 8 = 12 bytes
      return entityRepository.findById(buffer.getLong()); // needs 8 more bytes
  }
  ```

**Root cause:** The code assumes the caller always supplies exactly 20 bytes (a valid EVM address). There is no `assert evmAddressBytes.length == 20` or equivalent guard anywhere in the call chain.

**Exploit flow:**
1. Attacker sends a GraphQL query with `evmAddress: "0x000000000000000000000000AABBCCDD"` (32 hex chars after prefix = 16 bytes).
2. `decodeEvmAddress` decodes it to 16 bytes without error.
3. `buffer.getInt()` reads bytes 0–3 (`0x00000000`) → returns 0, condition continues.
4. `buffer.getLong()` reads bytes 4–11 (`0x0000000000000000`) → returns 0, condition is true, body entered.
5. `buffer.getLong()` on line 38 attempts to read 8 bytes but only 4 remain → **`BufferUnderflowException`** thrown.
6. No `try/catch` exists in this method or its callers for this exception type.

**Why existing checks are insufficient:** `decodeEvmAddress` only catches `DecoderException` (invalid hex characters) and re-throws as `IllegalArgumentException`. It does not enforce a 20-byte length constraint. [3](#0-2) 

### Impact Explanation
`BufferUnderflowException` is an unchecked `RuntimeException`. In a Spring for GraphQL deployment it will propagate out of the resolver, be caught by the framework's default error handler, and returned as a GraphQL error — the JVM itself does not crash. However: (a) it exposes an unhandled exception path from a public endpoint, (b) depending on error-handler configuration it may leak a stack trace, and (c) if the GraphQL error handler is not configured to swallow it gracefully, repeated requests can saturate thread pools or trigger circuit-breaker logic. The "total network shutdown" framing is overstated; the realistic impact is **unhandled exception / partial denial-of-service at the request level** for the GraphQL service.

### Likelihood Explanation
The GraphQL endpoint is publicly reachable with no authentication required to query account data. The trigger condition (first 12 bytes all zero) is trivially constructable. The attack is deterministic and repeatable with a single crafted query, requiring no special privileges, tokens, or knowledge of internal state.

### Recommendation
Add an explicit length guard in `decodeEvmAddress` or at the top of `getByEvmAddressAndType`:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    if (evmAddressBytes.length != 20) {
        throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
    }
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    ...
}
```

Alternatively, enforce the length constraint inside `decodeEvmAddress` itself so all callers benefit. [2](#0-1) 

### Proof of Concept
```graphql
# GraphQL query — no authentication required
query {
  account(input: {
    evmAddress: {
      address: "0x000000000000000000000000AABBCCDD"
    }
  }) {
    id
  }
}
```

**Step-by-step:**
1. Start the mirror-node GraphQL service.
2. Send the query above to the `/graphql` endpoint.
3. `decodeEvmAddress("0x000000000000000000000000AABBCCDD")` returns a 16-byte array — no exception.
4. `ByteBuffer.wrap(16-byte array)`: capacity = 16.
5. `buffer.getInt()` → reads 4 bytes, returns 0 (condition passes).
6. `buffer.getLong()` → reads 8 bytes, returns 0 (condition passes, body entered).
7. `buffer.getLong()` → position = 12, remaining = 4, needs 8 → **`java.nio.BufferUnderflowException`** thrown.
8. Exception propagates uncaught through `AccountController` → Spring GraphQL error handler.

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
