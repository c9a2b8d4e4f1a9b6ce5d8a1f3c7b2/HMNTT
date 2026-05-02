The key code to analyze is in `EntityServiceImpl.java` and `GraphQlUtils.java`. Let me trace the exact execution path:

**`decodeEvmAddress`** (`GraphQlUtils.java`, lines 87-98): strips `0x` prefix, then calls `Hex.decodeHex()` — **no length validation whatsoever**.

**`getByEvmAddressAndType`** (`EntityServiceImpl.java`, lines 34-41): assumes the decoded byte array is exactly 20 bytes (4 + 8 + 8 = 20). If a 12-byte buffer is passed and the first 12 bytes are all zero, `getInt()` (4 bytes) and the first `getLong()` (8 bytes) consume all 12 bytes, then the second `buffer.getLong()` at line 38 throws `BufferUnderflowException`.

---

### Title
`BufferUnderflowException` via Undersized EVM Address in GraphQL `getByEvmAddressAndType`

### Summary
`GraphQlUtils.decodeEvmAddress` performs no length validation on the decoded byte array. `EntityServiceImpl.getByEvmAddressAndType` unconditionally wraps the result in a `ByteBuffer` and reads 4 + 8 + 8 = 20 bytes. An unauthenticated attacker can supply a 24-hex-character (12-byte) all-zero address, causing the third `buffer.getLong()` call to throw `BufferUnderflowException`, crashing the GraphQL request handler thread.

### Finding Description
**Code path:**
- `GraphQlUtils.decodeEvmAddress` (`graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java`, lines 87–98): accepts any valid hex string, returns `Hex.decodeHex(evmAddress)` with no length check.
- `EntityServiceImpl.getByEvmAddressAndType` (`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41):
  ```java
  byte[] evmAddressBytes = decodeEvmAddress(evmAddress);   // 12 bytes if input is 24 hex chars
  var buffer = ByteBuffer.wrap(evmAddressBytes);            // 12-byte buffer
  if (buffer.getInt() == 0 && buffer.getLong() == 0) {     // consumes all 12 bytes
      return entityRepository.findById(buffer.getLong())   // BufferUnderflowException: 0 bytes remain
  ```

**Root cause:** The code assumes the caller always supplies a 20-byte EVM address. The `decodeEvmAddress` utility enforces only valid hex encoding, not a fixed 20-byte length. The `ByteBuffer` reads are not guarded by a remaining-bytes check.

**Trigger condition:** Input must decode to exactly 12 bytes AND the first 12 bytes must all be zero (so both `getInt() == 0` and `getLong() == 0` evaluate to true, entering the branch that calls the third `getLong()`). Input: `"000000000000000000000000"` (24 hex zeros).

**Why existing checks fail:** `decodeEvmAddress` only catches `DecoderException` (odd-length or non-hex input). It does not validate `evmAddressBytes.length == 20`. There is no GraphQL scalar type or schema-level constraint enforcing a 40-character (20-byte) EVM address.

### Impact Explanation
Every GraphQL request hitting this code path with the crafted input throws an unchecked `BufferUnderflowException`. Spring GraphQL catches it at the resolver boundary and returns an error response, so the JVM does not crash. However, repeated requests cause repeated exception handling overhead and pollute logs. If the GraphQL endpoint is publicly exposed (typical for mirror node deployments), an attacker can trivially loop this request to degrade service quality (partial DoS). No authentication is required.

### Likelihood Explanation
The exploit requires zero privileges, zero knowledge of internal state, and a single specific 24-character hex string. It is fully deterministic and repeatable. Any attacker who can reach the GraphQL endpoint (typically public) can trigger it in a tight loop with minimal tooling (e.g., `curl` or any HTTP client). Likelihood is high.

### Recommendation
Add an explicit length check in `decodeEvmAddress` or at the top of `getByEvmAddressAndType`:

```java
byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
}
```

Alternatively, enforce the constraint at the GraphQL schema layer using a custom scalar that validates the hex string is exactly 40 characters (excluding optional `0x` prefix) before it reaches the service layer.

### Proof of Concept
```
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{ account(input: { evmAddress: \"000000000000000000000000\" }) { id } }"
}
```
**Precondition:** GraphQL endpoint is reachable (no auth required).  
**Trigger:** The 24-character all-zero hex string decodes to 12 bytes; `getInt()` reads bytes 0–3 (= 0), `getLong()` reads bytes 4–11 (= 0), condition is true, second `getLong()` finds 0 remaining bytes → `java.nio.BufferUnderflowException` thrown at `EntityServiceImpl.java:38`.  
**Result:** Request returns a GraphQL error. Repeated in a loop → service degradation.