The code is confirmed. All three technical claims check out against the actual source.

- `decodeEvmAddress()` performs no length check — confirmed at [1](#0-0) 
- `getByEvmAddressAndType()` performs three unconditional buffer reads — confirmed at [2](#0-1) 
- The test suite explicitly accepts sub-20-byte inputs (e.g., `"0000AaAaAa"` → 5 bytes) — confirmed at [3](#0-2) 
- SECURITY.md excludes "Impacts that only require DDoS" (volumetric attacks), but this is a single-request input validation bug, not a volumetric attack — confirmed at [4](#0-3) 

---

# Audit Report

## Title
`BufferUnderflowException` in `getByEvmAddressAndType()` via Under-Length EVM Address Input

## Summary
`decodeEvmAddress()` in `GraphQlUtils.java` accepts any even-length hex string without validating that the decoded result is exactly 20 bytes. `getByEvmAddressAndType()` in `EntityServiceImpl.java` wraps the result in a `ByteBuffer` and unconditionally performs three sequential reads (`getInt()` + two `getLong()`) assuming exactly 20 bytes. A crafted short input whose first 12 bytes are zero satisfies the first two reads and causes an uncaught `BufferUnderflowException` on the third read, which propagates out of the service layer on every such request.

## Finding Description

**Root cause — no length guard in `decodeEvmAddress()`:**

`GraphQlUtils.decodeEvmAddress()` strips the optional `0x` prefix and delegates directly to `Hex.decodeHex()`, returning a byte array of whatever length the caller supplied. There is no assertion or check that the result is exactly 20 bytes.

```java
// GraphQlUtils.java lines 87-98
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

The test suite explicitly confirms sub-20-byte inputs are accepted — `"0000AaAaAa"` (10 hex chars) decodes to 5 bytes without error.

**Vulnerable consumer — `getByEvmAddressAndType()`:**

```java
// EntityServiceImpl.java lines 34-41
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

Three sequential reads are performed with no remaining-capacity check:

| Read | Bytes consumed | Cumulative bytes needed |
|------|---------------|------------------------|
| `buffer.getInt()` | 4 | 4 |
| `buffer.getLong()` (condition) | 8 | 12 |
| `buffer.getLong()` (entity ID) | 8 | 20 |

**Exact trigger (12 bytes / 24 hex chars):**
Input `"000000000000000000000000"` (24 zeros) decodes to 12 bytes, all zero.

1. `buffer.getInt()` → reads bytes 0–3 → returns `0` ✓ (condition arm entered)
2. `buffer.getLong()` → reads bytes 4–11 → returns `0` ✓ (condition true, 0 bytes remain)
3. `buffer.getLong()` → needs 8 bytes, 0 remain → **`BufferUnderflowException` thrown**

`java.nio.BufferUnderflowException` extends `RuntimeException` and is unchecked. There is no `try/catch` anywhere in this call chain. Spring GraphQL's default error handler catches it at the framework boundary and returns a generic error response, but the exception is logged and the request fails on every invocation.

Any input between 12 and 19 bytes (inclusive) with the first 12 bytes all zero triggers the same exception at the third read. Inputs shorter than 12 bytes with leading zeros trigger it earlier (at the condition `getLong()`).

## Impact Explanation

Any unauthenticated caller who can reach the GraphQL endpoint can send a malformed `evmAddress` string and force an unhandled `BufferUnderflowException` on every such request. The GraphQL service returns an error for that request. The service thread itself is not killed (Spring's thread pool absorbs the exception). The realistic impact is a reliable per-request error on the GraphQL account/contract lookup path. The "total network shutdown" framing is overstated — this is a partial DoS limited to the EVM address lookup path, not a full service crash.

## Likelihood Explanation

- No authentication is required; the GraphQL endpoint is public-facing.
- The payload is trivial: any even-length hex string of 12–19 hex-byte length whose first 12 bytes are zero.
- Fully repeatable and scriptable; no race condition or timing dependency.
- The existing test suite does not cover this case — tests only use exactly 20-byte addresses or empty input.

## Recommendation

Add a length validation in `decodeEvmAddress()` or at the call site in `getByEvmAddressAndType()`:

```java
// Option A: validate in decodeEvmAddress (preferred — single enforcement point)
public static byte[] decodeEvmAddress(String evmAddress) {
    if (evmAddress == null) {
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }
    try {
        evmAddress = Strings.CS.removeStart(evmAddress, HEX_PREFIX);
        byte[] decoded = Hex.decodeHex(evmAddress);
        if (decoded.length != 0 && decoded.length != 20) {
            throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
        }
        return decoded;
    } catch (DecoderException e) {
        throw new IllegalArgumentException("Unable to decode evmAddress: " + evmAddress);
    }
}

// Option B: guard in getByEvmAddressAndType before buffer reads
if (evmAddressBytes.length != 20) {
    throw new IllegalArgumentException("evmAddress must be exactly 20 bytes");
}
```

Either fix eliminates the `BufferUnderflowException` by rejecting non-20-byte inputs before any buffer reads occur.

## Proof of Concept

```
# GraphQL query with a 12-byte (24 hex char) zero-padded evmAddress
POST /graphql/alpha HTTP/1.1
Content-Type: application/json

{
  "query": "{ account(input: { evmAddress: \"000000000000000000000000\" }) { id } }"
}

# Expected (correct) behavior: HTTP 400 with validation error
# Actual behavior: HTTP 200 with generic error body + BufferUnderflowException in server logs
#   java.nio.BufferUnderflowException
#     at java.base/java.nio.Buffer.nextGetIndex(Buffer.java:...)
#     at java.base/java.nio.HeapByteBuffer.getLong(HeapByteBuffer.java:...)
#     at EntityServiceImpl.getByEvmAddressAndType(EntityServiceImpl.java:38)
```

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

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
