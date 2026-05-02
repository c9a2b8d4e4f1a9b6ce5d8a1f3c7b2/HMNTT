### Title
Cache Key Collision via `Arrays.hashCode` Allows Cross-Entity Data Leakage in EVM Address Lookup

### Summary
`findByEvmAddressAndDeletedIsFalse()` and `findByEvmAddressOrAliasAndDeletedIsFalse()` use `@spelHelper.hashCode(#alias)` as the sole cache key, which resolves to a 32-bit `int` via `Arrays.hashCode(byte[])`. Because the cache stores entries keyed by this integer (not the original byte array), two distinct 20-byte EVM addresses that produce the same `Arrays.hashCode` value map to the same cache slot, causing the cache to return entity A's data for entity B's address query.

### Finding Description
**Code locations:**

- `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–49: both `findByEvmAddressAndDeletedIsFalse` and `findByEvmAddressOrAliasAndDeletedIsFalse` use `key = "@spelHelper.hashCode(#alias)"`.
- `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22: `hashCode(byte[] value)` returns `Arrays.hashCode(value)` — a 32-bit polynomial hash (`result = 31 * result + b` for each byte).

**Root cause:** The SpEL key expression evaluates to a plain Java `int` (autoboxed to `Integer`). Spring's `CaffeineCacheManager` stores this `Integer` as the actual map key. Two different `byte[]` inputs that produce the same `Arrays.hashCode` integer are indistinguishable at the cache layer — the second lookup returns the first entry's cached value without ever reaching the database.

**Exploit flow:**
1. Entity A exists at EVM address `addrA`. A query for `addrA` populates the cache under key `k = Arrays.hashCode(addrA)`.
2. Attacker computes `addrB ≠ addrA` such that `Arrays.hashCode(addrB) == k`. This is trivial: the 32-bit output space means collisions are found in O(2^16) attempts via birthday attack, or analytically by solving the linear recurrence.
3. Attacker queries `addrB`. The cache returns entity A's record instead of entity B's (or `empty` if B doesn't exist but A does).

**Why existing checks fail:** `unless = "#result == null"` only suppresses caching of null results. It provides no protection against key collisions. There is no secondary equality check on the original byte array after a cache hit.

### Impact Explanation
An unprivileged caller can retrieve the full `Entity` record (account ID, balance, keys, type, etc.) of an arbitrary cached entity by querying a crafted colliding address. This causes incorrect entity data to be served for EVM address lookups, directly producing incorrect records exported to mirror nodes and potentially incorrect smart contract execution results (e.g., wrong account resolved during `eth_call`). Severity: **Medium** — data confidentiality and correctness are both affected, but exploitation requires the target entity to already be in the cache.

### Likelihood Explanation
Finding a 32-bit `Arrays.hashCode` collision for 20-byte arrays requires no special privileges and is computationally trivial (birthday bound ~65,536 attempts). The attacker does not need to know the target's private key or any on-chain secret — only the target's EVM address (publicly visible on-chain). The cache is populated by normal user traffic, so a busy node will have many cached entries to collide against. The attack is fully repeatable and stateless.

### Recommendation
Replace the integer hash with a collision-resistant key. The simplest correct fix is to use the hex-encoded address string or `Arrays.toString(alias)` as the cache key, which preserves full byte-array identity:

```java
key = "T(org.bouncycastle.util.encoders.Hex).toHexString(#alias)"
// or simply:
key = "new String(#alias, T(java.nio.charset.StandardCharsets).ISO_8859_1)"
```

Alternatively, use Spring's default key generation (remove the `key =` attribute) which calls `SimpleKeyGenerator` and uses the actual `byte[]` reference — but note that `byte[]` `equals()` is reference equality, so a safer approach is to wrap in a `ByteBuffer` or use `java.util.HexFormat.of().formatHex(#alias)` as the key, ensuring structural equality without hash collisions.

### Proof of Concept
```java
// Find two 20-byte arrays with the same Arrays.hashCode:
// Arrays.hashCode iterates: result = 31*result + (byte & 0xFF)
// Fix bytes 0..18 identically; solve for byte[19] to match.
// Example (pseudocode):
byte[] addrA = new byte[20]; // some real entity address
int target = Arrays.hashCode(addrA);

for (int b = -128; b <= 127; b++) {
    byte[] addrB = Arrays.copyOf(addrA, 20);
    addrB[0] ^= 1;          // differ in byte 0
    addrB[19] = (byte) b;   // adjust last byte to restore hash
    if (Arrays.hashCode(addrB) == target && !Arrays.equals(addrA, addrB)) {
        // addrB collides with addrA — query addrB to get entity A's record
        break;
    }
}
// Send eth_call / contract_call with addrB as the target address.
// The mirror node cache returns entity A's Entity object for addrB's lookup.
```