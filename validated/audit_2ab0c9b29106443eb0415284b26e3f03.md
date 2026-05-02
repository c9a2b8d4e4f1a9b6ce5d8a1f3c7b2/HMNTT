I verified all the key technical claims against the actual code. Here is my assessment:

**Verified facts:**

1. `ContractRepository.java` line 16 uses `unless = "#result == null"` on a method returning `Optional<byte[]>` — confirmed. [1](#0-0) 

2. Spring's `CacheAspectSupport` unwraps `Optional` before evaluating SpEL `#result`. `Optional.empty()` → `#result == null` → `unless` is `true` → **never cached**. This is documented Spring behavior and the claim is technically accurate.

3. Cache config `expireAfterAccess=1h,maximumSize=1000` — confirmed. [2](#0-1) 

4. `scaleGas()` math is correct: `scaleGas(21_000) = 2` tokens, gas bucket = 750,000 tokens → gas throttle allows ~375,000 req/s, far above the binding rate limit. [3](#0-2) 

5. `requestsPerSecond = 500` is the global default, and `ThrottleManagerImpl` uses a single shared `rateLimitBucket` — not per-IP. [4](#0-3) [5](#0-4) 

All required checks pass. The finding is valid.

---

# Audit Report

## Title
Cache-Miss Amplification DoS via Non-Existent Contract IDs in `findRuntimeBytecode()`

## Summary
`ContractRepository.findRuntimeBytecode()` is annotated with `@Cacheable(unless = "#result == null")` but returns `Optional<byte[]>`. Spring unwraps `Optional` before evaluating SpEL `#result`, so queries for non-existent contracts always produce `#result == null`, the `unless` condition is always `true`, and the empty result is **never stored in the cache**. An unauthenticated attacker can sustain 500 uncached database queries per second indefinitely using the global rate limit.

## Finding Description

**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

**Root cause:** Spring Framework's `CacheAspectSupport` unwraps `Optional` return values before evaluating `unless`/`condition` SpEL expressions and before storing in the cache. The intended semantics of `unless = "#result == null"` — "don't cache absent results" — are inverted: it correctly caches present results but **never caches absent ones**, even for repeated identical lookups.

- `Optional.of(bytes)` → `#result = bytes` (non-null) → `unless` false → **cached** ✓  
- `Optional.empty()` → `#result = null` → `unless` true → **not cached, DB hit every time** ✗

The contract cache is configured with `expireAfterAccess=1h, maximumSize=1000`, so a cached miss would be protected for up to one hour. [2](#0-1) 

**Throttle bypass math:**

`scaleGas(21_000) = Math.floorDiv(21_000, 10_000) = 2` tokens consumed per minimum-gas request. The gas bucket holds `scaleGas(7_500_000_000) = 750_000` tokens, refilling at 750,000/s. The gas throttle permits ~375,000 req/s — far above the binding constraint. [6](#0-5) 

The only effective constraint is the global rate limit of 500 req/s, enforced by a single shared `rateLimitBucket` (not per-IP): [7](#0-6) 

## Impact Explanation

A single unauthenticated attacker saturating the 500 req/s global bucket with requests targeting distinct non-existent contract addresses forces 500 live `SELECT runtime_bytecode FROM contract WHERE id = ?` queries per second against the database, sustained indefinitely. This exhausts DB connection pool capacity, increases query latency for all concurrent operations (entity lookups, token lookups, state reads), and degrades or denies service to legitimate users. Because the rate bucket is global and not per-IP, the attacker simultaneously crowds out all legitimate traffic.

## Likelihood Explanation

No authentication or API key is required. Generating valid 40-character hex addresses that do not correspond to existing contracts is trivial to script. The attack is fully repeatable from a single machine, requires no special knowledge of the system, and can be sustained at the 500 req/s ceiling indefinitely. The minimum gas constraint (`@Min(21_000)`) does not meaningfully limit throughput given the gas bucket math above.

## Recommendation

Replace the `unless` condition to correctly handle the `Optional` wrapper. Since Spring unwraps `Optional` before SpEL evaluation, use:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null"
)
```

This annotation is already correct for the **unwrapped** value — the real fix is to ensure empty `Optional` results are also cached. Change the `unless` condition to never exclude empty results, or use a `condition` that caches both present and absent results:

```java
// Option A: cache everything (including empty Optional, stored as null)
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT)

// Option B: explicit — only skip caching if the Optional itself is null (method error)
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "false"   // always cache
)
```

The simplest correct fix is to remove the `unless` clause entirely, allowing Spring to cache the unwrapped `null` (from `Optional.empty()`) so that repeated lookups for the same non-existent ID are served from cache.

Additionally, consider adding per-IP rate limiting to prevent a single client from monopolizing the global 500 req/s bucket. [4](#0-3) 

## Proof of Concept

```
# Generate 500 distinct non-existent contract addresses and send at max rate
for i in $(seq 1 500); do
  ADDR=$(printf "0x%040x" $((0xDEAD000000000000 + i)))
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$ADDR\",\"gas\":21000,\"data\":\"0x\"}" &
done
wait
```

Each request targets a unique non-existent address. Because `Optional.empty()` is never cached, every request issues a live `SELECT runtime_bytecode FROM contract WHERE id = ?`. At 500 req/s (the global ceiling), this produces 500 uncached DB queries per second. Legitimate users sharing the same global rate bucket receive degraded or no service.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java (L16-18)
```java
    @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
    @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
    Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L22-22)
```java
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-47)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;

    // Necessary since bucket4j has a max capacity and fill rate of 1 token per nanosecond
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-41)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
```
