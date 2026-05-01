### Title
Cache-Bypass DoS via Uncached Negative Lookups in `findByEvmAddressAndDeletedIsFalse`

### Summary
Spring Cache's `@Cacheable` with `unless = "#result == null"` on an `Optional<Entity>` return type does not cache negative (miss) results because Spring unwraps the `Optional` before evaluating the SpEL expression — `Optional.empty()` is treated as `null`, so the `unless` condition is always true for misses and the result is never stored. An unauthenticated attacker can flood the `/api/v1/contracts/call` endpoint with requests targeting random EVM addresses, causing every lookup to hit the database. The only protection is a single global (not per-IP) rate bucket of 500 req/s, which the attacker can fully monopolize, starving legitimate users.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–37.

```java
@Cacheable(
        cacheNames = CACHE_NAME_EVM_ADDRESS,
        cacheManager = CACHE_MANAGER_ENTITY,
        key = "@spelHelper.hashCode(#alias)",
        unless = "#result == null")
Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
```

**Root cause:** Spring Framework's caching abstraction unwraps `Optional` return values before evaluating `unless`. When the repository finds no entity, it returns `Optional.empty()`. Spring unwraps this to `null`, so `#result == null` evaluates to `true`, and the result is excluded from the cache. Every subsequent call with the same (or any non-existent) address bypasses the cache and issues a fresh SQL query.

**Cache configuration** (`web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java`, line 19):
```
expireAfterWrite=1s,maximumSize=10000,recordStats
```
Even for addresses that *do* exist, the 1-second TTL means the cache provides minimal protection under sustained load.

**Exploit flow:**
1. Attacker sends `POST /api/v1/contracts/call` with `"to": "<random 20-byte hex address>"` at the maximum allowed rate.
2. `ContractController.call()` passes the request through `ThrottleManagerImpl.throttle()` (global bucket, 500 req/s).
3. EVM execution resolves the `to` address via `CommonEntityAccessor.getEntityByEvmAddressTimestamp()` → `findByEvmAddressAndDeletedIsFalse(addressBytes)`.
4. No entity found → `Optional.empty()` → Spring treats as `null` → `unless` fires → result not cached.
5. Every request hits the database. The attacker rotates addresses to prevent any cache hits.
6. The global 500 req/s bucket is fully consumed by the attacker; legitimate users receive `429 Too Many Requests`.

**Why existing checks fail:**
- `ThrottleManagerImpl` uses a single shared `rateLimitBucket` (500 req/s) with no per-IP partitioning (`web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42). One attacker exhausts the entire budget.
- Gas-based throttling (`gasLimitBucket`) can be minimized by sending requests with `gas: 21000` (below the `GAS_SCALE_FACTOR` of 10,000, which rounds to 0 tokens consumed — `ThrottleProperties.scaleGas()`, line 43–46 of `ThrottleProperties.java`), making gas throttling ineffective.
- No authentication is required for the endpoint.
- The `db.statementTimeout` of 3000 ms means each DB query holds a connection for up to 3 seconds, amplifying connection pool exhaustion.

### Impact Explanation
A single unauthenticated attacker can consume the entire global request budget (500 req/s), causing all legitimate contract-call requests to be rejected with HTTP 429. Simultaneously, the database receives up to 500 indexed lookups per second for non-existent addresses, increasing connection pool pressure and query latency. This constitutes a complete availability denial for the Web3 API endpoint with no privilege requirement.

### Likelihood Explanation
The attack requires no credentials, no on-chain assets, and no special knowledge — only the ability to send HTTP POST requests. The exploit is trivially scriptable (e.g., `curl` in a loop with random hex addresses). The global (non-per-IP) throttle means a single host can execute the full attack. The 1-second cache TTL further reduces any residual protection. Repeatability is unlimited.

### Recommendation
1. **Cache negative results:** Change `unless = "#result == null"` to `unless = "#result != null && !#result.isPresent()"` — but note Spring's Optional unwrapping means you should instead use `unless = "T(java.util.Optional).empty().equals(#result)"` or switch to returning `Entity` directly and caching `null` via a null-value sentinel. Alternatively, use a dedicated negative-result cache that stores empty markers.
2. **Per-IP rate limiting:** Introduce a per-source-IP rate limiter (e.g., via a servlet filter or Spring Cloud Gateway) in addition to the global bucket.
3. **Increase gas floor:** Raise `GAS_SCALE_FACTOR` or enforce a minimum gas value so that gas-bucket throttling cannot be bypassed with `gas=21000`.
4. **Increase cache TTL or use `expireAfterAccess`:** A 1-second TTL provides negligible protection; increase it to at least 10–30 seconds for entity lookups.

### Proof of Concept
```bash
# Send 500 requests/second with random EVM addresses (no auth required)
for i in $(seq 1 500); do
  ADDR=$(openssl rand -hex 20)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"0x${ADDR}\",\"gas\":21000,\"data\":\"0x\"}" &
done
wait
# Repeat in a loop — legitimate users now receive HTTP 429
# Each request causes a DB query: SELECT * FROM entity WHERE evm_address = $1 AND deleted IS NOT TRUE
```

Preconditions: network access to the Web3 API endpoint. No account, token, or on-chain state required.