### Title
Cache-Miss DoS via Unbounded DB Queries on Non-Existent Alias Lookups in `findByEvmAddressOrAliasAndDeletedIsFalse`

### Summary
The `@Cacheable` annotation on `findByEvmAddressOrAliasAndDeletedIsFalse` uses `unless = "#result == null"`. Because the method returns `Optional<Entity>`, Spring Cache unwraps the Optional before evaluating `#result` — meaning `Optional.empty()` results in `#result == null` being `true`, so negative (not-found) results are never cached. An unauthenticated attacker can flood the endpoint with distinct non-existent alias byte arrays, forcing every request to execute a full DB query, and under sustained load can exhaust the HikariCP/pgbouncer connection pool.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 39–49.

```java
@Cacheable(
        cacheNames = CACHE_NAME_ALIAS,
        cacheManager = CACHE_MANAGER_ENTITY,
        key = "@spelHelper.hashCode(#alias)",
        unless = "#result == null")          // ← root cause
@Query(value = """
        select *
        from entity
        where (evm_address = ?1 or alias = ?1) and deleted is not true
        """, nativeQuery = true)
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

**Root cause:** Spring Cache's `CacheAspectSupport` unwraps `Optional<T>` before evaluating SpEL expressions. When the query returns no row, the method returns `Optional.empty()`, but `#result` in the `unless` expression is bound to the *unwrapped* value — which is `null`. Therefore `unless = "#result == null"` evaluates to `true` and the empty result is **never stored in the cache**. Every subsequent call with the same (or any other non-existent) alias bypasses the Caffeine cache entirely and issues a new SQL query.

The entity cache is configured as `expireAfterWrite=1s,maximumSize=10000` — even if a positive result were cached, it expires in 1 second, so the attack window is always open.

**Exploit flow:**
1. Attacker sends `eth_call` / `eth_estimateGas` requests that resolve an address via alias lookup (e.g., by targeting a contract address that triggers `CommonEntityAccessor.get()` → `findByEvmAddressOrAliasAndDeletedIsFalse`).
2. Each request uses a distinct, non-existent 20-byte or 32-byte alias value.
3. The Caffeine cache is never populated for these misses.
4. Each request executes the native SQL `SELECT * FROM entity WHERE (evm_address = ? OR alias = ?) AND deleted IS NOT TRUE` against PostgreSQL.
5. The OR predicate may not use a single composite index efficiently, increasing per-query cost.
6. With the global rate limit at 500 RPS and a `statementTimeout` of 3000 ms, up to `500 × 3 = 1500` concurrent DB connections can be in-flight simultaneously.
7. The pgbouncer `max_user_connections` for `mirror_web3` is **275**. Once the pool is saturated, new requests queue or fail with connection-acquisition timeouts, degrading or halting the web3 service.

### Impact Explanation
The web3 service's DB connection pool (`mirror_web3`, capped at 275 pgbouncer connections) can be exhausted, causing all contract-call and gas-estimation requests to fail with connection-pool timeout errors. This degrades or takes down the web3 API entirely. Because the rate limiter is global (not per-IP) and in-memory (per-instance, not distributed), a single attacker consuming 500 RPS starves all legitimate users simultaneously. Multiple web3 replicas each have their own 500 RPS budget, multiplying the DB pressure linearly with replica count.

### Likelihood Explanation
No authentication or special privilege is required — any caller of the public JSON-RPC endpoint can trigger alias lookups. The attacker only needs to craft `eth_call` requests targeting addresses that do not exist in the entity table. Generating distinct random 20-byte EVM addresses is trivial. The attack is fully repeatable and automatable with standard HTTP tooling (e.g., `wrk`, `hey`, or a simple script). The only friction is the 500 RPS global rate limit, which the attacker can saturate alone.

### Recommendation
1. **Cache negative results explicitly:** Change `unless = "#result == null"` to `unless = "#result != null && !#result.isPresent()"` — but note this still won't cache `Optional.empty()` because Spring unwraps it. Instead, use a sentinel/wrapper pattern or switch to a non-Optional return type with a null-safe `unless` expression, or use `@Cacheable` with `sync = true` and a custom `CacheResolver` that stores empty markers.
   - Simplest fix: use `unless = "false"` to always cache (including empty results), relying on the 1-second TTL for freshness, or use `unless = "#result != null && #result.isEmpty()"` — but verify Spring's SpEL evaluation order for Optional.
2. **Add per-IP rate limiting** upstream (API gateway / ingress) to prevent a single source from consuming the entire global budget.
3. **Add a negative-result TTL cache** at the service layer (e.g., in `CommonEntityAccessor`) that explicitly caches `Optional.empty()` results for a short duration (e.g., 1–5 seconds) keyed by the alias hash.
4. **Index the OR query:** Ensure separate indexes on `entity.evm_address` and `entity.alias` so the OR predicate uses index scans rather than sequential scans, reducing per-query cost.

### Proof of Concept
```python
import requests, os, threading

URL = "http://<web3-host>/api/v1/contracts/call"

def flood():
    while True:
        # Random non-existent EVM address
        addr = "0x" + os.urandom(20).hex()
        payload = {
            "to": addr,
            "data": "0x",
            "estimate": False,
            "block": "latest"
        }
        requests.post(URL, json=payload, timeout=5)

# Launch 50 threads to sustain ~500 RPS
threads = [threading.Thread(target=flood) for _ in range(50)]
for t in threads:
    t.start()
# Observe: DB connection pool exhaustion, web3 API returns 503/timeout
```

Each request resolves `to` through `CommonEntityAccessor` → `findByEvmAddressOrAliasAndDeletedIsFalse`, misses the cache (empty Optional not cached), and issues a live DB query. Sustained at the rate limit, the pgbouncer pool for `mirror_web3` saturates and legitimate requests fail.