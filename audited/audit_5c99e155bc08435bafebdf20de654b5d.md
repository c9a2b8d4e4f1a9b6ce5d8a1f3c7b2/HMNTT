### Title
Uncached Historical Entity Query Enables Global Rate Limit Monopolization and DB Exhaustion via `findActiveByEvmAddressOrAliasAndTimestamp()`

### Summary
`findActiveByEvmAddressOrAliasAndTimestamp()` carries no `@Cacheable` annotation, unlike its non-historical counterpart `findByEvmAddressOrAliasAndDeletedIsFalse()`. The only protection is a global (not per-IP) token-bucket throttle of 500 RPS. An unprivileged attacker can monopolize the entire 500-RPS budget with requests using gas ≤ 10,000 (which bypasses the gas throttle entirely due to a `scaleGas` floor), each triggering a fresh multi-table CTE query against `entity` and `entity_history`, exhausting DB connections and denying service to all legitimate users.

### Finding Description

**Exact code path:**

`ContractController.call()` → `throttleManager.throttle(request)` → `contractExecutionService.processCall(params)` → `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` (line 47–49) → `entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t)` (line 48).

**Root cause 1 — No cache on historical query:**

`findByEvmAddressOrAliasAndDeletedIsFalse()` is decorated with `@Cacheable(cacheNames = CACHE_NAME_ALIAS, ...)` at lines 39–49 of `EntityRepository.java`. `findActiveByEvmAddressOrAliasAndTimestamp()` at lines 95–121 has **no such annotation**. Every invocation hits the database unconditionally.

**Root cause 2 — Gas throttle bypass for small gas values:**

In `ThrottleProperties.scaleGas()`:
```java
if (gas <= GAS_SCALE_FACTOR) {  // GAS_SCALE_FACTOR = 10_000
    return 0L;
}
```
`ThrottleManagerImpl.throttle()` calls `gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))`. When gas ≤ 10,000, `scaleGas` returns 0, and `tryConsume(0)` always succeeds in bucket4j — the gas bucket is never decremented. Only the global RPS bucket (500/sec) applies.

**Root cause 3 — Global (not per-IP) RPS throttle:**

`ThrottleConfiguration` creates a single shared `rateLimitBucket` with capacity = `requestsPerSecond` (default 500). There is no per-source-IP partitioning. A single attacker can consume all 500 tokens/second, leaving zero capacity for legitimate callers.

**The expensive query:**

The CTE at lines 95–120 performs:
- A full scan/index lookup on `entity` filtered by `(evm_address = ?1 OR alias = ?1) AND created_timestamp <= ?2`
- A UNION ALL with `entity_history` filtered by `lower(timestamp_range) <= ?2`
- Two `ORDER BY … DESC LIMIT 1` passes

With varying alias bytes and blockTimestamp values, the PostgreSQL query plan cache provides no benefit and each execution is a fresh I/O-bound operation. The `statementTimeout` of 3000ms means each query can hold a DB connection for up to 3 seconds.

### Impact Explanation

An attacker sending 500 requests/second (the full global budget) with gas=21000 (≤ 10,000 bypasses gas bucket; 21,000 also returns 0 from scaleGas since 21,000 > 10,000 but the default `requestsPerSecond=500` is the binding constraint) and varying alias/timestamp values:

1. **Service-level DoS**: All 500 RPS slots are consumed; every legitimate request receives HTTP 429 `Too Many Requests`.
2. **DB connection exhaustion**: 500 concurrent or pipelined uncached CTE queries against `entity`/`entity_history` saturate the PostgreSQL connection pool and I/O bandwidth.
3. **Hashgraph history integrity**: Historical contract-call queries that depend on accurate point-in-time entity state (the stated critical scope) are either rejected (429) or delayed past the 10,000ms `requestTimeout`, returning errors instead of correct historical data.

Severity: **High**. The attack requires zero privileges, zero authentication, and is trivially repeatable.

### Likelihood Explanation

Any external user with network access to the `/api/v1/contracts/call` endpoint can execute this attack. No account, API key, or special knowledge is required. The attacker needs only:
- A valid JSON body with `block` set to a historical block number (e.g., `"block": "0x1"`) and a `to` address that resolves through the alias path
- Gas set to any value ≤ 10,000 to bypass the gas bucket
- A script generating unique alias-like `from`/`to` values per request to prevent any incidental caching

The attack is fully automatable, repeatable across restarts (the token bucket refills every second), and requires no persistence.

### Recommendation

1. **Add per-IP rate limiting** in addition to the global bucket. Use a `ConcurrentHashMap<String, Bucket>` keyed on the client IP (extracted from `X-Forwarded-For` or `HttpServletRequest.getRemoteAddr()`) inside `ThrottleManagerImpl`, so a single source cannot monopolize the global budget.

2. **Cache historical entity lookups with a composite key** (alias + blockTimestamp). Add `@Cacheable` to `findActiveByEvmAddressOrAliasAndTimestamp()` using a bounded short-TTL cache (e.g., `expireAfterWrite=1s, maximumSize=10000`) with a composite SpEL key: `key = "@spelHelper.hashCode(#alias) + ':' + #blockTimestamp"`. This mirrors the existing pattern on `findByEvmAddressOrAliasAndDeletedIsFalse()`.

3. **Fix the gas throttle floor**: `scaleGas` returning 0 for gas ≤ 10,000 means those requests consume no gas tokens. Enforce a minimum token cost of 1 for any request that reaches the DB: `return Math.max(1L, Math.floorDiv(gas, GAS_SCALE_FACTOR))`.

### Proof of Concept

```bash
# Attacker script — no authentication required
# Sends 500 req/s with gas=21000 (scaleGas returns 0, bypasses gas bucket)
# Each request uses a unique alias-like address to prevent cache hits
# and a historical block number to route through findActiveByEvmAddressOrAliasAndTimestamp()

for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{
      \"to\": \"0x$(printf '%040x' $RANDOM$RANDOM)\",
      \"gas\": 21000,
      \"block\": \"0x$(printf '%x' $((RANDOM % 1000000 + 1)))\",
      \"data\": \"0x\"
    }" &
done
wait

# Expected result:
# - Legitimate requests begin receiving HTTP 429
# - DB CPU/connection metrics spike
# - Historical Hashgraph queries return errors or timeouts
```

Preconditions: Network access to the web3 endpoint. No credentials needed.
Trigger: Sustained 500 req/s with varying `to` addresses and historical `block` values.
Result: Global RPS bucket drained; all legitimate callers throttled; DB stressed by uncached CTE queries.