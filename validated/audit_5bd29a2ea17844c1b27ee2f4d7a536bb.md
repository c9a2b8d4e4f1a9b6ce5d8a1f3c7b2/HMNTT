All technical claims are verified against the actual code. Here is my assessment:

**Claim 1 — Missing `@Cacheable` on historical method:** Confirmed. `findByEvmAddressOrAliasAndDeletedIsFalse()` has `@Cacheable` at lines 39–49; `findActiveByEvmAddressOrAliasAndTimestamp()` at lines 95–121 has none. [1](#0-0) [2](#0-1) 

**Claim 2 — Gas bypass:** `scaleGas()` returns `0L` for any `gas <= 10_000`, confirmed at lines 42–47. [3](#0-2) 

**Claim 3 — Global rate limiter:** `ThrottleConfiguration` creates a single shared `rateLimitBucket` with no per-IP partitioning, confirmed at lines 24–32. [4](#0-3) 

**Claim 4 — Code path:** `ContractController.call()` → `throttleManager.throttle()` → `contractExecutionService.processCall()` confirmed at lines 40–44. `CommonEntityAccessor.get(Bytes, Optional<Long>)` routes to `findActiveByEvmAddressOrAliasAndTimestamp()` when timestamp is present, confirmed at lines 46–49. [5](#0-4) [6](#0-5) 

---

Audit Report

## Title
Uncached Historical Entity Query Enables Global Rate-Limit Monopolization Leading to DB Exhaustion DoS

## Summary
The historical entity lookup method `findActiveByEvmAddressOrAliasAndTimestamp()` in `EntityRepository.java` carries no `@Cacheable` annotation, unlike its non-historical counterpart. Combined with a single global (non-per-IP) token-bucket rate limiter and a gas-throttle bypass for requests with `gas ≤ 10,000`, an unauthenticated attacker can monopolize the entire 500 req/s global budget, driving 500 uncached CTE+UNION ALL queries per second against the database and denying service to all legitimate users.

## Finding Description

**Code path:**
`ContractController.call()` → `throttleManager.throttle(request)` → `contractExecutionService.processCall(params)` → `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` → `entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t)`

**Root cause 1 — No caching on the historical method:**

`findByEvmAddressOrAliasAndDeletedIsFalse()` is annotated with `@Cacheable(cacheNames = CACHE_NAME_ALIAS, cacheManager = CACHE_MANAGER_ENTITY, ...)`: [1](#0-0) 

`findActiveByEvmAddressOrAliasAndTimestamp()` has no such annotation — every call unconditionally hits the database: [2](#0-1) 

The routing in `CommonEntityAccessor.get(Bytes, Optional<Long>)` makes the distinction explicit — timestamp present → uncached historical path: [7](#0-6) 

**Root cause 2 — Gas throttle bypass:**

`ThrottleProperties.scaleGas()` returns `0L` for any `gas ≤ 10_000` (the `GAS_SCALE_FACTOR`): [3](#0-2) 

`gasLimitBucket.tryConsume(0)` always succeeds in bucket4j, so the gas-per-second bucket provides zero protection for low-gas requests.

**Root cause 3 — Global (not per-IP) rate limiter:**

`ThrottleConfiguration` creates a single shared `rateLimitBucket` with capacity `requestsPerSecond` (default: 500). There is no per-IP or per-client partitioning: [4](#0-3) 

A single attacker can consume the entire 500 req/s budget, causing all subsequent requests from legitimate users to receive HTTP 429 while each attacker request triggers a full uncached DB query.

**The query itself is expensive:**

The CTE is resolved twice (once per UNION ALL branch), scanning both `entity` and `entity_history` tables with range predicates on `created_timestamp` and `timestamp_range`: [2](#0-1) 

## Impact Explanation

- **DB resource exhaustion:** 500 complex uncached CTE queries/second against `entity` and `entity_history` saturates the DB connection pool and I/O, degrading or halting all other DB-dependent operations in the mirror node.
- **Service denial for legitimate users:** The global rate bucket is fully consumed by the attacker; all subsequent `eth_call` requests receive HTTP 429.
- **Historical audit unavailability:** Historical queries — the mechanism for auditing past Hashgraph state — become unavailable, directly undermining the mirror node's core purpose.

## Likelihood Explanation

- **No authentication required:** Any unauthenticated HTTP client can POST to `/api/v1/contracts/call` with a historical `block` parameter.
- **Trivially automatable:** A single machine with a persistent HTTP/2 connection can sustain 500 req/s against the global bucket.
- **Gas throttle bypass is reliable:** Setting `gas` to any value `≤ 10,000` in the request body is sufficient to avoid gas-bucket consumption entirely.
- **Varying alias + timestamp defeats result-level deduplication:** Each request with a distinct `alias` byte array or `blockTimestamp` is a unique cache miss even if caching were added naively.

## Recommendation

1. **Add per-IP rate limiting** in addition to the global bucket, so a single client cannot monopolize the global budget.
2. **Add `@Cacheable` to historical query methods** where the `(alias, blockTimestamp)` pair is stable, using a bounded TTL cache keyed on `(alias, blockTimestamp)`.
3. **Enforce a minimum gas floor** in `scaleGas()` so that `gas = 0` or very low gas values still consume at least 1 token from the gas bucket, preventing the bypass.
4. **Consider query result caching at the service layer** in `CommonEntityAccessor` for repeated `(alias, timestamp)` lookups within a short window.

## Proof of Concept

```http
POST /api/v1/contracts/call HTTP/1.1
Host: <mirror-node>
Content-Type: application/json

{
  "to": "0x<any_valid_or_invalid_address>",
  "gas": 9999,
  "block": "0x<historical_block_number>",
  "data": "0x"
}
```

Send this request at 500 req/s (e.g., using `wrk`, `hey`, or a simple async HTTP/2 client). Each request:
1. Passes `throttleManager.throttle()` — consumes 1 token from the global 500 req/s bucket.
2. Passes the gas bucket check — `scaleGas(9999)` returns `0`, `tryConsume(0)` always succeeds.
3. Reaches `CommonEntityAccessor.get(Bytes, Optional<Long>)` with a non-empty timestamp.
4. Executes `findActiveByEvmAddressOrAliasAndTimestamp()` — a full uncached CTE+UNION ALL query against the DB.

The global bucket is exhausted; all legitimate requests receive HTTP 429 while the DB sustains 500 complex queries/second.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L39-49)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_ALIAS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    @Query(value = """
            select *
            from entity
            where (evm_address = ?1 or alias = ?1) and deleted is not true
            """, nativeQuery = true)
    Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L95-121)
```java
    @Query(value = """
            with entity_cte as (
                select id
                from entity
                where created_timestamp <= ?2 and (evm_address = ?1 or alias = ?1)
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
    Optional<Entity> findActiveByEvmAddressOrAliasAndTimestamp(byte[] alias, long blockTimestamp);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L40-44)
```java
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
