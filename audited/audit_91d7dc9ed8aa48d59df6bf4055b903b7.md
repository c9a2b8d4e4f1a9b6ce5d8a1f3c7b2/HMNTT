### Title
Uncached Historical Entity Query Enables Global Rate-Limit Monopolization Leading to DB Exhaustion DoS

### Summary
`findActiveByEvmAddressOrAliasAndTimestamp()` carries no `@Cacheable` annotation, unlike its non-historical counterpart, meaning every invocation unconditionally executes a multi-table CTE + UNION ALL query against the database. The only protection is a single global (not per-IP) token-bucket rate limiter capped at 500 req/s by default. An unprivileged attacker can monopolize the entire global budget with low-gas historical requests, sustaining 500 uncached complex DB queries per second and denying service to all legitimate users.

### Finding Description

**Exact code path:**

`ContractController.call()` → `throttleManager.throttle(request)` → `ContractExecutionService.processCall()` → `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` → `entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t)`

**Root cause — no caching on the historical method:**

`findByEvmAddressOrAliasAndDeletedIsFalse()` (non-historical) is annotated with `@Cacheable(cacheNames = CACHE_NAME_ALIAS, cacheManager = CACHE_MANAGER_ENTITY, ...)` at lines 39–49 of `EntityRepository.java`. The historical variant `findActiveByEvmAddressOrAliasAndTimestamp()` at lines 95–121 has **no such annotation** — every call hits the database unconditionally.

**The query itself is expensive:**

```sql
with entity_cte as (
    select id from entity
    where created_timestamp <= ?2 and (evm_address = ?1 or alias = ?1)
    order by created_timestamp desc limit 1
)
(select * from entity e where e.deleted is not true and e.id = (select id from entity_cte))
union all
(select * from entity_history eh where lower(eh.timestamp_range) <= ?2
 and eh.id = (select id from entity_cte)
 order by lower(eh.timestamp_range) desc limit 1)
order by timestamp_range desc limit 1
```

This is a CTE resolved twice (once per UNION branch), scanning both `entity` and `entity_history` tables with range predicates on `created_timestamp` and `timestamp_range`.

**Gas throttle bypass for low-gas requests:**

`ThrottleProperties.scaleGas()` returns `0L` when `gas <= 10_000` (GAS_SCALE_FACTOR). `gasLimitBucket.tryConsume(0)` always succeeds. An attacker sending requests with `gas ≤ 10,000` bypasses the gas-per-second bucket entirely, leaving only the 500 req/s rate limit as a guard.

**Global (not per-IP) rate limiter:**

`ThrottleConfiguration` creates a single shared `rateLimitBucket` with capacity `requestsPerSecond` (default: 500). There is no per-IP or per-client partitioning. A single attacker can consume the entire 500 req/s budget, causing all subsequent requests from legitimate users to receive HTTP 429 while the attacker's requests each trigger a full uncached DB query.

### Impact Explanation

- **DB resource exhaustion:** 500 complex uncached CTE queries/second against `entity` and `entity_history` tables saturates DB connection pool and I/O, degrading or halting all other DB-dependent operations in the mirror node.
- **Service denial for legitimate users:** The global rate bucket is fully consumed by the attacker; legitimate `eth_call` requests with historical block parameters receive 429 responses.
- **Hashgraph history integrity impact:** Historical queries — the specific mechanism for auditing past Hashgraph state — become unavailable, directly undermining the stated critical scope of accurate Hashgraph history queries.

### Likelihood Explanation

- **No authentication required:** Any unauthenticated HTTP client can POST to `/api/v1/contracts/call` with a historical `block` parameter.
- **Trivially automatable:** A single machine with a persistent HTTP/2 connection can sustain 500 req/s against the global bucket.
- **Gas throttle bypass is reliable:** Setting `gas` to any value ≤ 10,000 in the request body is sufficient to avoid gas-bucket consumption, making the attack cheaper to sustain.
- **Varying alias + timestamp defeats any future result-level deduplication:** Each request with a distinct `alias` byte array or `blockTimestamp` is a unique cache miss even if caching were added naively.

### Recommendation

1. **Add per-IP (or per-client) rate limiting** in addition to the global bucket, so a single attacker cannot monopolize the full global budget.
2. **Cache historical entity lookups** with a short TTL keyed on `(alias, blockTimestamp)` — historical data is immutable by definition, making it safe to cache aggressively.
3. **Fix the gas throttle bypass:** `scaleGas` returning `0` for `gas ≤ 10,000` means low-gas requests consume no gas tokens. Apply a minimum token cost of 1 for any request that reaches the DB.
4. **Add a DB query timeout** on `findActiveByEvmAddressOrAliasAndTimestamp()` to bound the per-query resource cost.

### Proof of Concept

```bash
# Attacker sends 500 req/s with historical block param and gas <= 10_000
# Each request: unique alias bytes + varying blockTimestamp → guaranteed cache miss → full DB CTE query

for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{
      \"to\": \"0x$(openssl rand -hex 20)\",
      \"from\": \"0x0000000000000000000000000000000000000001\",
      \"gas\": 9999,
      \"block\": \"0x$(printf '%x' $((1700000000 + $i)))\",
      \"data\": \"0x\"
    }" &
done
wait
# Result: global rateLimitBucket exhausted; DB sustains 500 uncached CTE queries/sec;
# legitimate users receive HTTP 429; entity_history table under sustained scan load.
```