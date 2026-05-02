### Title
Uncached Historical Entity Lookup Enables DB Griefing via Global Rate Limit Monopolization

### Summary
`findActiveByIdAndTimestamp()` in `EntityRepository.java` carries no `@Cacheable` annotation, unlike every other lookup method in the same interface. An unprivileged attacker can issue historical contract calls with a non-existent entity ID and a different block number on each request, forcing a UNION ALL query against both `entity` and `entity_history` tables on every single call with no cache absorption. Because the rate limiter is a single global bucket (not per-IP), a single attacker can consume the entire 500 RPS budget, starving legitimate users while continuously hammering the database.

### Finding Description

**Exact code path:**

`ContractController.call()` → `ThrottleManager.throttle()` → `contractExecutionService.processCall()` → `CommonEntityAccessor.get()` → `EntityRepository.findActiveByIdAndTimestamp(long id, long blockTimestamp)`

**No caching on the historical path:**

Every other lookup in `EntityRepository` is annotated with `@Cacheable` or `@Caching`:
- `findByIdAndDeletedIsFalse()` — `@Caching` with two `@Cacheable` entries (lines 20-30)
- `findByEvmAddressAndDeletedIsFalse()` — `@Cacheable` (lines 32-37)
- `findByEvmAddressOrAliasAndDeletedIsFalse()` — `@Cacheable` (lines 39-49)

`findActiveByIdAndTimestamp()` (lines 136-155) has **no caching annotation at all**. Every invocation, regardless of parameters or result, executes the following query directly against the database:

```sql
(select * from entity
 where id = ?1 and lower(timestamp_range) <= ?2 and deleted is not true)
union all
(select * from entity_history
 where id = ?1 and lower(timestamp_range) <= ?2 and deleted is not true
 order by lower(timestamp_range) desc limit 1)
order by timestamp_range desc limit 1
```

When `id` does not exist, both subqueries perform index scans that return zero rows — but the scans still execute and consume DB I/O and CPU.

**Why the throttle is insufficient:**

`ThrottleManagerImpl.throttle()` (lines 37-48) checks a single global `rateLimitBucket` (default 500 RPS) and a single global `gasLimitBucket`. Neither bucket is keyed per IP or per caller. A single attacker can legally consume all 500 tokens/second. The minimum gas per request is 21,000 (`@Min(21_000)` in `ContractCallRequest`, line 36), which `scaleGas(21000)` maps to 2 tokens — meaning the gas bucket (capacity 750,000 scaled tokens) is not the binding constraint; the 500 RPS bucket is.

**Varying `blockTimestamp` defeats any future caching:**

Even if a `@Cacheable` annotation were added with `unless = "#result == null"` (the pattern used elsewhere), an attacker supplying a different historical block number on each request would produce a unique cache key `(id, blockTimestamp)` every time, so the cache would never be hit.

### Impact Explanation

An attacker running at the 500 RPS global ceiling forces 500 UNION ALL queries per second against `entity` and `entity_history`. Legitimate users receive HTTP 429 for the duration of the attack. The database sustains sustained index-scan load proportional to the table sizes. No authentication, funds, or special privileges are required. The impact is service degradation (griefing) with no direct economic loss to network participants, consistent with the Medium classification.

### Likelihood Explanation

Any anonymous user with a standard HTTP client can execute this. The attack requires only:
1. Knowledge of the `/api/v1/contracts/call` endpoint (publicly documented in `openapi.yml`)
2. A historical block number (any past block number works)
3. Any 20-byte address that does not correspond to a real entity

No wallet, no tokens, no on-chain interaction. The attack is trivially scriptable and repeatable indefinitely.

### Recommendation

1. **Add `@Cacheable` with a composite key** to `findActiveByIdAndTimestamp()`, caching both hits and misses (use a sentinel for null results, or accept that null-result caching requires a wrapper). Even a short TTL (e.g., 1 second, matching the entity cache) would absorb repeated identical `(id, timestamp)` pairs.

2. **Introduce per-IP rate limiting** in `ThrottleManagerImpl` or at the ingress layer (e.g., via a servlet filter or API gateway), so a single source cannot monopolize the global 500 RPS bucket.

3. **Validate that the target entity exists before executing the historical UNION query** — a cheap `SELECT 1 FROM entity WHERE id = ?1` with a cached result can short-circuit the full UNION for non-existent IDs.

### Proof of Concept

```bash
# Attacker script — no credentials required
BLOCK=1
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{
      \"to\":   \"0x000000000000000000000000000000000FFFFFFF\",
      \"data\": \"0x\",
      \"gas\":  21000,
      \"block\": \"$(printf '0x%x' $BLOCK)\"
    }" &
  BLOCK=$((BLOCK + 1))
done
```

- `to` address maps to a non-existent entity ID (e.g., `0x0FFFFFFF` = entity 268435455, which does not exist).
- Each iteration increments `block`, producing a unique `(id, blockTimestamp)` pair.
- Each request reaches `findActiveByIdAndTimestamp()` and executes the UNION ALL query with no cache hit.
- After ~500 concurrent requests/second the global rate bucket is exhausted; all subsequent legitimate requests receive HTTP 429.