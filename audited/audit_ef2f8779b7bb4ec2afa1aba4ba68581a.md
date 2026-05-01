### Title
Uncached Historical Entity Lookup Enables DB Amplification DoS via `findActiveByIdAndTimestamp()`

### Summary
`EntityRepository.findActiveByIdAndTimestamp()` carries no `@Cacheable` annotation, unlike every other entity-lookup method in the same interface. Any unprivileged caller who supplies a historical block number in a `/api/v1/contracts/call` request causes every entity resolution during EVM execution to issue a full `UNION ALL` query across the `entity` and `entity_history` tables with no cache absorption. Because the global throttle limits HTTP requests—not per-request DB query count—a single attacker operating within the rate limit can still drive a large, unbounded number of expensive DB queries per second.

### Finding Description

**Exact code location:**

`findActiveByIdAndTimestamp()` at `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java` lines 136–155 has only a `@Query` annotation. Every other entity-lookup method in the same file has `@Cacheable` or `@Caching`:

- `findByIdAndDeletedIsFalse()` — `@Caching` with two `@Cacheable` entries (lines 20–30)
- `findByEvmAddressAndDeletedIsFalse()` — `@Cacheable` (lines 32–37)
- `findByEvmAddressOrAliasAndDeletedIsFalse()` — `@Cacheable` (lines 39–49)

`findActiveByIdAndTimestamp()` is called from `CommonEntityAccessor` at three separate sites (lines 62, 76, 89 of `web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java`) with no intermediate caching layer. The entity cache manager (`CACHE_MANAGER_ENTITY`) is configured with `expireAfterWrite=1s,maximumSize=10000` (`CacheProperties.java` line 19) but is never applied to this method.

**Root cause:** The design assumption that historical queries are rare or low-volume is not enforced anywhere. The cache key for a historical lookup would be `(id, blockTimestamp)`, a two-dimensional space that is trivially varied by an attacker to defeat any future caching as well.

**Exploit flow:**
1. Attacker sends `POST /api/v1/contracts/call` with `"block": "<historical_block_number>"` targeting a contract that interacts with multiple accounts/tokens (e.g., a precompile that resolves sender, receiver, token entity, treasury account).
2. `ContractCallContext.useHistorical()` returns `true`; `getTimestamp()` returns a non-empty `Optional<Long>`.
3. `CommonEntityAccessor.get(EntityId, Optional<Long>)` branches to `entityRepository.findActiveByIdAndTimestamp(entityId.getId(), t)` — no cache check.
4. The DB executes the UNION ALL query across `entity` and `entity_history` for every entity resolved during EVM execution (sender, receiver, precompile contracts, token entities, treasury, fee collector, etc.).
5. The attacker repeats with a slightly different `blockTimestamp` (e.g., incrementing by 1 nanosecond) to ensure no result is ever reused.

**Why existing checks fail:**

`ThrottleManagerImpl.throttle()` (lines 37–48) uses two shared `Bucket` instances — `rateLimitBucket` (requests/second) and `gasLimitBucket` (gas/second). These are global singletons, not per-IP. They limit the number of HTTP requests, not the number of DB queries issued per request. A complex historical call touching 10–20 entities issues 10–20 uncached UNION ALL queries while consuming only 1 token from `rateLimitBucket`. The gas throttle is also irrelevant here because historical read-only calls consume gas for EVM opcodes, not for DB I/O.

### Impact Explanation
An attacker operating entirely within the published rate limit can drive a sustained, amplified load of expensive UNION ALL queries against the `entity` and `entity_history` tables. On a production node with millions of historical entity records, each query requires a range scan on `timestamp_range` with an `ORDER BY` and `LIMIT`. At even 50 req/s (well within a typical rate limit), a contract call touching 20 entities generates 1,000 uncached DB queries per second. This can saturate DB I/O, increase query latency for all other users, and ultimately cause the mirror node to become unresponsive — a complete availability loss for the web3 API.

### Likelihood Explanation
No authentication or special privilege is required. The `/api/v1/contracts/call` endpoint is publicly documented and accepts any historical block number. The attacker needs only a valid contract address and a past block number, both of which are publicly observable on-chain. The attack is fully repeatable, scriptable, and requires no on-chain transactions or funds. Any developer or researcher with basic knowledge of the Ethereum JSON-RPC API can reproduce it.

### Recommendation
1. **Add a request-scoped cache** for historical entity lookups within a single EVM execution context (e.g., a `Map<Pair<Long,Long>, Entity>` stored in `ContractCallContext`), so repeated lookups of the same `(id, timestamp)` within one call are served from memory.
2. **Add a bounded short-lived cross-request cache** for `findActiveByIdAndTimestamp()` keyed on `(id, blockTimestamp)` with a small TTL (e.g., 2–5 seconds) and a bounded maximum size, analogous to the existing `expireAfterWrite=1s,maximumSize=10000` entity cache.
3. **Apply per-IP rate limiting** in addition to the global bucket, so a single client cannot monopolize the global request budget.
4. **Limit the range of accepted historical block timestamps** (e.g., reject blocks older than N days) to reduce the attack surface of the `entity_history` table scan.

### Proof of Concept
```
# 1. Identify any deployed contract address and a valid historical block number
#    (both are publicly visible via the mirror node REST API)

# 2. Send high-frequency historical contract calls within the rate limit:
for i in $(seq 1 100); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{
      \"block\": \"0x$(printf '%x' $((HISTORICAL_BLOCK - i)))\",
      \"to\": \"<contract_address>\",
      \"data\": \"<calldata_touching_multiple_entities>\",
      \"gas\": 300000
    }" &
done
wait

# Each request triggers N uncached UNION ALL queries against entity + entity_history.
# Varying blockTimestamp by 1 per request ensures zero cache reuse even if caching is added later.
# Monitor DB query rate and latency to confirm amplification.
```