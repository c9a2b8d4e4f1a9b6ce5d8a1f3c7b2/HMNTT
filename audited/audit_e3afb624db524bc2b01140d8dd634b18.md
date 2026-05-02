### Title
Unauthenticated 100-Element IN-Clause DB Query via Unrestricted `key=` Parameter Repetition in `getHookStorage()`

### Summary
An unprivileged external user can send a `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` request with up to 100 distinct `key=` parameters (the maximum allowed by `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)`). The controller builds a 100-element `keyFilters` list and passes it directly to `hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()`, generating a 100-element SQL `IN`-clause DB query. With no authentication requirement and no rate limiting visible on this endpoint, an attacker can repeat this at high frequency or concurrently, driving sustained DB CPU and I/O load well above the 30% threshold.

### Finding Description

**Code path:**

1. `HooksController.getHookStorage()` — `rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java`, lines 104–130:
   - Accepts `List<SlotRangeParameter> keys` annotated only with `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` (= 100). No authentication annotation (`@PreAuthorize`, `@Secured`, etc.) is present.

2. `hookStorageChangeRequest()` — same file, lines 158–198:
   - Iterates over `keys`; for each key where `key.operator() == RangeOperator.EQ`, it calls `keyFilters.add(value)` (line 175). Sending 100 `key=<hex>` parameters (each parsed as EQ) produces a 100-element `keyFilters` list.

3. `HookServiceImpl.getHookStorage()` — `rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java`, lines 56–82:
   - When `keys` is non-empty, calls `request.getKeysInRange()` (line 72).

4. `HookStorageRequest.getKeysInRange()` — `rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java`, lines 43–52:
   - Filters keys between `keyLowerBound` (all-zero 32 bytes) and `keyUpperBound` (all-0xFF 32 bytes). All 100 distinct valid 32-byte hex keys pass this filter unchanged.

5. `HookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` — `rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java`, line 13–14:
   - Spring Data JPA translates the 100-element list into `WHERE key IN (?, ?, ..., ?)` — a 100-parameter IN-clause query executed against the DB.

**Root cause:** The `@Size(max = 100)` annotation is the only guard, and it permits exactly 100 keys — the maximum the attacker wants. There is no deduplication, no per-IP or per-user rate limiting, and no authentication on this endpoint.

### Impact Explanation
Each crafted request forces the DB to evaluate a 100-element IN-clause scan. Without rate limiting or authentication, an attacker can issue these requests at high frequency (e.g., hundreds per second from a single client, or thousands per second from distributed sources). The cumulative effect is sustained elevated DB CPU (index lookups for 100 keys per query) and I/O (buffer pool pressure), readily exceeding a 30% resource increase over baseline. This degrades service for all legitimate users and can cause query timeouts or connection pool exhaustion.

### Likelihood Explanation
The attack requires zero privileges — any internet-accessible client can craft the request. The exploit is trivially scriptable (a simple loop or `ab`/`wrk` invocation with 100 `key=` parameters). It is repeatable indefinitely with no lockout mechanism. The attacker does not need to know valid `ownerId` or `hookId` values; any syntactically valid values trigger the DB query path.

### Recommendation
1. **Add a hard cap on the IN-clause size** separate from `@Size`: reject or truncate requests where the number of EQ `key=` parameters exceeds a safe threshold (e.g., 10–20).
2. **Deduplicate keys** before building `keyFilters` to prevent trivial amplification via repeated identical values.
3. **Apply rate limiting** (e.g., via a servlet filter or API gateway) on this endpoint, keyed by IP or authenticated identity.
4. **Require authentication** for this endpoint if the data is not intended to be fully public.
5. Consider replacing the unbounded IN-clause path with a range query when the number of keys is large.

### Proof of Concept
```bash
# Generate 100 distinct 32-byte hex keys and send as repeated key= params
KEYS=$(python3 -c "
for i in range(100):
    print(f'key={i:064x}', end='&')
")

# Single high-cost request
curl -s "http://<mirror-node-host>/api/v1/accounts/0.0.1000/hooks/1/storage?${KEYS}limit=100"

# Sustained attack (no auth required, no rate limit)
for i in $(seq 1 500); do
  curl -s "http://<mirror-node-host>/api/v1/accounts/0.0.1000/hooks/1/storage?${KEYS}limit=100" &
done
wait
```
Each request triggers `findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse()` with a 100-element IN-clause. Running 500 concurrent requests produces sustained DB load measurably exceeding 30% above baseline.