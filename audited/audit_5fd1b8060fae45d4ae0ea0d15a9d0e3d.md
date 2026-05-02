### Title
Unauthenticated DoS via Unbounded Concurrent IN-Clause Flooding on `/api/v1/accounts/{ownerId}/hooks`

### Summary
The `getHooks()` endpoint in `HooksController` accepts up to 100 `hook.id=eq:X` query parameters from any unauthenticated caller, each of which is accumulated into a `TreeSet` and forwarded as a 100-element SQL `IN` clause to the database. No rate limiting is applied to this endpoint (unlike `NetworkController`, which uses `HIGH_VOLUME_THROTTLE`). An attacker flooding this endpoint with concurrent maximum-payload requests can exhaust the DB connection pool and degrade query plan performance, causing mirror node API unavailability.

### Finding Description
**Code path:**

- `HooksController.java` `getHooks()` (lines 80–102): The `hookId` parameter is annotated `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` where `MAX_REPEATED_QUERY_PARAMETERS = 100` (`Constants.java` line 36). This is the only size guard — it caps the array at 100 entries but imposes no rate limit.
- `hooksRequest()` (lines 132–156): Every parameter with `RangeOperator.EQ` is unconditionally inserted into a `TreeSet<Long>` (line 140). With 100 unique EQ values, the set grows to 100 entries.
- `HookServiceImpl.getHooks()` (lines 39–52): When `hookIds` is non-empty, it streams the set, filters by range (which is `[0, MAX_VALUE]` by default, so all 100 pass), and calls `hookRepository.findByOwnerIdAndHookIdIn(id.getId(), idsInRange, page)` — issuing a `WHERE hook_id IN (0,1,2,...,99)` query to the database.

**Root cause:** The `@Size(max = 100)` annotation was intended as a sanity bound, but it simultaneously defines the maximum amplification factor per request. No rate-limiting filter, token bucket, or `HIGH_VOLUME_THROTTLE` guard (present in `NetworkController` but absent here) is applied to `HooksController`. No authentication is required (`SecurityConfig` has no `@PreAuthorize`/`@Secured` annotations anywhere in the `restjava` module).

**Why existing checks fail:** `@Size(max = 100)` prevents >100 parameters per request but does nothing to limit request rate or concurrency. The `HIGH_VOLUME_THROTTLE` constant defined in `Constants.java` (line 19) is wired only into `NetworkController` and fee estimation services — it is never referenced in `HooksController`.

### Impact Explanation
Each maximally-crafted request forces a 100-element `IN` clause DB query. PostgreSQL's query planner may switch from an index scan to a bitmap heap scan or sequential scan at this cardinality, increasing per-query cost. Under concurrent flood conditions, the application's DB connection pool is exhausted, causing all subsequent requests (including legitimate ones) to queue or fail. The mirror node REST API becomes unavailable. This does not halt Hedera consensus but does cause a full outage of the mirror node's read API, which downstream applications (wallets, explorers, dApps) depend on.

### Likelihood Explanation
No authentication is required. The attack requires only an HTTP client capable of sending GET requests with 100 query parameters — trivially scriptable with `curl`, `ab`, `wrk`, or any load tool. The attacker needs no account, token, or credential. The attack is repeatable and stateless. A single attacker with modest bandwidth can sustain it indefinitely.

### Recommendation
1. **Apply rate limiting to `HooksController`** using the existing `HIGH_VOLUME_THROTTLE` mechanism already present in `NetworkController`, or a Spring `HandlerInterceptor`/filter with per-IP token bucket semantics.
2. **Reduce `MAX_REPEATED_QUERY_PARAMETERS`** for EQ-operator parameters specifically, or add a separate cap (e.g., 10) for the number of EQ values that trigger the `IN`-clause path.
3. **Require authentication** for this endpoint if the data is not intended to be fully public.
4. **Add a DB query timeout** at the connection pool level to bound the blast radius of any single slow query.

### Proof of Concept
```bash
# Generate 100 unique eq parameters
PARAMS=$(python3 -c "print('&'.join([f'hook.id=eq:{i}' for i in range(100)]))")

# Flood with 200 concurrent connections, 10000 total requests
ab -n 10000 -c 200 \
  "http://<mirror-node-host>/api/v1/accounts/0.0.0.1000/hooks?${PARAMS}"

# Expected result: DB connection pool exhaustion, HTTP 503/timeout responses,
# mirror node API unavailable for legitimate users.
```

Each request causes `HookServiceImpl.getHooks()` to call `hookRepository.findByOwnerIdAndHookIdIn()` with a 100-element collection, issuing `SELECT ... WHERE owner_id = ? AND hook_id IN (0,1,...,99)` to the database on every hit.