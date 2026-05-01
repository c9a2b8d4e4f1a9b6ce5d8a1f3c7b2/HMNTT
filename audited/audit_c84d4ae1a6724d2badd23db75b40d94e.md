### Title
Unauthenticated Repeated Calls to `/api/v1/network/supply` Trigger Uncached Expensive DB Aggregation on Every Request

### Summary
The `GET /api/v1/network/supply` endpoint is publicly accessible with no authentication, no rate limiting, and no caching. When called without a timestamp parameter, `NetworkServiceImpl.getSupply()` unconditionally invokes `entityRepository.getSupply()`, which executes a full SQL aggregation (`SUM`/`MAX` with multi-range `unnest` join) against the `entity` table on every single request. An unprivileged attacker can flood this endpoint to saturate the database connection pool and degrade API performance for all users.

### Finding Description
**Code path:**

- `rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 132–137: `@GetMapping("/supply")` — no authentication, no throttle guard, publicly reachable.
- `rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java`, lines 66–67: when `timestamp.isEmpty()` (the default when no `?timestamp=` param is supplied), calls `entityRepository.getSupply(lowerBounds, upperBounds)` directly with no caching layer.
- `rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java`, lines 19–29: `getSupply()` is a native SQL query — `SELECT SUM(balance), MAX(balance_timestamp) FROM entity JOIN unnest(...)` — with **no `@Cacheable` annotation**.

**Root cause:** The `EntityRepository.getSupply()` method carries no Spring `@Cacheable` annotation (unlike, e.g., `grpc/EntityRepository.findById` which is annotated with `@Cacheable`). The service method `NetworkServiceImpl.getSupply()` also has no result-caching or memoization. The only filter registered in the rest-java module is `ShallowEtagHeaderFilter` (line 42–45 of `RestJavaConfiguration.java`), which computes ETags *after* the response body is generated — meaning the DB query still executes on every request unless the client cooperates by sending `If-None-Match`. An attacker simply omits that header.

The throttling infrastructure (`ThrottleManager`, `bucket4j` rate-limit buckets) exists exclusively in the `web3` module for contract calls. The `rest-java` module has no equivalent rate-limiting mechanism for any of its endpoints.

**Exploit flow:**
1. Attacker sends a flood of `GET /api/v1/network/supply` requests (no `?timestamp` param, no `If-None-Match` header).
2. Each request reaches `NetworkServiceImpl.getSupply(Bound.EMPTY)`.
3. `timestamp.isEmpty()` is `true`, so `entityRepository.getSupply(lowerBounds, upperBounds)` is called.
4. The native SQL aggregation runs against the `entity` table with up to 7 account ranges (default config), performing `SUM(balance)` and `MAX(balance_timestamp)` on every call.
5. Concurrent requests exhaust DB connection pool threads; query latency spikes for all API consumers.

### Impact Explanation
Every concurrent unauthenticated request causes a full aggregation scan on the `entity` table. Under sustained flood, the database connection pool becomes saturated, increasing query latency across all endpoints that share the same pool. This degrades service quality for all legitimate users of the mirror node REST API. No economic damage occurs to network participants, but availability and responsiveness of the public API are materially impaired — consistent with the "Medium griefing" classification.

### Likelihood Explanation
No privileges, credentials, or special knowledge are required. The endpoint is publicly documented and reachable. A single attacker with a basic HTTP flood script (e.g., `ab`, `wrk`, or a simple loop) can trigger this. The attack is trivially repeatable and requires no state. The absence of any rate limiting in the rest-java module means there is no application-layer barrier.

### Recommendation
Apply one or more of the following mitigations:

1. **Add `@Cacheable` to `EntityRepository.getSupply()`** with a short TTL (e.g., 15–30 seconds). Since the result changes only when entity balances are updated, a short cache is safe and eliminates redundant DB hits for the common no-timestamp case.
2. **Add application-level rate limiting** to the rest-java module (analogous to the `bucket4j`-based `ThrottleManager` in the `web3` module), applied globally or specifically to the `/api/v1/network/supply` endpoint.
3. **Cache at the service layer** in `NetworkServiceImpl.getSupply()` using a `@Cacheable` annotation on the method itself for the `timestamp.isEmpty()` branch.

### Proof of Concept
```bash
# Flood the endpoint with no timestamp (triggers entityRepository.getSupply() on every request)
while true; do
  curl -s "https://<mirror-node-host>/api/v1/network/supply" -o /dev/null &
done
# Or with a tool:
wrk -t 10 -c 100 -d 60s "https://<mirror-node-host>/api/v1/network/supply"
```
Each request executes the uncached SQL aggregation. Monitor DB connection pool utilization and query latency to observe degradation.