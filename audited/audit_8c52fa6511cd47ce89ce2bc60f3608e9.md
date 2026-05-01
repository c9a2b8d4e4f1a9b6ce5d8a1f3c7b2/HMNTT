Based on my investigation of the code, here is my analysis:

**Code reviewed:**
- `TokenAirdropServiceImpl.java` (lines 19-22): the `getAirdrops()` implementation
- `TokenAirdropsController.java`: the HTTP layer exposing the endpoints
- `ThrottleManagerImpl.java`, `ThrottleProperties.java`, `RequestProperties.java`: rate limiting — all in the `web3` module, not `rest-java`
- `MetricsFilter` in `rest-java`: metrics only, no rate limiting

---

### Title
Unauthenticated DB Exhaustion via Empty-Airdrop Account Flooding on `getAirdrops()`

### Summary
The `getAirdrops()` method in `TokenAirdropServiceImpl` unconditionally executes two database queries per request — an entity lookup and an airdrop table scan — with no application-level rate limiting in the `rest-java` module. An unprivileged attacker can flood the `/api/v1/accounts/{id}/airdrops/outstanding` or `/pending` endpoints with valid accountIds that have no airdrops, causing sustained unnecessary DB load that degrades performance for all users.

### Finding Description
**Code path:**

`TokenAirdropsController.getOutstandingAirdrops()` / `getPendingAirdrops()` → `processRequest()` → `service.getAirdrops(request)` → `TokenAirdropServiceImpl.getAirdrops()`:

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java, lines 19-22
public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
    var id = entityService.lookup(request.getAccountId());   // DB query 1: entity table
    return repository.findAll(request, id);                  // DB query 2: token_airdrop table
}
```

The controller at `TokenAirdropsController.java` (lines 66-86) exposes these as unauthenticated `GET` endpoints with no authentication annotation, no rate-limit guard, and no per-IP throttle. The only validation is input format (accountId format, limit range).

**Root cause:** The `rest-java` module has no rate limiting. All throttle infrastructure (`ThrottleManagerImpl`, `ThrottleProperties`, `RequestProperties`, `ThrottleConfiguration`) lives exclusively in the `web3` module and is not applied to `rest-java` endpoints. The `MetricsFilter` in `rest-java` only records metrics; it does not throttle.

**Exploit flow:**
1. Attacker enumerates or generates valid Hedera accountIds (e.g., `0.0.1`, `0.0.2`, ..., `0.0.N`) — all publicly known.
2. Attacker sends thousands of concurrent `GET /api/v1/accounts/0.0.X/airdrops/outstanding` requests where account `0.0.X` exists but has no airdrops.
3. For each request: `entityService.lookup()` succeeds (entity found), `repository.findAll()` executes a full parameterized query against `token_airdrop` and returns empty.
4. Each request costs 2 DB round-trips. At thousands of RPS, this saturates DB connection pool and query throughput.
5. Legitimate users experience increased latency or timeouts on all `rest-java` endpoints sharing the same DB.

**Why existing checks fail:** Input validation (accountId format, limit bounds) only rejects malformed inputs — it does not prevent valid requests from being issued at high volume. There is no per-IP, per-account, or global RPS cap in `rest-java`.

### Impact Explanation
Sustained DB load increase degrades response times for all `rest-java` endpoints (airdrops, network, tokens, etc.) that share the same database connection pool. At sufficient request volume, the DB connection pool exhausts, causing cascading 500 errors or timeouts for all users. This is a service availability impact with no authentication barrier.

### Likelihood Explanation
Preconditions are minimal: any internet user, no credentials, no privileged access. Valid accountIds are publicly enumerable from the Hedera ledger or simply iterated numerically. The attack is repeatable, automatable with standard HTTP tooling (curl, wrk, ab), and requires no special knowledge beyond the public API documentation.

### Recommendation
1. Add a global RPS rate limiter to the `rest-java` module (analogous to `ThrottleManagerImpl` in `web3`) applied as a servlet filter or Spring interceptor before controller dispatch.
2. Add per-IP rate limiting (e.g., via a `HandlerInterceptor` using bucket4j keyed on `X-Forwarded-For` / remote IP).
3. Consider caching `entityService.lookup()` results for recently queried accountIds to reduce DB round-trips on repeated lookups.
4. Apply the existing `hiero.mirror.restjava` configuration to expose a `requestsPerSecond` throttle property mirroring the `web3` module pattern.

### Proof of Concept
```bash
# Step 1: Identify valid accountIds with no airdrops (e.g., system accounts 0.0.1 - 0.0.100)
# Step 2: Flood the endpoint
seq 1 100 | xargs -P 50 -I{} \
  bash -c 'while true; do
    curl -s "https://<mirror-node>/api/v1/accounts/0.0.{}/airdrops/outstanding" -o /dev/null
  done'
# Expected: Each request returns HTTP 200 with empty airdrops list.
# DB query count scales linearly with request rate.
# At ~1000 RPS sustained, DB connection pool saturates and latency spikes for all users.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L66-86)
```java
    @GetMapping(value = "/outstanding")
    TokenAirdropsResponse getOutstandingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, receiverIds, limit, order, serialNumbers, tokenIds, OUTSTANDING);
    }

    @GetMapping(value = "/pending")
    TokenAirdropsResponse getPendingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = SENDER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] senderIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, senderIds, limit, order, serialNumbers, tokenIds, PENDING);
    }
```
