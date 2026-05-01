### Title
Thread Pool Exhaustion via Unbounded Concurrent DSLContext Calls in `NftAllowanceRepositoryCustomImpl.findAll` During Database Slowdown

### Summary
The `findAll` method in `NftAllowanceRepositoryCustomImpl` issues a synchronous, blocking jOOQ `DSLContext` query with no application-level concurrency limit, no circuit breaker at the code level, and no per-IP in-flight request cap at the ingress level. During a transient database slowdown, an unprivileged attacker can flood the `/api/v1/accounts/{id}/allowances/nfts` endpoint, causing all available threads and HikariCP connections to pile up waiting for slow DB responses, amplifying the partition duration well beyond design parameters. The Traefik-level circuit breaker is insufficient because it only triggers on error ratios, not on latency, and the configured retry middleware actively triples the DB load per request.

### Finding Description

**Exact code path:**

`NftAllowanceRepositoryCustomImpl.findAll` (lines 37–47):
```java
public Collection<NftAllowance> findAll(NftAllowanceRequest request, EntityId accountId) {
    boolean byOwner = request.isOwner();
    var bounds = request.getBounds();
    var condition = getBaseCondition(accountId, byOwner).and(getBoundConditions(bounds));
    return dslContext
            .selectFrom(NFT_ALLOWANCE)
            .where(condition)
            .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
            .limit(request.getLimit())
            .fetchInto(NftAllowance.class);   // ← blocking, no timeout override, no semaphore
}
```

This is a fully synchronous, blocking call. Each HTTP request occupies one JVM thread and one HikariCP connection for the entire duration of the DB query (up to `hiero.mirror.restJava.db.statementTimeout` = **10,000 ms** by default).

**Why existing checks fail:**

1. **Traefik circuit breaker** (`charts/hedera-mirror-rest-java/values.yaml` lines 151–152):
   ```yaml
   - circuitBreaker:
       expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
   ```
   This only opens on *error ratios*. A slow DB that returns results after 8–9 seconds produces HTTP 200 responses — the circuit breaker never opens. Compare with rosetta (`charts/hedera-mirror-rosetta/values.yaml` lines 150–163) which additionally has `inFlightReq: amount: 5` per source IP and `rateLimit: average: 10`. The rest-java chart has **neither**.

2. **Retry middleware** (`charts/hedera-mirror-rest-java/values.yaml` lines 153–155):
   ```yaml
   - retry:
       attempts: 3
       initialInterval: 100ms
   ```
   Each slow request is retried up to 3 times, tripling the DB connection hold time per original client request.

3. **No application-level rate limiting**: The web3 service has `ThrottleConfiguration` with bucket4j (`ThrottleManagerImpl`). The rest-java service has no equivalent. There is no `@RateLimiter`, no semaphore, no `inFlightReq` guard anywhere in the `AllowancesController` → `NftAllowanceServiceImpl` → `NftAllowanceRepositoryCustomImpl` call chain.

4. **HikariCP pool exhaustion**: `CommonConfiguration` wires HikariCP via `spring.datasource.hikari` properties with no explicit `maximumPoolSize` override documented for rest-java. Once the pool is saturated, new requests queue on the HikariCP `connectionAcquisitionTimeout`, holding their HTTP threads blocked — creating a second layer of pile-up beyond the DB timeout.

### Impact Explanation

During a transient DB slowdown (e.g., a replica lag spike, a lock contention event, or a network hiccup to the DB), an attacker sending N concurrent requests causes N threads to block for up to 10 seconds each. With no per-IP in-flight cap, a single attacker IP can exhaust the entire thread pool and HikariCP connection pool. The service becomes unresponsive to all clients (not just the attacker), and the DB continues to receive queries it cannot serve quickly, extending the slowdown window. This converts a transient 2–3 second DB hiccup into a sustained service outage lasting the full `statementTimeout` window (10 s) multiplied by retry attempts (×3 = 30 s effective hold per request).

### Likelihood Explanation

No authentication is required to call `/api/v1/accounts/{id}/allowances/nfts`. The endpoint is publicly documented and reachable. The attacker needs only a valid account ID (trivially enumerable from the public ledger) and the ability to send concurrent HTTP GET requests — achievable from a single machine with standard tooling (`ab`, `wrk`, `curl` in parallel). The attack is repeatable on demand and does not require any special knowledge of the system internals.

### Recommendation

1. **Add `inFlightReq` per-IP middleware** to `charts/hedera-mirror-rest-java/values.yaml`, matching the pattern already used in rosetta and graphql:
   ```yaml
   - inFlightReq:
       amount: 5
       sourceCriterion:
         ipStrategy:
           depth: 1
   ```
2. **Add application-level concurrency limiting** (e.g., a `Semaphore` or Resilience4j `Bulkhead`) around the `dslContext` call in `NftAllowanceRepositoryCustomImpl.findAll`, so that DB connection exhaustion does not cascade into full thread pool exhaustion.
3. **Remove or scope the retry middleware** so it does not apply to endpoints backed by synchronous DB queries, or ensure retries only fire on connection errors, not on slow responses.
4. **Set an explicit HikariCP `connectionTimeout`** (fail-fast on pool exhaustion rather than queuing indefinitely) for the rest-java datasource.

### Proof of Concept

**Preconditions:** DB is experiencing a slowdown (queries taking 3–8 s). No authentication needed.

**Steps:**
```bash
# 1. Pick any valid account ID from the public ledger (e.g., 0.0.1234)
ACCOUNT="0.0.1234"
BASE_URL="https://<mirror-node-host>"

# 2. Send 200 concurrent requests (single unprivileged attacker)
seq 200 | xargs -P200 -I{} curl -s \
  "$BASE_URL/api/v1/accounts/$ACCOUNT/allowances/nfts" -o /dev/null

# 3. Observe: all 200 requests hold threads for up to 10s each.
#    HikariCP pool saturates; subsequent legitimate requests time out.
#    Traefik circuit breaker does NOT open (no 5xx generated during slowdown).
#    Retry middleware fires up to 3x per request, tripling DB load.
```

**Result:** The rest-java service becomes unresponsive for the duration of the DB slowdown plus the full `statementTimeout` window, amplifying a transient partition into a sustained outage. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L37-47)
```java
    public Collection<NftAllowance> findAll(NftAllowanceRequest request, EntityId accountId) {
        boolean byOwner = request.isOwner();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, byOwner).and(getBoundConditions(bounds));
        return dslContext
                .selectFrom(NFT_ALLOWANCE)
                .where(condition)
                .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
                .limit(request.getLimit())
                .fetchInto(NftAllowance.class);
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L150-155)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** docs/configuration.md (L629-629)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```
