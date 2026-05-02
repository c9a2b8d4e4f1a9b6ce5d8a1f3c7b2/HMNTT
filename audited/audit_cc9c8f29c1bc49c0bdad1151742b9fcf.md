### Title
Unauthenticated GraphQL `balance()` Endpoint Lacks Rate Limiting, Enabling Resource-Exhaustion Griefing

### Summary
The `balance()` field resolver in `AccountController` is publicly accessible with no per-client rate limiting. An unprivileged attacker can send a high-frequency stream of structurally valid `balance(unit: GIGABAR)` queries against any account, each of which triggers a real database lookup via `EntityRepository`, while the `convertCurrency()` integer division silently returns 0 — making every response semantically useless but computationally expensive. The existing query-structure guards (complexity, depth, parser limits) constrain the shape of individual queries but impose no frequency cap, leaving the service open to sustained resource exhaustion.

### Finding Description
**Code path:**

- `graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java`, lines 61–63: `@SchemaMapping Long balance(@Argument @Valid HbarUnit unit, Account account)` calls `convertCurrency(unit, account.getBalance())` with no authentication or rate-limiting guard.
- `graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java`, line 44: `case GIGABAR -> tinybars / 100_000_000_000_000_000L;` — integer division truncates any balance below 10^17 tinybars to 0.
- `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 24–26: every `account` query issues `entityRepository.findById(entityId.getId())` — a live database round-trip.
- `graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java`, lines 24–27: the cache stores the *parsed query document* keyed on the query string, not query results. Repeated identical queries still hit the database.

**Root cause:** `GraphQlConfiguration` (lines 42–48) installs only `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`. These constrain the *structure* of a single query but impose no limit on *how many times per second* a client may submit queries. The `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl` (bucket4j rate limiter) is entirely absent from the `graphql` module. There is no authentication requirement, no IP-based throttle, and no per-session request cap on the GraphQL endpoint.

**Failed assumption:** The design assumes that query complexity and depth limits are sufficient to prevent abuse. They are not: a minimal-complexity, minimal-depth query (`account { balance(unit: GIGABAR) }`) scores well within both limits while still causing a database lookup on every invocation.

### Impact Explanation
Each request causes at least one synchronous JDBC call (`findById`) against the mirror node's database. A sustained flood saturates the database connection pool, degrades or denies service to legitimate users, and consumes server-side CPU and memory. Because the result is always 0 for typical account balances with `GIGABAR`, the attacker gains no useful information — the sole purpose is resource consumption. Severity is Medium (griefing / availability degradation) with no on-chain economic impact, consistent with the stated scope.

### Likelihood Explanation
The attack requires zero privileges, zero credentials, and zero knowledge beyond the public GraphQL schema (which documents `GIGABAR` as a valid `HbarUnit`). It is trivially scriptable with any HTTP client in a loop. The query is short (well under the 10 000-character parser limit), low-complexity, and low-depth, so all structural guards pass. Repeatability is unlimited until the server is overwhelmed or an external network-layer control (e.g., a WAF or load-balancer rate limiter) intervenes — neither of which is present in the application code.

### Recommendation
1. **Add a request-rate limiter to the GraphQL module.** Port the bucket4j pattern from `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` into a `graphql`-module servlet filter or Spring `WebGraphQlInterceptor`, enforcing a per-IP (or global) requests-per-second cap before any resolver executes.
2. **Cache query *results*, not just parsed documents.** A short-lived result cache (e.g., 5–30 seconds) for `account` lookups would absorb repeated identical queries without hitting the database.
3. **Consider requiring authentication for write-amplifying queries**, or at minimum returning HTTP 429 with `Retry-After` when the rate limit is exceeded.

### Proof of Concept
```bash
# No credentials required. Run in parallel to saturate the DB connection pool.
while true; do
  curl -s -X POST http://<graphql-host>/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input:{entityId:{shard:0,realm:0,num:3}}) { balance(unit: GIGABAR) } }"}' &
done
```
Every iteration: passes parser limits (tiny query), passes complexity check (score << 200), passes depth check (depth 2), triggers `entityRepository.findById(3)`, returns `{"data":{"account":{"balance":0}}}`. With sufficient parallelism the database connection pool is exhausted and legitimate requests begin timing out.