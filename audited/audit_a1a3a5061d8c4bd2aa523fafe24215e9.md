### Title
Unauthenticated Long-Zero EVM Address Lookup Causes Unbounded DB Queries Leading to Connection Pool Exhaustion

### Summary
The `getByEvmAddressAndType()` method in `EntityServiceImpl` routes long-zero EVM addresses directly to `entityRepository.findById()`, which has no caching in the GraphQL module's `EntityRepository`. An unauthenticated attacker can flood the public GraphQL endpoint with crafted long-zero addresses pointing to non-existent entity IDs, generating a DB query on every request with no cache absorption, exhausting the connection pool and rendering the service unavailable.

### Finding Description

**Exact code path:**

`AccountController.account()` (line 51-54) accepts an `evmAddress` argument from any unauthenticated caller and passes it to `EntityServiceImpl.getByEvmAddressAndType()`:

```
graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java:51-54
graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java:34-41
```

Inside `getByEvmAddressAndType()`:

```java
byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
var buffer = ByteBuffer.wrap(evmAddressBytes);
if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // first 12 bytes == 0 → long-zero
    return entityRepository.findById(buffer.getLong())         // DB hit, no cache
                           .filter(e -> e.getType() == type);
}
```

The long-zero branch calls `entityRepository.findById()`, which is the standard Spring Data `CrudRepository.findById()`. The GraphQL module's `EntityRepository` carries **zero `@Cacheable` annotations**:

```java
// graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    Optional<Entity> findByAlias(byte[] alias);
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
}
```

Neither `findById` (inherited) nor `findByEvmAddress` is annotated with `@Cacheable`. This is in direct contrast to the web3 module's `EntityRepository`, which explicitly caches both methods with `unless = "#result == null"` to absorb null/miss results.

**Root cause:** The failed assumption is that repeated lookups for non-existent entity IDs are bounded by a cache. They are not. Every request for a non-existent long-zero address produces a live SQL `SELECT` against the `entity` table.

**Why existing checks fail:**

- `GraphQlConfiguration` sets `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` — these limit the *structure* of a single query, not the *rate* of requests.
- Parser limits (`maxCharacters=10000`, `maxTokens=1000`) prevent oversized payloads but not high request volume.
- `LoggingFilter` only logs; it applies no throttling.
- `CacheProperties.query` caches only preparsed GraphQL *documents*, not entity lookup results.
- No authentication, no per-IP rate limiting, no request quota anywhere in the GraphQL module.

### Impact Explanation

Each concurrent attacker request holds a JDBC connection for the duration of the `SELECT` against the `entity` table. With a sufficiently high request rate, the connection pool (typically 10–20 connections by default in HikariCP) is fully occupied by queries returning empty results. Subsequent legitimate requests queue and time out. The GraphQL service becomes completely unresponsive — matching the "total network shutdown" severity classification — without any privileged access required.

### Likelihood Explanation

The attack requires zero authentication, zero prior knowledge of the system beyond the public GraphQL endpoint, and only a standard HTTP client. The payload is a single valid GraphQL query:

```graphql
{ account(input: { evmAddress: "0x000000000000000000000000FFFFFFFFFFFFFFFF" }) { id } }
```

Any attacker with network access to the endpoint can automate this at high concurrency. The address space for non-existent long-zero IDs is effectively unbounded (any 8-byte value not corresponding to a real entity), so cache-warming by the attacker is not a concern — every distinct non-existent ID is a fresh miss. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add `@Cacheable` with null-result caching to the GraphQL `EntityRepository`**, mirroring the web3 module's pattern. Critically, cache negative (empty) results so that repeated misses for the same ID do not hit the DB:
   ```java
   @Cacheable(cacheNames = "entity", unless = "#result != null && #result.isPresent()")
   Optional<Entity> findById(Long id);
   ```
2. **Apply rate limiting** at the servlet or API gateway layer (e.g., Spring's `RateLimiter`, Bucket4j, or an upstream reverse proxy) keyed on client IP.
3. **Validate entity ID range** before issuing the DB query: reject IDs that are obviously out of the valid shard/realm/num range (e.g., negative or exceeding known maximums) before touching the database.

### Proof of Concept

**Preconditions:** Network access to the GraphQL endpoint (no credentials needed).

**Steps:**

```bash
# Craft a long-zero address: 12 zero bytes + 8 bytes for a non-existent entity num (e.g., 0xDEADBEEFDEADBEEF)
EVM_ADDR="0x000000000000000000000000DEADBEEFDEADBEEF"

# Flood with concurrent requests (e.g., using GNU parallel or wrk)
for i in $(seq 1 500); do
  curl -s -X POST http://<graphql-host>/graphql \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ account(input: { evmAddress: \\\"$EVM_ADDR\\\" }) { id } }\"}" &
done
wait
```

**Trigger:** Each request enters `getByEvmAddressAndType()`, passes the long-zero check (first 12 bytes are `0x00`), and calls `entityRepository.findById(0xDEADBEEFDEADBEEF)` — a live DB query returning empty with no caching.

**Result:** DB connection pool saturates; subsequent legitimate GraphQL queries receive connection timeout errors or are rejected; service is effectively unavailable.