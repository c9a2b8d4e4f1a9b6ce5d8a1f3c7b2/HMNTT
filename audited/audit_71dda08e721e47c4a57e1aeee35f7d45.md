### Title
Unauthenticated DB Connection Pool Exhaustion via Crafted EVM Address Routing in GraphQL `getByEvmAddressAndType()`

### Summary
The `getByEvmAddressAndType()` method in `EntityServiceImpl.java` contains a deterministic routing branch: any 20-byte EVM address whose first 12 bytes are zero is silently redirected to a primary-key DB lookup (`findById()`). Because the GraphQL endpoint requires no authentication and has no per-request rate limiting, an unprivileged attacker can flood the endpoint with crafted addresses — each triggering a unique DB query — exhausting the connection pool and degrading service for all users.

### Finding Description

**Exact code path:** [1](#0-0) 

```
bytes  0– 3  → buffer.getInt()   == 0  (shard field)
bytes  4–11  → buffer.getLong()  == 0  (realm field)
bytes 12–19  → buffer.getLong()  → passed directly to findById()
```

Any hex string matching `^(0x)?[a-fA-F0-9]{40}$` with the first 24 hex chars being `000000000000000000000000` satisfies the branch condition. The last 16 hex chars (8 bytes) are decoded to a `long` and used as the DB primary key with no further validation.

**Input validation is format-only:** [2](#0-1) 

The `@Pattern(regexp: "^(0x)?[a-fA-F0-9]{40}$")` directive only enforces that the string is 40 hex characters. It does not constrain the semantic content of the address, so the crafted prefix passes validation unconditionally.

**No rate limiting on the GraphQL module:** [3](#0-2) 

The only protections configured are `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`. These limit the structural complexity of a single GraphQL document, not the number of HTTP requests per second. The `ThrottleManagerImpl` / `ThrottleConfiguration` rate-limiting beans exist only in the `web3` module, not in the `graphql` module. [4](#0-3) 

The only servlet filter in the graphql module is a logging filter — no rate-limiting or authentication filter is present.

**Repository call triggered:** [5](#0-4) 

`findById()` is inherited from `CrudRepository<Entity, Long>` and issues `SELECT * FROM entity WHERE id = ?`. Each unique last-8-byte value produces a distinct query that must acquire a DB connection from the pool.

### Impact Explanation

Each crafted request acquires a JDBC connection, executes a primary-key query, and releases the connection. With no rate limiting, an attacker sending hundreds of concurrent requests per second will hold all connections in the pool simultaneously. Once the pool is exhausted, all other GraphQL queries (and any other component sharing the same pool) queue or fail, causing a full service outage for legitimate users. The impact is a denial-of-service against the mirror node's GraphQL API and its backing database.

### Likelihood Explanation

The attack requires no credentials, no prior knowledge of valid entity IDs (any 64-bit value triggers the query regardless of whether a matching row exists), and no special tooling beyond a standard HTTP client. The crafted address format is trivially constructable. The attack is fully repeatable and can be automated with a simple loop varying the last 8 bytes. Because the GraphQL endpoint is publicly documented and exposed, the barrier to exploitation is extremely low.

### Recommendation

1. **Add per-IP or global request-rate limiting** to the GraphQL module (e.g., a servlet filter using Bucket4j, analogous to `ThrottleManagerImpl` in the `web3` module).
2. **Validate the decoded entity ID** in the `findById()` branch: reject IDs that are zero or exceed the known maximum valid entity ID before issuing the DB query.
3. **Require authentication** for the GraphQL endpoint, or at minimum enforce connection-level throttling at the ingress/load-balancer layer.

### Proof of Concept

```bash
# Crafted evmAddress: first 12 bytes = 0x00, last 8 bytes vary
# Format: 000000000000000000000000 + <16 hex digits>

for i in $(seq 1 500); do
  SUFFIX=$(printf '%016x' $i)
  ADDR="000000000000000000000000${SUFFIX}"
  curl -s -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{account(input:{evmAddress:\\\"${ADDR}\\\"}){id}}\"}" &
done
wait
```

Each iteration sends a unique evmAddress satisfying the regex, passes the `getInt()==0 && getLong()==0` branch, and issues a distinct `SELECT * FROM entity WHERE id = <i>` query. Running 500 concurrent requests exhausts a typical connection pool (default HikariCP pool size is 10), blocking all other DB-dependent operations.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L96-96)
```text
    evmAddress: String @Pattern(regexp: "^(0x)?[a-fA-F0-9]{40}$")
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/LoggingFilter.java (L18-38)
```java
class LoggingFilter extends OncePerRequestFilter {

    @SuppressWarnings("java:S1075")
    private static final String ACTUATOR_PATH = "/actuator/";

    private static final String LOG_FORMAT = "{} {} {} in {} ms: {} {}";
    private static final String SUCCESS = "Success";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```
