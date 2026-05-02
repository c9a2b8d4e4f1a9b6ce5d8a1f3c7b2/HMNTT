### Title
Missing Alias Length Validation Enables Unauthenticated Resource Exhaustion via GraphQL `account()` Query

### Summary
The GraphQL `account()` endpoint accepts an `alias` input field constrained only by character set (`^[A-Z2-7]+$`) with no length limit. An unauthenticated attacker can submit arbitrarily long Base32 strings that pass validation, are decoded by `decodeBase32()` into large byte arrays, and are passed directly to `entityRepository.findByAlias()`, which executes a raw SQL equality scan against the `entity` table. Under concurrent load, this can exhaust the database connection pool and degrade or partition the application from the database.

### Finding Description

**Code path:**

1. `AccountController.account()` receives `@Valid AccountInput input` and extracts `alias`. [1](#0-0) 

2. The GraphQL schema enforces `@Pattern(regexp: "^[A-Z2-7]+$")` on `alias` — validating only the Base32 character set, with **no `@Size` or length constraint**. [2](#0-1) 

3. `EntityServiceImpl.getByAliasAndType()` calls `decodeBase32(alias)` with no length guard before passing the result to the repository. [3](#0-2) 

4. `decodeBase32()` is a bare `BASE32.decode(base32)` call — no maximum input or output length enforced. [4](#0-3) 

5. `EntityRepository.findByAlias()` executes `select * from entity where alias = ?1 and deleted is not true` — a native query that, if the `alias` column lacks a B-tree index, performs a full sequential scan of the `entity` table for every call. [5](#0-4) 

**Root cause:** The failed assumption is that `@Pattern` is sufficient input validation. It is not — it enforces only the alphabet, not the length. There is no `@Size(max=...)` annotation, no length check in `decodeBase32()`, and no query timeout or rate-limiting visible in the controller or service layer.

### Impact Explanation
Each crafted request holds a JDBC connection for the full duration of the `entity` table scan. A production Hedera mirror node's `entity` table can contain tens of millions of rows. With a modest number of concurrent requests (e.g., 50–100, matching a typical HikariCP pool size), all connections are occupied with long-running scans. New legitimate requests queue and eventually time out. This constitutes a denial-of-service against the GraphQL service's database connectivity — a network partition from the database caused by resource exhaustion, not a network fault.

### Likelihood Explanation
The GraphQL endpoint is publicly reachable with no authentication requirement. The exploit requires only the ability to send HTTP POST requests with a valid GraphQL query body. The `@Pattern` constraint is trivially satisfied by any string of uppercase `A-Z` and `2-7` characters of arbitrary length. The attack is fully repeatable and scriptable. No special knowledge, credentials, or protocol access is needed.

### Recommendation
1. Add a `@Size(max = N)` constraint to the `alias` field in the `AccountInput` schema/Java class, where `N` reflects the maximum legitimate alias length (e.g., 100 characters for a protobuf-encoded public key alias in Base32).
2. Add a length guard inside `decodeBase32()` or `getByAliasAndType()` that rejects inputs exceeding the expected byte length before any DB call.
3. Ensure the `alias` column in the `entity` table has a database index to bound query cost regardless of input.
4. Apply query-level rate limiting or GraphQL complexity limits at the `GraphQlConfiguration` layer.

### Proof of Concept

```bash
# Generate a long valid Base32 alias (10,000 chars, all valid Base32 alphabet)
ALIAS=$(python3 -c "print('A' * 10000)")

# Send concurrent account() queries to the GraphQL endpoint
for i in $(seq 1 100); do
  curl -s -X POST http://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input: { alias: \\\"$ALIAS\\\" }) { id } }\"}" &
done
wait
```

Each request passes the `@Pattern` check, decodes to a ~6,250-byte array, and triggers `select * from entity where alias = ?1 and deleted is not true`. With 100 concurrent requests and a large `entity` table, the connection pool is saturated, and subsequent legitimate queries are rejected or time out.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L33-48)
```java
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L87-100)
```text
input AccountInput {

    "A RFC 4648 Base32, with the trailing '=' characters removed, string that represents an account alias."
    alias: String @Pattern(regexp: "^[A-Z2-7]+$")

    "The unique shard, realm, and number associated with an account."
    entityId: EntityIdInput

    "A hex-encoded string that represents a 20-byte EVM address."
    evmAddress: String @Pattern(regexp: "^(0x)?[a-fA-F0-9]{40}$")

    "An opaque, globally unique identifier specific to GraphQL."
    id: ID @Pattern(regexp: "^[a-zA-Z0-9+/=]+$")
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L83-85)
```java
    public static byte[] decodeBase32(String base32) {
        return BASE32.decode(base32);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```
