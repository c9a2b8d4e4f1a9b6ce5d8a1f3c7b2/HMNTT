### Title
Unbounded Base32 Alias Input Bypasses Index, Enabling Sequential Table Scan DoS

### Summary
The GraphQL `account` query accepts an alias string with no maximum length constraint — only a character-set `@Pattern` is enforced. A Base32 string long enough to decode to a byte array exceeding PostgreSQL's B-tree index key size limit (~2,712 bytes for default 8 KB pages) causes the planner to abandon the `entity__alias` partial index and fall back to a full sequential scan of the `entity` table. Any unauthenticated caller can trigger this repeatedly, exhausting database I/O and connection capacity.

### Finding Description

**Code path:**

1. `graphql/src/main/resources/graphql/account.graphqls` line 90 — the only validation on `alias` is a character-set regex; no `@Size` or `@Length` constraint exists:
   ```graphql
   alias: String @Pattern(regexp: "^[A-Z2-7]+$")
   ```

2. `graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java` lines 83–85 — `decodeBase32` performs no length check before decoding:
   ```java
   public static byte[] decodeBase32(String base32) {
       return BASE32.decode(base32);
   }
   ```

3. `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java` line 30 — the decoded byte array is passed directly to the repository:
   ```java
   return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
   ```

4. `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` lines 13–14 — the native query runs against the `entity` table:
   ```java
   @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
   Optional<Entity> findByAlias(byte[] alias);
   ```

**Root cause:** PostgreSQL B-tree indexes have a maximum key size of approximately 2,712 bytes (default 8 KB page). The partial index `entity__alias` (created in `V1.50.3__account_alias.sql` line 13) cannot hold entries larger than this limit. When the query parameter exceeds that size, the planner cannot use the index and falls back to a sequential scan of the entire `entity` table.

**Threshold calculation:** Base32 encodes 5 bits per character (8 chars → 5 bytes). To produce a decoded value of 2,713 bytes requires ⌈2713 × 8/5⌉ = **4,341 Base32 characters** — well within the Jackson `maxStringLength(11000)` limit configured in `GraphQlConfiguration.java` line 79.

### Impact Explanation

Every request carrying a ≥4,341-character alias string forces a full sequential scan of the `entity` table. In a production Hedera mirror node the `entity` table contains tens of millions of rows. Concurrent sequential scans saturate disk I/O and shared-buffer bandwidth, degrading or blocking all other queries that depend on the same table — including legitimate transaction history lookups. The `db.statementTimeout` of 10 seconds (documented in `docs/graphql/README.md` line 23) means each malicious request can hold a database connection for up to 10 seconds before being killed, and the attacker can pipeline requests continuously.

### Likelihood Explanation

No authentication is required. The GraphQL endpoint is publicly reachable. The only per-IP concurrency control is the Traefik `inFlightReq: amount: 5` middleware (`charts/hedera-mirror-graphql/values.yaml` line 138–141), which does not prevent a distributed attack and still allows 5 simultaneous 10-second sequential scans per source IP. The exploit requires only a standard HTTP client and knowledge of the GraphQL schema, which is publicly introspectable.

### Recommendation

Add an explicit maximum-length constraint on the alias field before decoding. The longest legitimate Hedera alias is a protobuf-encoded ECDSA secp256k1 key (~38 bytes → 61 Base32 characters). A safe upper bound is 100 characters:

1. **GraphQL schema** (`account.graphqls`): replace the bare `@Pattern` with a combined size+pattern directive, or add `@Size(max=100)`.
2. **`GraphQlUtils.decodeBase32`**: add a guard before decoding:
   ```java
   public static byte[] decodeBase32(String base32) {
       if (base32 != null && base32.length() > 100) {
           throw new IllegalArgumentException("Alias exceeds maximum length");
       }
       return BASE32.decode(base32);
   }
   ```
3. Optionally add a database-level `CHECK (length(alias) <= 50)` constraint to enforce the invariant at the storage layer.

### Proof of Concept

```bash
# Generate a 5000-character valid Base32 alias (all 'A', valid [A-Z2-7])
ALIAS=$(python3 -c "print('A' * 5000)")

curl -s -X POST http://<mirror-node-host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"query { account(input: { alias: \\\"$ALIAS\\\" }) { id } }\"}"
```

Each request causes PostgreSQL to execute `SELECT * FROM entity WHERE alias = $1 AND deleted IS NOT TRUE` with a ~3,125-byte parameter, bypassing the `entity__alias` B-tree index and performing a full sequential scan. Sending this in a loop (or from multiple IPs) exhausts database I/O capacity and prevents legitimate queries from completing within their timeout window.