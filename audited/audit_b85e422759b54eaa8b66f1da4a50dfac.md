### Title
GraphQL `findByAlias()` Returns Entities with `deleted = NULL` Due to `IS NOT TRUE` vs `<> TRUE` SQL Semantic Difference

### Summary
The GraphQL `EntityRepository.findByAlias()` uses `deleted is not true` which, under SQL three-valued logic, matches both `deleted = false` AND `deleted = NULL`. Every other service in the codebase (importer, rest-java, REST Node.js) explicitly excludes `deleted = NULL` rows using `deleted <> true` or `coalesce(deleted, false) <> true`. An unprivileged external user can query the public GraphQL API by alias and receive entities whose deletion status was never confirmed by the importer — entities that all other mirror node services correctly suppress.

### Finding Description
**Exact location:** `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, line 13:
```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
```

**Root cause — SQL NULL semantics:**
- `deleted IS NOT TRUE` → evaluates to `TRUE` for both `NULL` and `FALSE` → rows with `deleted = NULL` are **included**
- `deleted <> true` → evaluates to `NULL` (unknown) for `NULL` → rows with `deleted = NULL` are **excluded**
- `coalesce(deleted, false) <> true` → explicitly coerces `NULL` to `false` → rows with `deleted = NULL` are **excluded**

**Why `deleted = NULL` exists:** Migration `V1.39.1__upsert_support.sql` explicitly dropped the `NOT NULL` constraint on `deleted` with the comment *"allow nullable on entity deleted as transaction cannot make this assumption on updates."* This means `deleted = NULL` is a legitimate, reachable database state representing an entity whose active/deleted status has not yet been confirmed by the importer.

**Contrast with other services:**

| Service | Query predicate | Returns `deleted = NULL`? |
|---|---|---|
| `graphql` `EntityRepository` (line 13) | `deleted is not true` | **YES** |
| `importer` `EntityRepository` (line 16) | `deleted <> true` | No |
| `rest-java` `EntityRepository` (line 13) | `deleted <> true` | No |
| REST Node.js `entityService.js` (line 19) | `coalesce(deleted, false) <> true` | No |

The rest-java test at `rest-java/src/test/java/.../EntityRepositoryTest.java` lines 23–28 explicitly asserts that `findByAlias` on an entity with `deleted = null` returns empty — confirming the intended behavior is to exclude such entities. The GraphQL repository has no equivalent test and no equivalent guard.

**Exploit flow:**
1. Attacker has no credentials. They observe or enumerate a base32-encoded alias (aliases are public on-chain data).
2. They POST to the public GraphQL endpoint (`/graphql/alpha`):
   ```graphql
   query { account(input: { alias: "<base32_alias>" }) { deleted entityId { num } } }
   ```
3. The request reaches `AccountController.account()` → `EntityServiceImpl.getByAliasAndType()` → `EntityRepository.findByAlias()`.
4. The SQL query `select * from entity where alias = ?1 and deleted is not true` matches the row where `deleted IS NULL`.
5. The response returns the entity with `"deleted": null`, exposing an entity that the importer has not confirmed as active.

**Existing checks are insufficient:** The only filter applied after `findByAlias()` in `EntityServiceImpl.getByAliasAndType()` is `.filter(e -> e.getType() == type)` — a type check, not a deletion-status check. There is no secondary guard against `deleted = NULL`.

### Impact Explanation
The GraphQL mirror node serves authoritative account state to downstream consumers (wallets, explorers, integrators). Returning entities with `deleted = NULL` means the mirror node exports records whose canonical status is "unknown/unconfirmed" as if they were live accounts. This is a data-integrity violation: the mirror node's view of active accounts diverges from the view of every other service in the same codebase. Consumers relying on the GraphQL API to determine whether an account is active will receive incorrect affirmative answers for accounts in an indeterminate state. Severity is **Medium** — no direct asset theft, but incorrect state propagation to downstream systems and clients.

### Likelihood Explanation
Exploitation requires zero privileges. The GraphQL endpoint is publicly reachable, aliases are on-chain public data, and the query is a standard single-field lookup. Any external user who knows or can enumerate an alias can trigger this. The condition (`deleted = NULL`) is a normal operational state that arises during importer processing gaps, so affected rows exist in production databases. Repeatability is deterministic.

### Recommendation
Replace `deleted is not true` with the same predicate used by every other service:

```java
// Option 1 — consistent with importer and rest-java:
@Query(value = "select * from entity where alias = ?1 and deleted <> true", nativeQuery = true)

// Option 2 — most explicit, consistent with REST Node.js:
@Query(value = "select * from entity where alias = ?1 and coalesce(deleted, false) <> true", nativeQuery = true)
```

Apply the same fix to `findByEvmAddress()` on line 16, which has the identical issue. Add a test mirroring the rest-java test (lines 23–28) that asserts `findByAlias` returns empty for an entity with `deleted = null`.

### Proof of Concept
**Precondition:** An entity row exists in the `entity` table with a known `alias` and `deleted = NULL` (normal during importer lag or partial upsert).

**Trigger:**
```bash
curl -X POST http://<mirror-node>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ account(input: { alias: \"<BASE32_ALIAS>\" }) { deleted entityId { num } } }"}'
```

**Expected (correct) result:** `{ "data": { "account": null } }` — entity suppressed because deletion status is unconfirmed.

**Actual result:** `{ "data": { "account": { "deleted": null, "entityId": { "num": 12345 } } } }` — entity returned with `deleted: null`, exposing an unconfirmed record that importer, rest-java, and REST Node.js all suppress.