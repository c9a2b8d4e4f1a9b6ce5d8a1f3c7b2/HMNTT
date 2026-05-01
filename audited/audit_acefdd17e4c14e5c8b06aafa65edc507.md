### Title
Deleted Entity Exposed via ID Lookup Due to Missing `deleted` Filter in `getByIdAndType`

### Summary
`EntityServiceImpl.getByIdAndType()` uses the standard Spring Data `CrudRepository.findById()` which carries no `deleted` filter, while `getByAliasAndType()` uses a custom query with an explicit `deleted is not true` predicate. This means a deleted entity is returned when queried by numeric ID but returns empty when queried by alias, creating an observable inconsistency in the mirror node's exported state that misrepresents the entity as active.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, line 25:
```java
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
}
```
`findById` is the inherited `CrudRepository<Entity, Long>.findById()` — a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate.

`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, line 13:
```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
```
`findByAlias` explicitly excludes deleted rows.

`getByEvmAddressAndType()` (line 38) has the same defect for long-zero EVM addresses, also delegating to `findById()`.

**Root cause:** The developer added `deleted is not true` to the custom alias and EVM-address queries but forgot to apply the same constraint to the ID path, which relies on the framework-generated `findById` that has no such filter.

**Exploit flow:**
1. Account `0.0.12345` with alias `AAABBB...` is deleted on-chain; the mirror node records `deleted = true`.
2. Attacker (no credentials required) sends GraphQL query by `entityId: "0.0.12345"` → `getByIdAndType` → `findById(12345)` → row returned (deleted flag ignored) → full account object returned to caller.
3. Same attacker queries by `alias: "AAABBB..."` → `getByAliasAndType` → `findByAlias(bytes)` → SQL `deleted is not true` excludes the row → empty result.
4. The two responses for the same entity contradict each other.

### Impact Explanation
Any unauthenticated GraphQL client can retrieve a deleted account's data (balance, keys, memo, type) by querying with its numeric ID. The mirror node's exported state falsely represents the entity as existing and active. Downstream applications that rely on the GraphQL API to verify account existence before acting (e.g., displaying balances, routing payments, validating counterparties) will receive stale/incorrect data. The same defect applies to `getByEvmAddressAndType` for long-zero addresses. Severity is **medium**: no write path is exposed, but the integrity of the read API is broken in a way that is silently inconsistent rather than loudly failing.

### Likelihood Explanation
No authentication or special privilege is required. The attacker only needs to know (or enumerate) a numeric entity ID — IDs are sequential and publicly known on Hedera. The inconsistency is trivially reproducible by any user of the public GraphQL endpoint. It is persistent until the code is fixed.

### Recommendation
Replace the bare `findById` call in `getByIdAndType` (and the `findById` branch in `getByEvmAddressAndType`) with a custom repository method that includes the deleted filter, consistent with the alias and EVM-address paths:

```java
// EntityRepository.java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then update `EntityServiceImpl`:
```java
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findByIdAndNotDeleted(entityId.getId())
                           .filter(e -> e.getType() == type);
}
```
Apply the same fix to the `findById(buffer.getLong())` call in `getByEvmAddressAndType`.

### Proof of Concept
**Precondition:** Entity `0.0.12345` exists in the mirror node DB with `deleted = true` and `alias = <base32-encoded bytes>`.

**Step 1 — query by ID (returns deleted entity):**
```graphql
query {
  account(input: { entityId: "0.0.12345" }) {
    id
    balance
    deleted
  }
}
```
Response: account object with `deleted: true` (or the field may not even be exposed, hiding the deletion).

**Step 2 — query by alias (returns nothing):**
```graphql
query {
  account(input: { alias: "<base32alias>" }) {
    id
    balance
  }
}
```
Response: `null`.

**Observed inconsistency:** Step 1 returns the entity; Step 2 returns empty for the identical entity — confirming the deleted filter is absent in the ID path. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L37-39)
```java
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```
