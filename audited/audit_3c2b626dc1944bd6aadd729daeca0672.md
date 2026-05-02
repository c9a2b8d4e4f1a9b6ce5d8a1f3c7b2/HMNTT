### Title
GraphQL `findByEvmAddress` Returns NULL-Deleted Entities Due to `deleted is not true` vs `deleted <> true` Inconsistency

### Summary
The GraphQL `EntityRepository.findByEvmAddress` uses the SQL predicate `deleted is not true`, which in standard SQL evaluates to TRUE when `deleted IS NULL`, causing entities in an indeterminate deletion state to be returned. All other API layers (REST-Java, importer, web3) use either `deleted <> true` or Spring Data's `DeletedIsFalse`, both of which exclude NULL-deleted entities. This creates a cross-API data inconsistency observable by any unauthenticated user.

### Finding Description
**Exact code location:**

- GraphQL: `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, line 16–17 — uses `deleted is not true`
- REST-Java: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java`, line 16–17 — uses `deleted <> true`
- Importer: `importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java`, line 19–20 — uses `deleted <> true`
- Web3: `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, line 37 — uses `findByEvmAddressAndDeletedIsFalse` (generates `deleted = false`)

**Root cause — SQL three-valued logic:**

| Predicate | `deleted = false` | `deleted = true` | `deleted IS NULL` |
|---|---|---|---|
| `deleted is not true` | ✅ returned | ❌ filtered | ✅ **returned** |
| `deleted <> true` | ✅ returned | ❌ filtered | ❌ filtered (NULL) |
| `deleted = false` | ✅ returned | ❌ filtered | ❌ filtered |

**NULL-deleted entities exist in production.** Migration `V1.39.1__upsert_support.sql` explicitly dropped the NOT NULL constraint and default on `entity.deleted` with the comment *"allow nullable on entity deleted as transaction cannot make this assumption on updates"*. This means any entity that was partially upserted without an explicit deletion flag will have `deleted IS NULL`.

**Failed assumption:** The GraphQL query author likely intended `deleted is not true` to be equivalent to `deleted = false`, but in SQL's three-valued logic, `NULL IS NOT TRUE` evaluates to `TRUE`, not `FALSE`.

**Exploit flow:**
1. An entity is written to the database with `deleted IS NULL` (normal upsert path).
2. An unprivileged user queries the GraphQL API: `{ account(input: {evmAddress: "0x..."}) { ... } }` — the entity is returned.
3. The same user queries the REST API `/api/v1/accounts/{evmAddress}` — the entity is NOT returned (uses `deleted <> true`).
4. The same address queried via web3/EVM calls also returns nothing (uses `deletedIsFalse`).

**Test gap confirmed:** The REST-Java test (`rest-java/src/test/java/org/hiero/mirror/restjava/repository/EntityRepositoryTest.java`, lines 23–28 and 36–46) explicitly covers the `deleted(null)` case and asserts empty result. The GraphQL test (`graphql/src/test/java/org/hiero/mirror/graphql/repository/EntityRepositoryTest.java`, lines 29–34) has no such test case, confirming the gap is untested.

### Impact Explanation
Any entity in the `deleted IS NULL` state is exposed through GraphQL as an active, non-deleted entity while being invisible to all other API surfaces. Applications or users relying on GraphQL for entity resolution will receive stale or indeterminate state data. This is a cross-API data inconsistency that can cause incorrect application behavior (e.g., treating a logically-deleted entity as live). Severity is medium/griefing: no funds are at risk, but the inconsistency is persistent and reproducible.

### Likelihood Explanation
The precondition (entities with `deleted IS NULL`) is a normal, documented database state created by the upsert mechanism — not an edge case. Any unprivileged user can trigger this by querying the GraphQL endpoint with a known EVM address. No special privileges, credentials, or network access beyond public API access are required. The condition is repeatable as long as NULL-deleted entities exist in the database.

### Recommendation
Change the GraphQL `EntityRepository` queries to use `deleted <> true` (matching the importer and REST-Java repositories) or `deleted is false` to explicitly exclude NULL-deleted entities:

```java
@Query(value = "select * from entity where evm_address = ?1 and deleted is false", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);

@Query(value = "select * from entity where alias = ?1 and deleted is false", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
```

Add a test case mirroring the REST-Java test that asserts `findByEvmAddress` returns empty for a `deleted(null)` entity.

### Proof of Concept
1. Insert an entity into the `entity` table with `evm_address = '\xdeadbeef...'` and `deleted = NULL` (achievable via the normal upsert path).
2. Send a GraphQL query:
   ```graphql
   query { account(input: { evmAddress: "0xdeadbeef..." }) { id deleted } }
   ```
   → Returns the entity with `deleted: null`.
3. Query the REST API:
   ```
   GET /api/v1/accounts/0xdeadbeef...
   ```
   → Returns 404 (entity not found, because `deleted <> true` excludes NULL).
4. The same entity appears active in GraphQL and non-existent in REST, demonstrating the inconsistency. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L19-20)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L37-37)
```java
    Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
```

**File:** importer/src/main/resources/db/migration/v1/V1.39.1__upsert_support.sql (L5-8)
```sql
-- allow nullable on entity deleted as transaction cannot make this assumption on updates
alter table entity
    alter column deleted drop default,
    alter column deleted drop not null;
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/repository/EntityRepositoryTest.java (L36-46)
```java
        var entityDeletedNull =
                domainBuilder.entity().customize(b -> b.deleted(null)).persist();

        assertThat(entityRepository.findByEvmAddress(entity.getEvmAddress()))
                .get()
                .isEqualTo(entity.getId());
        assertThat(entityRepository.findByEvmAddress(entityDeleted.getEvmAddress()))
                .isEmpty();
        assertThat(entityRepository.findByEvmAddress(new byte[] {1, 2, 3})).isEmpty();
        assertThat(entityRepository.findByEvmAddress(entityDeletedNull.getEvmAddress()))
                .isEmpty();
```

**File:** graphql/src/test/java/org/hiero/mirror/graphql/repository/EntityRepositoryTest.java (L29-34)
```java
    void findByEvmAddress() {
        var entity = domainBuilder.entity().persist();
        assertThat(entityRepository.findByEvmAddress(entity.getEvmAddress()))
                .get()
                .isEqualTo(entity);
    }
```
