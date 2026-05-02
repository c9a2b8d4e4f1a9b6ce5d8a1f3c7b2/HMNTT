### Title
GraphQL `findByEvmAddress` Returns NULL-Deleted Entities Due to Inconsistent SQL Predicate

### Summary
The GraphQL `EntityRepository.findByEvmAddress` uses `deleted is not true` which, by SQL three-valued logic, matches rows where `deleted` is `NULL` in addition to `false`. Every other module in the same codebase (`importer`, `rest-java`) uses `deleted <> true`, which excludes `NULL` rows because `NULL <> true` evaluates to `UNKNOWN` (falsy) in SQL. An unprivileged user can therefore retrieve an entity via GraphQL that is invisible to every other API surface, producing contradictory responses from the same underlying data.

### Finding Description
**Exact location:**
- `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java`, line 16–17
  ```java
  @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
  Optional<Entity> findByEvmAddress(byte[] evmAddress);
  ```
- Contrast with `importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java`, line 19–20 and `rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java`, line 16–17, both of which use `deleted <> true`.

**Root cause — SQL NULL semantics:**
| Predicate | `deleted = false` | `deleted = true` | `deleted = NULL` |
|---|---|---|---|
| `deleted is not true` | ✓ returned | ✗ filtered | **✓ returned** |
| `deleted <> true` | ✓ returned | ✗ filtered | **✗ filtered** |

`NULL <> true` evaluates to `UNKNOWN`, which is treated as `FALSE` in a `WHERE` clause, so `deleted <> true` silently drops NULL rows. `deleted is not true` explicitly handles the three-valued case and passes NULL rows through.

**Exploit flow:**
1. An entity row exists in the `entity` table with `evm_address = X` and `deleted = NULL` (common for entities whose deletion state was never explicitly set).
2. Attacker sends a GraphQL query: `{ account(input: { evmAddress: "0x<X>" }) { ... } }` → GraphQL calls `findByEvmAddress(X)` → SQL predicate `deleted is not true` is satisfied → entity is returned.
3. Attacker (or any other user/system) queries the REST-Java API for the same address → `deleted <> true` is not satisfied for a NULL row → empty response.

**Why existing checks fail:**
The GraphQL test (`EntityRepositoryTest.findByEvmAddress`) only tests a normally-persisted entity; it never asserts that a `deleted = NULL` entity is excluded. The rest-java test explicitly asserts `entityDeletedNull` returns empty (`rest-java/src/test/java/.../EntityRepositoryTest.java`, lines 36–46), confirming the intended cross-API contract is that NULL-deleted entities should not be surfaced — but GraphQL violates this contract silently.

### Impact Explanation
Any entity whose `deleted` column is `NULL` is exposed through the GraphQL API while being invisible to the REST and importer APIs. This creates a split-brain view of entity existence: a user or downstream system that cross-checks GraphQL against REST will receive contradictory answers for the same address. In a financial/ledger context this can cause incorrect assumptions about account existence, leading to griefing (e.g., constructing transactions against an account that REST reports as non-existent). No write path is involved, so direct economic loss is not possible, but the inconsistency undermines the reliability of the mirror node as a source of truth.

### Likelihood Explanation
No authentication or special privilege is required. The GraphQL endpoint is publicly accessible. Entities with `deleted = NULL` are a normal database state (any entity whose deletion flag was never explicitly written). The attacker needs only to know or enumerate a valid `evmAddress` — a trivial precondition given that EVM addresses are observable on-chain. The attack is fully repeatable and requires no timing window.

### Recommendation
Change the GraphQL query predicate to match the rest of the codebase:

```java
// graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java
@Query(value = "select * from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);

// and the same fix for findByAlias on line 13
@Query(value = "select * from entity where alias = ?1 and deleted <> true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
```

Add a test case mirroring the rest-java test to assert that a `deleted = NULL` entity is not returned by `findByEvmAddress` in the GraphQL repository.

### Proof of Concept
1. Insert a row into the `entity` table: `INSERT INTO entity (id, evm_address, deleted, ...) VALUES (999, '\xDEADBEEF...', NULL, ...)`.
2. Send GraphQL query:
   ```graphql
   { account(input: { evmAddress: "0xDEADBEEF..." }) { id deleted } }
   ```
   → Response: entity with `id=999` is returned.
3. Send REST-Java request: `GET /api/v1/accounts/0xDEADBEEF...`
   → Response: 404 / empty (because `deleted <> true` excludes the NULL row).
4. The two responses contradict each other for the same address, confirming the inconsistency. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L19-20)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
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
