### Title
Stale Replica Read in GraphQL `getByAliasAndType()` Due to Missing pgpool Load-Balance Bypass

### Summary
The GraphQL module's `EntityServiceImpl.getByAliasAndType()` issues alias-lookup queries through pgpool without the `/* NO PGPOOL LOAD BALANCE */` hint that the importer module explicitly uses to force reads to the primary. During replication lag or a network partition, pgpool can route the query to a stale replica that has not yet applied a recent alias re-assignment (delete old entity + create new entity with same alias), causing the old entity's account data to be returned to any caller.

### Finding Description
**Code path:**

`AccountController.account()` (line 48) → `EntityServiceImpl.getByAliasAndType()` (line 29-31) → `EntityRepository.findByAlias()` (line 13-14):

```sql
select * from entity where alias = ?1 and deleted is not true
```

The importer module contains `HibernateConfiguration.java` (lines 19-35) which prepends `/* NO PGPOOL LOAD BALANCE */` to every SQL statement when `loadBalance` is disabled, with an explicit comment: *"This is used to prevent the stale read-after-write issue."* The graphql module has no equivalent `HibernateConfiguration`, no `StatementInspector`, and no load-balance bypass of any kind — confirmed by a full search of `graphql/src/main/java/` and `graphql/src/main/resources/`.

**Root cause:** The graphql module's `EntityRepository` queries are eligible for pgpool read-replica routing. The `deleted is not true` predicate is evaluated on whatever replica pgpool selects, not necessarily the primary.

**Alias re-use is real:** The Rosetta test suite (`rosetta/app/persistence/account_test.go`, lines 535-548) explicitly constructs a scenario where `accountNum2` holds the same alias as a live account but was deleted first — confirming the Hedera protocol allows alias re-use after deletion. The `entity` table has only a non-unique index on `alias` (no unique constraint), supporting multiple rows with the same alias value across time.

**Exploit flow:**
1. Account A (alias `X`) exists and is active. Importer writes `deleted = true` for A and creates Account B with alias `X`.
2. Pgpool replica has not yet replicated these two writes (replication lag, or network partition between primary and replica).
3. Attacker (or any user) sends: `POST /graphql/alpha` with `account(input: { alias: "X" })`.
4. Pgpool routes the query to the stale replica.
5. Replica still sees Account A with `deleted = false` and alias `X`. The `deleted is not true` filter passes.
6. GraphQL returns Account A's data (balance, keys, memo, etc.) instead of Account B's.

### Impact Explanation
Any caller receives Account B's alias lookup resolved to Account A's entity record — wrong balance, wrong public key, wrong account ID. For a read-only mirror node this is a data-integrity violation: clients making decisions based on the returned key or balance (e.g., verifying ownership, checking balance before a transfer) act on incorrect state. Severity is medium: no funds are moved by the mirror node itself, but downstream clients trusting the response are misled.

### Likelihood Explanation
No privilege is required — the GraphQL endpoint is public. The precondition (alias re-use) is a documented, tested Hedera protocol feature. Replication lag is a normal operational condition; a network partition makes it worse and longer-lasting. The deployment uses pgpool with read replicas by default (Helm chart `values.yaml`, lines 169-201). The importer team already identified and fixed this exact class of bug for their own queries, confirming the threat model is understood — but the fix was not applied to the graphql module.

### Recommendation
Apply the same `StatementInspector` pattern used in the importer to the graphql module:

1. Add a `GraphQlHibernateConfiguration` (mirroring `importer/src/main/java/org/hiero/mirror/importer/config/HibernateConfiguration.java`) that prepends `/* NO PGPOOL LOAD BALANCE */\n` to all SQL statements when load balancing is enabled.
2. Expose a `hiero.mirror.graphql.db.loadBalance` property (defaulting to `false`, matching the importer's safe default) to control this behavior.
3. Alternatively, annotate `EntityRepository.findByAlias()` with `@Transactional(readOnly = false)` routed explicitly to the primary, or use a JDBC URL that targets the primary directly for alias lookups.

### Proof of Concept
**Preconditions:**
- Mirror node deployed with pgpool and at least one read replica (default Helm chart).
- Account A (alias `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`) was recently deleted and Account B was created with the same alias. Replication lag exists (e.g., induced by pausing the replica or during a network partition).

**Steps:**
```bash
# Query the GraphQL endpoint while the replica is lagging
curl -X POST http://<mirror-node>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ account(input: { alias: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" }) { id balance key } }"}'
```

**Expected (correct):** Returns Account B's `id`, `balance`, `key`.

**Observed (vulnerable):** Returns Account A's `id`, `balance`, `key` — the deleted account's stale data — because the replica has not yet applied the `deleted = true` update for Account A. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** importer/src/main/java/org/hiero/mirror/importer/config/HibernateConfiguration.java (L19-35)
```java
    private static final String NO_LOAD_BALANCE = "/* NO PGPOOL LOAD BALANCE */\n";

    @Override
    public void customize(Map<String, Object> hibernateProperties) {
        if (!dbProperties.isLoadBalance()) {
            hibernateProperties.put(STATEMENT_INSPECTOR, statementInspector());
        }
    }

    /**
     * https://www.pgpool.net/docs/latest/en/html/runtime-config-load-balancing.html pgpool disables load balancing for
     * SQL statements beginning with an arbitrary comment and sends them to the primary node. This is used to prevent
     * the stale read-after-write issue.
     */
    private StatementInspector statementInspector() {
        return sql -> NO_LOAD_BALANCE + sql;
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L47-49)
```java
        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
        }
```
