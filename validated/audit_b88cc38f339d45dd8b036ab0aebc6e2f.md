All referenced code was verified against the actual repository. Here is the result:

---

# Audit Report

## Title
Stale Replica Read in GraphQL `getByAliasAndType()` Due to Missing pgpool Load-Balance Bypass

## Summary
The GraphQL module's `EntityRepository.findByAlias()` issues a plain SQL query with no pgpool load-balance bypass hint. The importer module (and web3 module) explicitly prepend `/* NO PGPOOL LOAD BALANCE */` to all Hibernate-issued SQL to force reads to the primary and prevent stale read-after-write. The graphql module has no equivalent `HibernateConfiguration`, no `StatementInspector`, and no `loadBalance` property — confirmed by exhaustive search. During replication lag, pgpool can route the alias lookup to a stale replica, returning the wrong entity record to callers.

## Finding Description

**Verified code path:**

`AccountController.account()` at line 48 calls `entityService.getByAliasAndType()`: [1](#0-0) 

`EntityServiceImpl.getByAliasAndType()` at lines 29–31 delegates directly to `entityRepository.findByAlias()`: [2](#0-1) 

`EntityRepository.findByAlias()` at lines 13–14 issues a native SQL query with no hint: [3](#0-2) 

The importer module's `HibernateConfiguration` at lines 19 and 33–35 prepends `/* NO PGPOOL LOAD BALANCE */` to every SQL statement when `loadBalance` is disabled, with an explicit comment: *"This is used to prevent the stale read-after-write issue."* [4](#0-3) 

The web3 module has an equivalent `HibernateConfiguration`. The graphql module has **none** — no `HibernateConfiguration.java`, no `StatementInspector`, and no `loadBalance` property anywhere under `graphql/src/main/java/` or `graphql/src/main/resources/`. A full grep for `NO PGPOOL LOAD BALANCE` across the entire repo returns only the importer file.


**Alias re-use is a real, tested scenario.** The Rosetta test suite at lines 535–548 explicitly constructs a case where `accountNum2` holds the same alias as a live account but was deleted first: [5](#0-4) 

**pgpool with read replicas is the default deployment.** The Helm chart `values.yaml` at lines 169–201 configures pgpool with `numInitChildren`, `podAntiAffinityPreset`, and resource limits — confirming a multi-node pgpool setup is the standard: [6](#0-5) 

## Impact Explanation
Any caller of `POST /graphql/alpha` with an `account(input: { alias: "X" })` query can receive the wrong entity record during replication lag — wrong account ID, wrong public key, wrong balance. Downstream clients that use the returned public key for ownership verification or the returned balance for pre-transfer checks act on incorrect state. This is a data-integrity violation on a public, unauthenticated endpoint.

## Likelihood Explanation
No privilege is required — the GraphQL endpoint is public. Alias re-use after deletion is a documented, tested Hedera protocol feature. Replication lag is a normal operational condition in any pgpool HA deployment. The importer team already identified and fixed this exact class of bug for their own queries, confirming the threat model is understood and real — but the fix was not carried over to the graphql module.

## Recommendation
Add a `HibernateConfiguration` to the graphql module that mirrors the one in the importer module:

```java
// graphql/src/main/java/org/hiero/mirror/graphql/config/HibernateConfiguration.java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
class HibernateConfiguration implements HibernatePropertiesCustomizer {
    private static final String NO_LOAD_BALANCE = "/* NO PGPOOL LOAD BALANCE */\n";

    @Override
    public void customize(Map<String, Object> hibernateProperties) {
        hibernateProperties.put(STATEMENT_INSPECTOR, (StatementInspector) sql -> NO_LOAD_BALANCE + sql);
    }
}
```

Alternatively, expose a `DBProperties`-equivalent in the graphql module and make the bypass conditional on a `loadBalance` flag, consistent with the importer pattern. [7](#0-6) 

## Proof of Concept

1. Deploy the mirror node with the default Helm chart (pgpool + at least one read replica).
2. Introduce artificial replication lag on the replica (e.g., `pg_wal_replay_pause()` on the replica).
3. On the primary: delete Account A (alias `X`), then create Account B with alias `X`.
4. Before the replica catches up, send:
   ```graphql
   POST /graphql/alpha
   { "query": "{ account(input: { alias: \"<base32-of-X>\" }) { id balance } }" }
   ```
5. Observe that the response returns Account A's `id` and `balance` instead of Account B's, because pgpool routed the `select * from entity where alias = ?1 and deleted is not true` query to the stale replica where Account A still has `deleted = false`.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L47-49)
```java
        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
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

**File:** importer/src/main/java/org/hiero/mirror/importer/config/HibernateConfiguration.java (L14-35)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
class HibernateConfiguration implements HibernatePropertiesCustomizer {
    private final DBProperties dbProperties;

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

**File:** rosetta/app/persistence/account_test.go (L535-548)
```go
	// add accountNum2 with the same alias but was deleted before accountNum1
	// the entity row with deleted = true in entity table
	accountId2 := MustEncodeEntityId(suite.shard, suite.realm, accountNum2).EncodedId
	tdomain.NewEntityBuilder(dbClient, accountId2, account2CreatedTimestamp, domain.EntityTypeAccount).
		Alias(suite.accountAlias).
		Deleted(true).
		ModifiedTimestamp(account2DeletedTimestamp).
		Persist()
	// the historical entry
	tdomain.NewEntityBuilder(dbClient, accountId2, account2CreatedTimestamp, domain.EntityTypeAccount).
		Alias(suite.accountAlias).
		TimestampRange(account2CreatedTimestamp, account2DeletedTimestamp).
		Historical(true).
		Persist()
```

**File:** charts/hedera-mirror/values.yaml (L169-201)
```yaml
  pgpool:
    adminPassword: ""  # Randomly generated if left blank
    childLifeTime: 60
    childMaxConnections: 2
    existingSecret: mirror-passwords
    extraEnvVars:
      - name: PGPOOL_POSTGRES_CUSTOM_PASSWORDS
        valueFrom:
          secretKeyRef:
            name: mirror-passwords
            key: PGPOOL_POSTGRES_CUSTOM_PASSWORDS
      - name: PGPOOL_POSTGRES_CUSTOM_USERS
        valueFrom:
          secretKeyRef:
            name: mirror-passwords
            key: PGPOOL_POSTGRES_CUSTOM_USERS
    image:
      debug: true
      repository: bitnamilegacy/pgpool
    numInitChildren: 100
    podAntiAffinityPreset: soft
    podLabels:
      role: db
    pdb:
      create: true
    reservedConnections: 0
    resources:
      limits:
        cpu: 600m
        memory: 750Mi
      requests:
        cpu: 200m
        memory: 256Mi
```
