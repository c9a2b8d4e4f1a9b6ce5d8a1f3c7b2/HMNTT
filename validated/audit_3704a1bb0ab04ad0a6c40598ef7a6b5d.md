All key claims are verified against the actual codebase. Here is the result:

---

Audit Report

## Title
`entityFromEvmAddressQuery` Missing `COALESCE` Silently Excludes Entities with `deleted = NULL`

## Summary
The SQL query `entityFromEvmAddressQuery` in `rest/service/entityService.js` filters with `deleted <> true` without wrapping the nullable column in `COALESCE`. In PostgreSQL's three-valued logic, `NULL <> true` evaluates to `NULL` (not `TRUE`), so any entity row where `deleted IS NULL` is silently excluded from results. The sibling query `entityFromAliasQuery` in the same file correctly uses `coalesce(deleted, false) <> true`. This causes valid, live entities to be unreachable via EVM address lookups.

## Finding Description

**Exact location — the vulnerable query:**

`rest/service/entityService.js`, lines 22–25: [1](#0-0) 

```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where ${Entity.DELETED} <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

**Correct sibling query for comparison:**

`rest/service/entityService.js`, lines 17–20: [2](#0-1) 

```js
static entityFromAliasQuery = `select ${Entity.ID}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ALIAS} = $1`;
```

**Root cause — `deleted` is explicitly nullable:**

Migration `V1.39.1__upsert_support.sql` drops both the `NOT NULL` constraint and the default value from the `deleted` column: [3](#0-2) 

```sql
alter table entity
    alter column deleted drop default,
    alter column deleted drop not null;
```

This means any entity that has never received an explicit delete/undelete update will have `deleted = NULL`. The comment in the migration itself confirms this is intentional: *"allow nullable on entity deleted as transaction cannot make this assumption on updates."*

**The `entity__evm_address` index is non-unique**, confirmed in `V1.58.6__ethereum_nonce.sql`: [4](#0-3) 

```sql
create index if not exists entity__evm_address on entity (evm_address) where evm_address is not null;
```

## Impact Explanation

**Primary impact — false 404 / denial of service:**
Any entity whose `deleted` column is `NULL` (the default state for newly created entities) is completely invisible to `getEntityIdFromEvmAddress()`. The function throws `NotFoundError` even though the entity is live and valid. [5](#0-4) 

**Secondary impact — wrong entity resolution (two-entity scenario):**
Because `entity__evm_address` is a non-unique index, two rows can share the same EVM address. The bulk insert in `V1.64.2__merge_contract_entity.sql` (migrating former `contract` rows into `entity`) is a concrete path that can produce this state. [6](#0-5) 

If Entity A has `deleted = false` and Entity B has `deleted = NULL` for the same EVM address, the query returns only Entity A — potentially the wrong entity — while Entity B is silently dropped.

## Likelihood Explanation

- `deleted = NULL` is the **default state** for any entity that has never been explicitly updated. No privileged access is required to trigger the bug — any user submitting a standard EVM address lookup (e.g., `GET /api/v1/accounts/0x<address>`) against such an entity will receive a false 404.
- The two-entity scenario requires an abnormal DB state (two rows with the same `evm_address`), but the schema explicitly permits it (non-unique index), and the `V1.64.2` migration provides a realistic historical path for it to occur.

## Recommendation

Apply `COALESCE` to the `deleted` column in `entityFromEvmAddressQuery`, matching the pattern already used in `entityFromAliasQuery`:

```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where coalesce(${Entity.DELETED}, false) <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

Also audit `EntityRepository.java` in the importer module, which has the same pattern (`deleted <> true` without `COALESCE`) in `findByAlias` and `findByEvmAddress`: [7](#0-6) 

## Proof of Concept

1. Insert an entity row with a known EVM address and `deleted = NULL` (the default — simply omit the `deleted` column on insert).
2. Call `GET /api/v1/accounts/0x<evm_address>`, which internally invokes `getEntityIdFromEvmAddress()`.
3. Observe a `404 NotFoundError` even though the entity exists and is not deleted.
4. Repeat the same lookup using the entity's `shard.realm.num` form — the entity is found normally, confirming it is live.
5. Fix: change the query to use `coalesce(deleted, false) <> true`. The lookup now succeeds.

### Citations

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** importer/src/main/resources/db/migration/v1/V1.39.1__upsert_support.sql (L6-8)
```sql
alter table entity
    alter column deleted drop default,
    alter column deleted drop not null;
```

**File:** importer/src/main/resources/db/migration/v1/V1.58.6__ethereum_nonce.sql (L9-9)
```sql
create index if not exists entity__evm_address on entity (evm_address) where evm_address is not null;
```

**File:** importer/src/main/resources/db/migration/v1/V1.64.2__merge_contract_entity.sql (L11-58)
```sql
insert
into entity (auto_renew_account_id,
             auto_renew_period,
             created_timestamp,
             decline_reward,
             deleted,
             evm_address,
             expiration_timestamp,
             id,
             key,
             max_automatic_token_associations,
             memo,
             num,
             obtainer_id,
             permanent_removal,
             proxy_account_id,
             public_key,
             realm,
             shard,
             staked_account_id,
             staked_node_id,
             stake_period_start,
             timestamp_range,
             type)
select auto_renew_account_id,
       auto_renew_period,
       created_timestamp,
       decline_reward,
       deleted,
       evm_address,
       expiration_timestamp,
       id,
       key,
       max_automatic_token_associations,
       memo,
       num,
       obtainer_id,
       permanent_removal,
       proxy_account_id,
       public_key,
       realm,
       shard,
       staked_account_id,
       staked_node_id,
       stake_period_start,
       timestamp_range,
       type
from contract;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L16-20)
```java
    @Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByAlias(byte[] alias);

    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```
