### Title
Soft-Deleted Entity Data Exposed via Numeric ID Lookup in GraphQL API

### Summary
`EntityServiceImpl.getByIdAndType()` uses Spring Data's `CrudRepository.findById()`, which performs no filtering on the `deleted` column. Unlike `findByAlias()` and `findByEvmAddress()` — both of which include `deleted is not true` in their SQL — `findById()` returns soft-deleted entities unconditionally. Any unauthenticated external user can query the public GraphQL endpoint with a numeric entity ID to retrieve full account data for deleted accounts.

### Finding Description
**Exact code path:**

`AccountController.account()` (line 41–44) dispatches to `EntityServiceImpl.getByIdAndType()` when `entityId` is supplied: [1](#0-0) 

`getByIdAndType()` calls the bare Spring Data `findById()`: [2](#0-1) 

`findById()` is inherited from `CrudRepository<Entity, Long>` and issues a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate. By contrast, the custom queries in the same repository explicitly guard against deleted rows: [3](#0-2) 

**Secondary occurrence:** `getByEvmAddressAndType()` also falls back to `findById()` (without deleted filtering) when the supplied EVM address is a long-zero address: [4](#0-3) 

**Why the type-check does not help:** The `.filter(e -> e.getType() == type)` call only filters by entity type, not by deletion status. A deleted `ACCOUNT` entity still passes this filter and is returned to the caller. [5](#0-4) 

### Impact Explanation
The GraphQL `account` query is publicly accessible at `/graphql/alpha` with no authentication requirement. A successful query returns the full `Account` object including `alias`, `key`, `memo`, `balance`, `deleted`, `createdTimestamp`, `expirationTimestamp`, and all staking/reward fields. This constitutes information disclosure of account data that the network has marked as deleted and that the system's own alias/EVM-address lookup paths deliberately suppress. [6](#0-5) 

### Likelihood Explanation
Preconditions are minimal: the attacker needs only a numeric account ID (publicly observable on-chain or via the REST API) and the ability to send an HTTP POST to the GraphQL endpoint. No credentials, tokens, or special network access are required. The exploit is trivially repeatable and scriptable.

### Recommendation
Replace the bare `findById()` call with a custom repository method that includes the `deleted is not true` predicate, consistent with the existing `findByAlias` and `findByEvmAddress` methods. For example, add to `EntityRepository`:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then update both call sites in `EntityServiceImpl`:
- Line 25: `getByIdAndType()` 
- Line 38: the long-zero EVM address fallback in `getByEvmAddressAndType()` [7](#0-6) 

### Proof of Concept
1. Identify a deleted account's numeric ID (e.g., `num: 1234`) — observable via the Hedera REST API or mirror node history.
2. Send the following GraphQL request to the public endpoint:

```http
POST /graphql/alpha HTTP/1.1
Content-Type: application/json

{
  "query": "{ account(input: { entityId: { shard: 0, realm: 0, num: 1234 } }) { deleted alias key memo balance createdTimestamp } }"
}
```

3. The response returns the full account object with `deleted: true` and all associated sensitive fields, whereas the same account queried by alias or EVM address would return `null`. [8](#0-7)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L41-44)
```java
        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-41)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }

    @Override
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }

    @Override
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/resources/graphql/query.graphqls (L1-6)
```text
"""
The query root of the GraphQL API
"""
type Query {
    account(input: AccountInput!): Account
}
```
