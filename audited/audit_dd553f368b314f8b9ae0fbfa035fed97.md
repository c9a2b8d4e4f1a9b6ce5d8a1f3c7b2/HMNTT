### Title
Missing Deleted-Entity Filter in `getByEvmAddressAndType` Long-Zero EVM Address Path

### Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, when the supplied EVM address is a "long-zero" address (first 12 bytes all zero, last 8 bytes encode an entity num), the code falls through to `entityRepository.findById()` — a standard Spring Data `CrudRepository` method that carries no `deleted` filter. Unlike the custom `findByAlias` and `findByEvmAddress` queries, which both explicitly include `deleted is not true`, `findById` returns any entity regardless of deletion status. Any unauthenticated caller can therefore retrieve deleted entity records by supplying sequential long-zero EVM addresses to the public GraphQL endpoint.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 all zero → long-zero path
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 = entity num; NO deleted filter
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)      // has "deleted is not true"
                           .filter(e -> e.getType() == type);
}
``` [1](#0-0) 

**Root cause:** `findById` is the bare Spring Data `CrudRepository<Entity, Long>` method. The graphql-module `EntityRepository` defines only two custom queries, both with `deleted is not true`:

```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);

@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
``` [2](#0-1) 

`findById` is never overridden with a deleted filter, so it executes a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` predicate.

**Exploit flow:**
1. Attacker identifies the public GraphQL endpoint (no authentication required — `AccountController` applies no access control).
2. Attacker constructs a long-zero EVM address: 12 zero bytes followed by the 8-byte big-endian encoding of a target entity num, e.g. `0x0000000000000000000000000000000000000001` for entity num 1.
3. The `buffer.getInt() == 0 && buffer.getLong() == 0` check passes, routing to `findById`.
4. `findById` returns the entity row regardless of `deleted = true`.
5. The only post-fetch filter is `e.getType() == type`, which checks entity type (ACCOUNT, CONTRACT, etc.) but not deletion status.
6. The deleted entity is serialized and returned in the GraphQL response. [3](#0-2) 

**Why existing checks are insufficient:** The `filter(e -> e.getType() == type)` guard only enforces entity-type matching. It does not check `e.getDeleted()`. The `findByAlias` and `findByEvmAddress` paths correctly filter at the SQL level, but the `findById` path has no equivalent guard at either the SQL or Java level. [4](#0-3) 

### Impact Explanation
Any deleted account or contract entity stored in the mirror node database can be retrieved in full (all fields, including key material, memo, balance history references, etc.) by an unprivileged external user. This violates the mirror node's stated data-export policy of not surfacing deleted entities and may expose sensitive metadata about entities that network participants intended to remove from public view.

### Likelihood Explanation
The attack requires zero privileges and zero prior knowledge beyond the public GraphQL schema. Entity nums are sequential integers starting from 1, making enumeration trivial with a simple loop. The GraphQL endpoint is publicly reachable by design. The exploit is fully repeatable and automatable.

### Recommendation
Replace the bare `findById` call in the long-zero branch with a custom repository method that includes the `deleted is not true` predicate, for example:

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

Then update `getByEvmAddressAndType` (and the identical issue in `getByIdAndType`) to call this method instead of `findById`.

### Proof of Concept
```graphql
# Entity num 12345 was deleted. Craft its long-zero EVM address:
# 0x0000000000000000000000000000000000003039  (0x3039 = 12345 decimal)

query {
  account(input: { evmAddress: "0x0000000000000000000000000000000000003039" }) {
    entityId { shard realm num }
    deleted
    memo
    key
  }
}
```

Expected (correct) behavior: empty/null response.
Actual behavior: full entity record returned with `deleted: true` and all fields populated.

Enumerate by incrementing the last 8 bytes of the address to scan all entity nums.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-17)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```
