The code is confirmed. All claims check out against the actual source:

- `getByEvmAddressAndType` long-zero branch calls `entityRepository.findById()` with no `deleted` filter. [1](#0-0) 
- `findByEvmAddress` explicitly enforces `deleted is not true` in SQL. [2](#0-1) 
- `deleted` field exists on `AbstractEntity`. [3](#0-2) 
- `AccountController` routes `evmAddress` input directly to `getByEvmAddressAndType`. [4](#0-3) 

---

Audit Report

## Title
Deleted Entity Returned via Long-Zero EVM Address in `getByEvmAddressAndType()`

## Summary
In `EntityServiceImpl.getByEvmAddressAndType()`, the long-zero EVM address path dispatches to `entityRepository.findById()`, which has no `deleted` filter. The non-long-zero path dispatches to `entityRepository.findByEvmAddress()`, which enforces `deleted is not true` in SQL. Any caller can craft a long-zero address encoding a deleted account's numeric ID and receive the deleted entity as a non-null result.

## Finding Description
In `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java` lines 34–41:

```java
@Override
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {
        // NO deleted filter — plain CrudRepository.findById()
        return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
    }
    // deleted is not true enforced in SQL
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
``` [5](#0-4) 

`EntityRepository` defines:

```java
@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
// findById() — inherited from CrudRepository<Entity, Long>, no deleted predicate
``` [6](#0-5) 

The only post-fetch guard on the long-zero path is `.filter(e -> e.getType() == type)` — a type check, not a deletion check. The `deleted` field (`Boolean deleted`) exists on `AbstractEntity` and is populated from the database. [3](#0-2) 

**Exploit flow:**
1. Identify a deleted account with numeric ID, e.g., `12345`.
2. Construct long-zero EVM address: `0x0000000000000000000000000000000000003039`.
3. Submit GraphQL query to the public `/graphql/alpha` endpoint:
   ```graphql
   { account(input: { evmAddress: "0x0000000000000000000000000000000000003039" }) {
       deleted entityId { num } balance key
   }}
   ```
4. `AccountController.account()` calls `entityService.getByEvmAddressAndType(evmAddress, ACCOUNT)`. [4](#0-3) 
5. Long-zero pattern detected; `entityRepository.findById(12345)` executes `SELECT * FROM entity WHERE id = 12345` — no `deleted` predicate.
6. Deleted entity row is returned; `.filter(e -> e.getType() == type)` passes.
7. Deleted entity is returned to the caller as a non-null result.

## Impact Explanation
The GraphQL API is a public read-only mirror node interface used by wallets, dApps, and integrations to resolve EVM addresses to Hedera account data. Returning a deleted account as a non-null result creates a behavioral inconsistency: callers that do not explicitly inspect the optional `deleted` field will treat the account as active. This can cause wallets or dApps to display deleted accounts as valid recipients, and smart contract tooling or bridges that use the mirror node to resolve addresses before constructing transactions may route calls to deleted accounts. The inconsistency between the two lookup paths (long-zero returns deleted entities; regular EVM address does not) violates the API contract and creates unpredictable behavior for any caller using both paths.

## Likelihood Explanation
- No privileges required. The `/graphql/alpha` endpoint is publicly accessible.
- Trivial to craft. The long-zero address format is a well-known Hedera convention; encoding any numeric ID into the last 8 bytes of a 20-byte zero-padded address is a one-line operation.
- Deleted account IDs are discoverable via the mirror node's own REST API, which exposes historical account data including deleted accounts.
- Deterministic and repeatable: every long-zero address encoding a deleted account's ID will return that account.

## Recommendation
Add a `deleted` filter to the long-zero path in `getByEvmAddressAndType()`, consistent with the `findByEvmAddress` path:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
        .filter(e -> e.getType() == type);
}
```

Alternatively, introduce a dedicated repository method `findByIdAndNotDeleted(Long id)` with a native query mirroring the `deleted is not true` predicate used by `findByEvmAddress` and `findByAlias`, and use it consistently across all lookup paths that should exclude deleted entities.

Note: `getByIdAndType()` at line 25 uses the same `findById()` call without a deleted filter — review whether that path also requires the same fix. [7](#0-6) 

## Proof of Concept
```graphql
# Step 1: Find a deleted account ID via REST API (e.g., ID 12345)
# GET /api/v1/accounts?deleted=true

# Step 2: Encode as long-zero EVM address
# 12345 decimal = 0x3039 hex
# Address: 0x0000000000000000000000000000000000003039

# Step 3: Query GraphQL
{
  account(input: { evmAddress: "0x0000000000000000000000000000000000003039" }) {
    deleted
    entityId { num }
    balance
    key
  }
}

# Expected (correct): null result
# Actual (buggy): returns the deleted entity with deleted=true and all fields populated
```

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-25)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/AbstractEntity.java (L64-64)
```java
    private Boolean deleted;
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-54)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
```
