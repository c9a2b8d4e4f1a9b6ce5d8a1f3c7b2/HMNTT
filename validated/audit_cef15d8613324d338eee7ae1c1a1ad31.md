The code has been verified against the claim. All referenced lines, logic, and repository methods match exactly.

**Verification summary:**

- `EntityServiceImpl.java` line 38: `entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type)` — no deleted check. [1](#0-0) 
- `EntityRepository.java`: both custom queries carry `deleted is not true`; `findById` is inherited from `CrudRepository` with no such predicate. [2](#0-1) 
- `AbstractEntity` confirms the `deleted` field exists and is set to `true` on deletion. [3](#0-2) 
- Nothing in `SECURITY.md` places this finding out of scope. [4](#0-3) 

---

Audit Report

## Title
Deleted Entity Bypass via Long-Zero EVM Address in GraphQL `getByEvmAddressAndType`

## Summary
`EntityServiceImpl.getByEvmAddressAndType()` routes long-zero EVM addresses (bytes 0–11 all zero, bytes 12–19 = entity ID) to `entityRepository.findById()`, which is the raw Spring Data `CrudRepository.findById()` carrying no `deleted is not true` SQL predicate. The two custom query methods `findByEvmAddress` and `findByAlias` both filter out deleted rows at the SQL level, but `findById` does not. Any unauthenticated caller can therefore resolve a deleted (destroyed) smart contract or account entity through the GraphQL API by supplying its long-zero address.

## Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {   // bytes 0–11 == 0
        return entityRepository.findById(buffer.getLong()) // bytes 12–19 = entity ID
                               .filter(e -> e.getType() == type); // type only, no deleted check
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)  // has "deleted is not true"
                           .filter(e -> e.getType() == type);
}
``` [1](#0-0) 

**Root cause:**

`EntityRepository` extends `CrudRepository<Entity, Long>` and defines only two custom queries, both with `deleted is not true`:

```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);

@Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByEvmAddress(byte[] evmAddress);
``` [2](#0-1) 

`findById` is inherited from `CrudRepository` and issues a plain `SELECT * FROM entity WHERE id = ?` — no `deleted` predicate. The only post-fetch guard on the long-zero path is `.filter(e -> e.getType() == type)`, which passes for a deleted contract because the `type` column is not cleared on deletion.

Note: `getByIdAndType` at line 25 has the identical gap — it also calls `findById` with no deleted filter — but the long-zero EVM address path is the externally reachable vector via the public GraphQL API. [5](#0-4) 

## Impact Explanation
Any consumer of the GraphQL API (dApps, wallets, indexers) that queries a contract or account by its long-zero EVM address will receive a non-empty response for a destroyed/deleted entity, making it appear active. This violates the integrity of contract-state data served by the mirror node and can cause callers to believe a contract is live when it has been self-destructed, leading to incorrect application logic, erroneous UI state, or downstream protocol decisions based on stale metadata. No funds are directly at risk, but the data integrity guarantee of the API is broken.

## Likelihood Explanation
The GraphQL endpoint is unauthenticated and public. The attacker only needs the numeric entity ID of a deleted contract, which is public information (entity IDs are sequential and visible in block explorers). The long-zero address is deterministically constructed and the exploit is trivially repeatable for any deleted entity.

## Recommendation
Add a `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` guard on the `findById` branch, consistent with the SQL-level protection already present in `findByEvmAddress` and `findByAlias`:

```java
if (buffer.getInt() == 0 && buffer.getLong() == 0) {
    return entityRepository.findById(buffer.getLong())
            .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
            .filter(e -> e.getType() == type);
}
```

Alternatively, add a custom `findByIdAndDeletedIsNotTrue` query to `EntityRepository` (mirroring the pattern already used in the `web3` module's `EntityRepository`) and use it on both the long-zero path and in `getByIdAndType`. [6](#0-5) 

## Proof of Concept
1. A smart contract with Hedera entity ID `N` is destroyed on-chain; the mirror node sets `deleted = true` for that row.
2. Construct the long-zero EVM address: `0x` + 12 zero bytes + big-endian 8-byte encoding of `N` (e.g., entity 1234 → `0x0000000000000000000000000000000000000004D2`).
3. Send the GraphQL query:
   ```graphql
   { contract(input: { evmAddress: "0x0000000000000000000000000000000000000004D2" }) { contractId deleted } }
   ```
4. `decodeEvmAddress` returns the 20-byte array; `buffer.getInt()` reads bytes 0–3 = 0, `buffer.getLong()` reads bytes 4–11 = 0 → long-zero branch taken.
5. `entityRepository.findById(1234)` executes `SELECT * FROM entity WHERE id = 1234` — returns the deleted row.
6. `.filter(e -> e.getType() == CONTRACT)` passes because `type` is still `CONTRACT`.
7. The GraphQL response returns the deleted contract as if it were active.

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

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```
