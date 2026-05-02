### Title
Deleted Entity Full Record Disclosed via Numeric ID Lookup in GraphQL API

### Summary
`EntityServiceImpl.getByIdAndType()` calls the inherited `CrudRepository.findById()` which issues a plain `SELECT * FROM entity WHERE id = ?` with no `deleted` filter. The two custom repository methods `findByAlias` and `findByEvmAddress` both explicitly include `AND deleted is not true`, so the same deleted entity is hidden by those paths but fully returned by the numeric-ID path. Any unauthenticated user can reach this code through the public GraphQL endpoint.

### Finding Description
**Exact code path:**

- `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` lines 13–17: both custom queries carry `deleted is not true`.
- `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java` line 25: `entityRepository.findById(entityId.getId())` — no deleted filter, no post-fetch check on the `deleted` field.
- `graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java` lines 41–44: when the caller supplies `entityId`, the controller routes directly to `getByIdAndType`, which calls the unfiltered `findById`.
- The GraphQL schema (`query.graphqls`) exposes `account(input: AccountInput!)` with no authentication guard; the endpoint is `/graphql/alpha`.

**Root cause:** The developer added `deleted is not true` to the two custom JPQL/native queries but forgot to add the same guard to the ID-based lookup, which relies on the Spring Data `CrudRepository.findById()` default that generates an unfiltered `SELECT`.

**Why existing checks fail:** The only post-fetch filter in `getByIdAndType` is `.filter(e -> e.getType() == type)` (type check only). There is no `.filter(e -> !Boolean.TRUE.equals(e.getDeleted()))` step. The alias and EVM-address paths never reach `findById`; they call the custom queries that do filter.

### Impact Explanation
A deleted account's full record — including its admin `key` (cryptographic key structure), last-known `balance`, `memo`, `alias`, `evmAddress`, `obtainer`, `timestamp` range, and all other fields defined in `account.graphqls` — is returned to any caller who knows or can enumerate the numeric entity ID. Hedera entity IDs are sequential integers, making enumeration trivial. The design intent is clearly to suppress deleted entities (evidenced by the filters on the other two paths), so this constitutes an unintended information-disclosure inconsistency. The `key` field is the most sensitive: it reveals the signing-key topology of an account that the owner may have considered "gone."

### Likelihood Explanation
Exploitation requires zero privileges, zero authentication, and only knowledge of a numeric entity ID (publicly derivable from any Hedera explorer or by sequential scan). The GraphQL endpoint is HTTP POST to `/graphql/alpha` with a trivial query body. The attack is fully repeatable and automatable.

### Recommendation
Add a `deleted` filter to the ID-based lookup in `EntityServiceImpl`, mirroring the pattern already used by the custom queries:

```java
// EntityServiceImpl.java line 25 — replace:
return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);

// with:
return entityRepository.findById(entityId.getId())
        .filter(e -> !Boolean.TRUE.equals(e.getDeleted()))
        .filter(e -> e.getType() == type);
```

Alternatively, add a dedicated repository method with the filter baked into the query (consistent with `findByAlias`/`findByEvmAddress`):

```java
@Query(value = "select * from entity where id = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByIdAndNotDeleted(Long id);
```

The same fix must be applied to the `getByEvmAddressAndType` branch that falls through to `findById` (line 38 of `EntityServiceImpl`) when the EVM address encodes a plain numeric ID.

### Proof of Concept
**Precondition:** entity with numeric ID `12345` exists in the mirror node database with `deleted = true`.

**Trigger:**
```http
POST /graphql/alpha HTTP/1.1
Content-Type: application/json

{
  "query": "{ account(input: { entityId: { shard: 0, realm: 0, num: 12345 } }) { deleted balance key memo alias evmAddress timestamp { from to } } }"
}
```

**Expected (correct) result:** `"account": null`

**Actual result:** Full entity record returned, e.g.:
```json
{
  "data": {
    "account": {
      "deleted": true,
      "balance": 500000000,
      "key": { ... },
      "memo": "sensitive memo",
      "alias": "ABCDE...",
      "evmAddress": "0xabc...",
      "timestamp": { "from": "...", "to": "..." }
    }
  }
}
```

**Contrast:** the same entity queried by alias or EVM address returns `"account": null`, confirming the inconsistency.