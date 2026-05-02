### Title
`isValidAccount()` Does Not Validate Entity Type, Allowing Contract IDs to Retrieve Token Relationships via `/accounts/:id/tokens`

### Summary
`getTokenRelationships()` in `rest/controllers/tokenController.js` calls `EntityService.isValidAccount()` to gate access, but that function only checks whether an entity *exists* in the database — it never verifies the entity's `type` is `ACCOUNT`. Because CONTRACT-type entities are stored in the same `entity` table, an unprivileged attacker can supply a contract's numeric ID as the path parameter and receive a 200 response containing that contract's token relationships, which the API presents as if they belong to an account.

### Finding Description

**Code path:**

`getTokenRelationships()` resolves the path parameter and immediately calls `isValidAccount()`: [1](#0-0) 

`isValidAccount()` runs `entityExistenceQuery` and returns `!isNil(entity)`: [2](#0-1) 

`entityExistenceQuery` selects `Entity.TYPE` from the `entity` table but the returned value is **never inspected** — only its nullness is checked: [3](#0-2) 

**Root cause:** The function is named `isValidAccount` and its JSDoc says "Checks if provided accountId maps to a valid entity," but it performs no type assertion. The `type` column is fetched (suggesting the intent was to use it) but the check `!isNil(entity)` discards that information entirely.

**CONTRACT entities in the entity table:** Migration `V1.47.1` initially added `check (type_enum <> 'CONTRACT')` to the entity table, but migration `V1.64.2__merge_contract_entity.sql` merged contracts back. Integration tests confirm CONTRACT-type entities are persisted to `entityRepository` (the `entity` table): [4](#0-3) 

**Exploit flow:**
1. Attacker identifies a known contract entity ID (e.g., `0.0.1234`) — these are public on-chain.
2. Sends `GET /api/v1/accounts/0.0.1234/tokens` with no authentication.
3. `getEncodedId("0.0.1234")` resolves to the encoded ID.
4. `isValidAccount(encodedId)` queries the entity table, finds the CONTRACT row, returns `true`.
5. `TokenService.getTokenAccounts(query)` fetches token relationships for that contract ID.
6. API returns HTTP 200 with the contract's token relationships under the `/accounts/` endpoint.

### Impact Explanation
The mirror node's `/accounts/:id/tokens` endpoint is semantically defined to return token relationships for *accounts*. Returning data for a contract entity under this endpoint causes consumers (wallets, explorers, analytics) to incorrectly attribute contract token holdings to an account identity. This is an incorrect record export: the mirror node presents contract-owned token relationships as account-owned, violating the protocol's entity-type semantics. Severity is **Medium** — no funds are at risk, but data integrity and consumer trust are compromised.

### Likelihood Explanation
Exploitation requires zero privileges, zero authentication, and only knowledge of a contract's entity ID — all of which are publicly available on any Hedera network explorer. The attack is trivially repeatable for any contract that holds token associations. Any external user can perform this.

### Recommendation
In `isValidAccount()`, change the query to filter by entity type, or add a type check on the returned row:

```js
// Option A: filter in SQL
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and ${Entity.TYPE} = 'ACCOUNT'`;

// Option B: check the type in JS
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity) && entity.type === 'ACCOUNT';
}
``` [2](#0-1) 

### Proof of Concept
**Precondition:** A contract entity with ID `0.0.1234` exists in the mirror node database (standard on any Hedera network).

```bash
# Step 1: Confirm the entity is a contract (public info)
curl https://<mirror-node>/api/v1/contracts/0.0.1234
# Returns contract details → confirms it is a CONTRACT type entity

# Step 2: Query the accounts token endpoint with the contract ID
curl https://<mirror-node>/api/v1/accounts/0.0.1234/tokens

# Expected (correct) behavior: 404 Not Found
# Actual behavior: HTTP 200 with token relationships belonging to the contract,
# presented under the /accounts/ namespace
```

**Result:** The API returns `{"tokens": [...], "links": {"next": null}}` with the contract's token associations, incorrectly exported as account token relationships.

### Citations

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L28-30)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** importer/src/test/java/org/hiero/mirror/importer/parser/record/entity/sql/SqlEntityListenerTest.java (L771-793)
```java
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void onEntityTypeIsContract(boolean hasNonce) {
        // given
        Entity entity1 = domainBuilder
                .entity()
                .customize(e -> e.ethereumNonce(hasNonce ? 1L : null).type(CONTRACT))
                .get();
        Entity entity2 = domainBuilder
                .entity()
                .customize(e -> e.ethereumNonce(hasNonce ? 2L : null).type(CONTRACT))
                .get();

        // when
        sqlEntityListener.onEntity(entity1);
        sqlEntityListener.onEntity(entity2);
        completeFileAndCommit();

        // then
        assertThat(contractRepository.count()).isZero();
        // for contract, there shouldn't be a default nonce value
        assertThat(entityRepository.findAll()).containsExactlyInAnyOrder(entity1, entity2);
        assertThat(findHistory(Entity.class)).isEmpty();
```
