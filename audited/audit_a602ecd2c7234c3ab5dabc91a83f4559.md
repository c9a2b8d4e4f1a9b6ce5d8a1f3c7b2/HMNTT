### Title
Missing Entity Type Validation in `getAccountTokenAllowances` Allows Querying Token Allowances for Non-Account Entities

### Summary
`TokenAllowanceController.getAccountTokenAllowances()` calls `EntityService.getEncodedId()` to resolve the path parameter but never calls `EntityService.isValidAccount()` to verify the resolved entity exists, unlike `TokenController.getTokenRelationships()` which does perform this check. For numeric entity IDs (e.g., `0.0.12345`), `getEncodedId()` performs no database lookup at all — it simply parses and returns the encoded ID — meaning any entity ID belonging to a `CONTRACT` or `TOKEN` type passes through unchallenged and its token allowance records are returned.

### Finding Description

**Code path:**

`rest/controllers/tokenAllowanceController.js`, `getAccountTokenAllowances()`, line 69: [1](#0-0) 

The controller calls only `EntityService.getEncodedId()` and immediately proceeds to query allowances. Compare with `TokenController.getTokenRelationships()`: [2](#0-1) 

`TokenController` calls `isValidAccount()` after `getEncodedId()`; `TokenAllowanceController` does not.

**Root cause — `getEncodedId()` for numeric IDs performs zero DB lookup:** [3](#0-2) 

When `evmAddress === null` (i.e., a plain `shard.realm.num` or encoded numeric ID), the method returns `entityId.getEncodedId()` directly with no database round-trip and no type check. Any numeric entity ID — account, contract, or token — is accepted.

**Secondary issue — `isValidAccount()` does not actually check entity type:** [4](#0-3) 

Despite selecting the `type` column, `isValidAccount()` only checks `!isNil(entity)` (existence), not whether `entity.type === 'ACCOUNT'`. So even if `TokenAllowanceController` called it, it would not block CONTRACT or TOKEN entities.

**Query executed against the DB:** [5](#0-4) 

The `owner = $1` condition uses whatever encoded ID was resolved — no entity-type filter is applied at the SQL level either.

### Impact Explanation

An unprivileged external caller can supply the numeric ID of any `CONTRACT` or `TOKEN` entity to `GET /api/v1/accounts/{contractId}/allowances/tokens` and receive all token allowance records stored for that entity (spender, token ID, approved amount). These records are stored in the `token_allowance` table keyed only by `owner`, with no type guard. While the underlying data is on-chain and technically public, the accounts endpoint is semantically scoped to `ACCOUNT` entities; surfacing contract allowances through it violates the intended access model and can expose allowance relationships that operators or integrators do not expect to be reachable via this path.

### Likelihood Explanation

Exploitation requires no credentials, no special network position, and no prior knowledge beyond knowing a contract's entity ID (which is trivially discoverable from any block explorer or the mirror node's own `/contracts` endpoint). The attack is fully repeatable and automatable. Any public-facing mirror node deployment is affected.

### Recommendation

In `getAccountTokenAllowances()`, add an existence-and-type check immediately after resolving the ID. Because `isValidAccount()` currently only checks existence (not type), it must be extended to also assert `entity.type === 'ACCOUNT'`, or a new dedicated helper (e.g., `assertAccountType()`) should be introduced. The fix should mirror the pattern in `TokenController` but with the corrected type assertion:

```js
// After: const accountId = await EntityService.getEncodedId(...)
const isValid = await EntityService.isValidAccount(accountId); // extend to check type
if (!isValid) throw new NotFoundError();
```

Additionally, fix `isValidAccount()` to return `false` (or throw) when the entity's `type` is not `ACCOUNT`.

### Proof of Concept

**Preconditions:**
- A Hiero mirror node is running with its REST API accessible.
- A `CONTRACT` entity with ID `0.0.5000` exists in the `entity` table and has one or more rows in `token_allowance` where `owner = <encoded id of 0.0.5000>`.

**Steps:**
1. Send an unauthenticated HTTP GET request:
   ```
   GET /api/v1/accounts/0.0.5000/allowances/tokens
   ```
2. `getEncodedId("0.0.5000")` parses the string, finds `evmAddress === null`, and returns the encoded ID without any DB lookup.
3. No `isValidAccount()` call is made.
4. `TokenAllowanceService.getAccountTokenAllowances()` executes `SELECT * FROM token_allowance WHERE owner = $1 AND amount > 0` with the contract's encoded ID.
5. The response contains the contract's token allowance records (spender IDs, token IDs, approved amounts) — data that should not be reachable via the `/accounts/` endpoint.

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L68-72)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
```

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/entityService.js (L120-124)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/service/tokenAllowanceService.js (L56-57)
```javascript
    const params = [ownerAccountId, limit];
    const accountIdCondition = `${TokenAllowance.OWNER} = $1`;
```
