### Title
Account Existence Oracle via Differential HTTP Response on Staking Rewards Endpoint

### Summary
The `/api/v1/accounts/{id}/rewards` endpoint in `listStakingRewardsByAccountId()` returns HTTP 404 for account IDs absent from the `entity` table and HTTP 200 with an empty rewards array for accounts that exist but have no rewards. Because the endpoint is unauthenticated and has no rate limiting, any external user can enumerate which numeric account IDs exist in the `entity` table by observing this status-code difference.

### Finding Description
**Exact code path:**

In `rest/controllers/accountController.js` lines 170–175, `listStakingRewardsByAccountId` calls `EntityService.isValidAccount(accountId)` and throws `NotFoundError` (→ HTTP 404) only when the account is absent:

```js
// rest/controllers/accountController.js:170-175
listStakingRewardsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[...]);
  const isValidAccount = await EntityService.isValidAccount(accountId);
  if (!isValidAccount) {
    throw new NotFoundError();   // → HTTP 404
  }
  // ... returns HTTP 200 with rewards:[] when account exists but has no rewards
```

`EntityService.isValidAccount` in `rest/service/entityService.js` lines 60–63 executes:

```sql
select type from entity where id = $1
```

No filter on `deleted`, no filter on entity type. Any row present → `true` → HTTP 200; no row → `false` → HTTP 404.

**Root cause / failed assumption:** The design assumes the 404/200 distinction is harmless because account IDs are "public". In practice, the `entity` table contains all entities (accounts, contracts, tokens, topics, files). The differential response leaks the precise set of numeric IDs that have ever been assigned, including deleted entities (the query has no `deleted <> true` guard, unlike `entityFromAliasQuery` which does).

**Why existing checks fail:** The auth middleware (`rest/middleware/authHandler.js` lines 15–19) is entirely optional — if no `Authorization` header is sent, the handler returns immediately without blocking the request. No rate-limiting middleware is applied to this route. The endpoint is fully public.

### Impact Explanation
An attacker can enumerate the complete set of entity IDs present in the mirror node's `entity` table without any credentials. This reveals: which account numbers have been created, which have been deleted (deleted entities still return 200), and the density/range of the ID space. This information can be used to target subsequent attacks (e.g., targeted phishing, staking-reward theft attempts, or correlation with on-chain data to de-anonymize accounts). Severity: Medium — information disclosure with no direct fund loss, but meaningful privacy and reconnaissance impact.

### Likelihood Explanation
Exploitation requires only an HTTP client and knowledge of the public API (documented in the OpenAPI spec). No credentials, special network position, or prior knowledge is needed. The attack is fully automatable: iterate `GET /api/v1/accounts/{n}/rewards` for `n = 1..N`, record 200 vs 404. At typical REST API throughput this can scan tens of thousands of IDs per minute. Repeatability is unlimited.

### Recommendation
1. **Normalize the response:** Return HTTP 200 with `{"rewards": []}` for both non-existent and existing-but-no-rewards accounts, removing the oracle. This is the simplest fix and aligns with how many public ledger APIs handle missing resources on list endpoints.
2. **Alternatively**, if 404 for non-existent accounts is intentional, add rate limiting (e.g., express-rate-limit) on the `/accounts/:id/rewards` route to make bulk enumeration impractical.
3. **Add `deleted` filter** to `entityExistenceQuery` to at least be consistent with the alias-lookup query: `where id = $1 and coalesce(deleted, false) <> true`.

### Proof of Concept
```bash
# Account that does NOT exist → 404
curl -s -o /dev/null -w "%{http_code}" \
  https://<mirror-node>/api/v1/accounts/999999999/rewards
# Output: 404

# Account that EXISTS but has no rewards → 200
curl -s https://<mirror-node>/api/v1/accounts/3/rewards
# Output: {"rewards":[],"links":{"next":null}}

# Bulk enumeration script
for id in $(seq 1 10000); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    https://<mirror-node>/api/v1/accounts/${id}/rewards)
  [ "$status" = "200" ] && echo "EXISTS: $id"
done
```

The 200/404 distinction unambiguously identifies which IDs are present in the `entity` table with zero authentication required. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/controllers/accountController.js (L170-175)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L27-63)
```javascript
  // use a small column in existence check to reduce return payload size
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;

  static missingAccountAlias = 'No account with a matching alias found';
  static multipleAliasMatch = `Multiple alive entities matching alias`;
  static multipleEvmAddressMatch = `Multiple alive entities matching evm address`;

  /**
   * Retrieves the entity containing matching the given alias
   *
   * @param {AccountAlias} accountAlias accountAlias
   * @return {Promise<Entity>} raw entity object
   */
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }

  /**
   * Checks if provided accountId maps to a valid entity
   * @param {BigInt|Number} accountId
   * @returns {Promise<Boolean>} valid flag
   */
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/middleware/authHandler.js (L15-19)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
```
