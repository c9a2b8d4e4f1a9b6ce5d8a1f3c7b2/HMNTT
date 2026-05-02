### Title
Missing Account Existence Check in `getNftsByAccountId` Returns 200 for Non-Existent Numeric Account IDs

### Summary
`getNftsByAccountId` in `rest/controllers/accountController.js` does not verify that a numerically-addressed account actually exists before querying its NFTs. When a non-existent numeric account ID (e.g., `0.0.9999999`) is queried, the endpoint returns HTTP 200 with `{"nfts": [], "links": {"next": null}}` instead of HTTP 404. Mirror node consumers cannot distinguish "account exists with no NFTs" from "account does not exist," causing incorrect state recording.

### Finding Description
**Exact code path:**

In `rest/controllers/accountController.js`, `getNftsByAccountId` (lines 90–103):

```js
getNftsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
  const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
  const query = this.extractNftMultiUnionQuery(filters, accountId);
  const nonFungibleTokens = await NftService.getNfts(query);
  const nfts = nonFungibleTokens.map((nft) => new NftViewModel(nft));
  res.locals[responseDataLabel] = { nfts, links: { next: ... } };
};
``` [1](#0-0) 

**Root cause — `getEncodedId` does not perform a DB lookup for numeric IDs:**

In `rest/service/entityService.js` lines 118–137, `getEncodedId` branches on input type:
- For a valid numeric entity ID string (`0.0.X`), it calls `entityId.getEncodedId()` — a **pure arithmetic encoding with no database query**.
- For an alias, it calls `getAccountIdFromAlias` which queries the DB and throws `NotFoundError` if absent.
- For an EVM address, it calls `getEntityIdFromEvmAddress` which queries the DB and throws `NotFoundError` if absent. [2](#0-1) 

So for numeric IDs, `getEncodedId` returns a valid-looking encoded ID even when the account does not exist in the database. `NftService.getNfts` then executes a query filtered by `account_id = $1` against the `nft` table, finds zero rows, and the handler returns `{"nfts": [], "links": {"next": null}}` with HTTP 200.

**Contrast with the sibling handler `listStakingRewardsByAccountId`** (lines 170–175), which explicitly guards against this:

```js
const isValidAccount = await EntityService.isValidAccount(accountId);
if (!isValidAccount) {
  throw new NotFoundError();
}
``` [3](#0-2) 

`isValidAccount` queries `select type from entity where id = $1` and returns `false` when no row is found. [4](#0-3) 

**Test spec confirms the 200 behavior:** `rest/__tests__/specs/accounts/{id}/nfts/not-found.json` documents `responseStatus: 200` with `{"nfts": []}` for accounts with no NFTs, and the same code path applies to completely non-existent accounts. [5](#0-4) 

### Impact Explanation
Mirror node consumers (indexers, wallets, explorers, bridges) that call `/:idOrAliasOrEvmAddress/nfts` to determine account state will receive a semantically incorrect 200 response for non-existent accounts. They will record "account `0.0.X` exists and holds zero NFTs" rather than "account `0.0.X` does not exist." This corrupts downstream state: NFT ownership records, account existence caches, and audit trails. The OpenAPI spec for this endpoint explicitly documents a 404 response, so consumers are entitled to rely on it. [6](#0-5) 

### Likelihood Explanation
No authentication or privilege is required. Any external user can send `GET /api/v1/accounts/0.0.9999999/nfts` with an arbitrary numeric account ID. The request is syntactically valid, passes all input validation, and reliably produces the incorrect 200 response. The attack is trivially repeatable and requires no special knowledge beyond knowing the API endpoint exists.

### Recommendation
Add the same `isValidAccount` guard used in `listStakingRewardsByAccountId` to `getNftsByAccountId`, immediately after resolving the `accountId`:

```js
getNftsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
  const isValidAccount = await EntityService.isValidAccount(accountId);
  if (!isValidAccount) {
    throw new NotFoundError();
  }
  // ... rest of handler
};
```

This ensures a DB existence check is performed for numeric IDs before any NFT query is executed, consistent with the behavior already implemented for aliases, EVM addresses, and the rewards endpoint.

### Proof of Concept
**Precondition:** Mirror node is running; account `0.0.9999999` does not exist in the database.

**Steps:**
1. Send: `GET /api/v1/accounts/0.0.9999999/nfts`
2. No authentication required.

**Expected (per spec):** HTTP 404 `{"_status": {"messages": [{"message": "Not found"}]}}`

**Actual:** HTTP 200
```json
{
  "nfts": [],
  "links": { "next": null }
}
```

**Comparison — rewards endpoint (correctly returns 404):**
`GET /api/v1/accounts/0.0.9999999/rewards` → HTTP 404 `{"_status": {"messages": [{"message": "Not found"}]}}`

### Citations

**File:** rest/controllers/accountController.js (L90-103)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
    const query = this.extractNftMultiUnionQuery(filters, accountId);
    const nonFungibleTokens = await NftService.getNfts(query);
    const nfts = nonFungibleTokens.map((nft) => new NftViewModel(nft));

    res.locals[responseDataLabel] = {
      nfts,
      links: {
        next: this.getPaginationLink(req, nfts, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/controllers/accountController.js (L171-175)
```javascript
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

**File:** rest/service/entityService.js (L118-127)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** rest/__tests__/specs/accounts/{id}/nfts/not-found.json (L72-84)
```json
  "urls": [
    "/api/v1/accounts/0.0.3001/nfts",
    "/api/v1/accounts/0.0.1001/nfts?token.id=1",
    "/api/v1/accounts/0.0.1001/nfts?token.id=1500&serialnumber=5",
    "/api/v1/accounts/0.0.1001/nfts?token.id=1500&serialnumber=3&spender.id=2001"
  ],
  "responseStatus": 200,
  "responseJson": {
    "nfts": [],
    "links": {
      "next": null
    }
  }
```

**File:** rest/api/v1/openapi.yml (L154-164)
```yaml
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Nfts"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NotFoundError"
```
