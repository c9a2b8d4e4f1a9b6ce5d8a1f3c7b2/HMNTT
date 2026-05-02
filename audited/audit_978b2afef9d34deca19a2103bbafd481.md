### Title
Unbounded Double-DB-Query Per Request in `getTokenAccounts()` Enables Cache-Bypass DoS via Concurrent Token Relationship Requests

### Summary
The `/api/v1/accounts/{id}/tokens` endpoint issues two sequential database queries per request: one against `token_account` for up to `limit` rows, and a second `token_id = any($1)` query against the `token` table for any token IDs absent from the in-process LRU cache. An unprivileged attacker who controls accounts with many unique token associations can systematically bypass the LRU cache and flood the database with concurrent double-query bursts, exhausting the DB connection pool and causing a non-network-based DoS.

### Finding Description

**Code path — Query 1 (`token_account` table):**

In `rest/service/tokenService.js`, `getTokenRelationshipsQuery()` builds a parameterized query with `$1 = ownerAccountId` and `$2 = limit` (user-supplied, up to the configured maximum): [1](#0-0) 

`getTokenAccounts()` executes this query and collects all returned `token_id` values into a `Set`: [2](#0-1) 

**Code path — Query 2 (`token` table, cache-miss path):**

`getCachedTokens()` checks the in-process `quickLru` cache for each token ID. Any ID not present is appended to `uncachedTokenIds`, and a second DB query is issued unconditionally if that list is non-empty: [3](#0-2) 

The second query passes the entire uncached array as a single `any($1)` parameter: [4](#0-3) 

**Root cause — failed assumption:** The design assumes the LRU cache will absorb repeated lookups. However, the cache is a single in-process `quickLru` with a finite `maxSize`: [5](#0-4) 

An attacker who controls accounts associated with token IDs that are not yet cached (or that exceed `maxSize` and are evicted) will trigger the second DB query on every request.

**No application-level rate limiting:** The REST service has no per-IP or per-endpoint rate limiting middleware. The only rate limiting found is in the Rosetta Helm chart (a separate service), not in the REST API: [6](#0-5) 

The controller passes the user-supplied `limit` directly into the query without any concurrency guard: [7](#0-6) 

### Impact Explanation
Each concurrent request with `limit=100` and 100 uncached token IDs causes two DB round-trips: one full table scan/index scan on `token_account` filtered by `account_id`, and one `token_id = any($1)` scan on `token` with up to 100 IDs. With N concurrent requests, the DB receives 2N queries simultaneously. Because the DB connection pool is finite, sustained concurrency exhausts available connections, causing all mirror node API endpoints (not just this one) to queue or fail. This is a complete service outage for all consumers of the mirror node REST API.

### Likelihood Explanation
The precondition — accounts with many token associations — requires paying Hedera network transaction fees, which is a real but modest cost barrier. A motivated attacker can create a small number of accounts (e.g., 10–20), each associated with 100 distinct tokens, for a one-time setup cost. Once set up, the attack is repeatable indefinitely at zero additional on-chain cost. The attacker needs no credentials, no special permissions, and no knowledge of internal state beyond a valid account ID. The endpoint is publicly accessible: [8](#0-7) 

### Recommendation
1. **Add application-level rate limiting** (e.g., express-rate-limit) on the `/accounts/:id/tokens` route, keyed by source IP.
2. **Cap the second DB query**: if `uncachedTokenIds.length` exceeds a threshold (e.g., 25), batch the lookups or reject/defer the request.
3. **Increase cache `maxSize`** and consider a shared/distributed cache (e.g., Redis) so the LRU is not per-process and cannot be trivially exhausted by rotating token IDs across requests.
4. **Add a DB connection pool timeout and queue depth limit** so that a burst of expensive queries does not starve other endpoints.

### Proof of Concept

**Setup (one-time, on-chain):**
```
1. Create 100 unique tokens on Hedera (T1..T100).
2. Create account A and associate it with all 100 tokens.
3. Ensure none of T1..T100 are in the mirror node's token cache
   (use tokens never queried before, or wait for LRU eviction).
```

**Attack (repeated, off-chain):**
```bash
# Send 200 concurrent requests, each triggering 2 DB queries
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/accounts/<A>/tokens?limit=100" &
done
wait
```

**Expected result:**
- Each request issues query 1 (`SELECT ... FROM token_account WHERE account_id = $1 ... LIMIT $2`) returning 100 rows.
- Each request issues query 2 (`SELECT ... FROM token WHERE token_id = any($1)`) with 100 IDs.
- 200 concurrent requests → 400 simultaneous DB queries → DB connection pool exhausted → all mirror node API endpoints return 503/timeout.

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L20-29)
```javascript
  static tokenRelationshipsQuery = `
        select ${TokenAccount.getFullName(TokenAccount.AUTOMATIC_ASSOCIATION)},
               ${TokenAccount.getFullName(TokenAccount.BALANCE)},
               ${TokenAccount.getFullName(TokenAccount.CREATED_TIMESTAMP)},
               ${TokenAccount.getFullName(TokenAccount.FREEZE_STATUS)},
               ${TokenAccount.getFullName(TokenAccount.KYC_STATUS)},
               ${TokenAccount.getFullName(TokenAccount.TOKEN_ID)}
        from ${TokenAccount.tableName} ${TokenAccount.tableAlias}
        where ${TokenAccount.tableAlias}.${TokenAccount.ACCOUNT_ID} = $1
        and ${TokenAccount.tableAlias}.${TokenAccount.ASSOCIATED} = true `;
```

**File:** rest/service/tokenService.js (L31-38)
```javascript
  static tokenCacheQuery = `
    select
      decimals,
      freeze_status,
      kyc_status,
      token_id
    from token
    where token_id = any ($1)`;
```

**File:** rest/service/tokenService.js (L96-104)
```javascript
  async getTokenAccounts(query) {
    const {sqlQuery, params} = this.getTokenRelationshipsQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    if (rows.length === 0) {
      return [];
    }

    const tokenIds = rows.reduce((result, row) => result.add(row.token_id), new Set());
    const cachedTokens = await this.getCachedTokens(tokenIds);
```

**File:** rest/service/tokenService.js (L136-153)
```javascript
  async getCachedTokens(tokenIds) {
    const cachedTokens = new Map();
    const uncachedTokenIds = [];
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
    });

    if (uncachedTokenIds.length === 0) {
      return cachedTokens;
    }

    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
    rows.forEach((row) => {
```

**File:** rest/routes/accountRoute.js (L1-26)
```javascript
// SPDX-License-Identifier: Apache-2.0

// external libraries
import express from 'express';

import {filterKeys} from '../constants';
import {AccountController, CryptoAllowanceController, TokenAllowanceController, TokenController} from '../controllers';
import extendExpress from '../extendExpress';

const router = extendExpress(express.Router());

const getPath = (path) => `/:${filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}/${path}`;

const resource = 'accounts';
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);

export default {
  resource,
  router,
};


```

**File:** rest/controllers/tokenController.js (L40-57)
```javascript
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
        case filterKeys.ORDER:
          order = filter.value;
          break;
        default:
          break;
      }
    }

    return {
      conditions,
      inConditions,
      order,
      ownerAccountId,
      limit,
    };
```
