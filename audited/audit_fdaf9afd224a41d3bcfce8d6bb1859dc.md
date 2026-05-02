### Title
`isValidAccount()` Propagates `DbError` to Callers That Expect Only a Boolean, Enabling DoS via Unhandled Promise Rejection on DB Partition

### Summary
`EntityService.isValidAccount()` in `rest/service/entityService.js` is documented to return `Promise<Boolean>` but has no error handling around its DB call. When the database is unreachable, the underlying `queryQuietly` call throws a `DbError` that propagates uncaught through `isValidAccount()` into two controller handlers — `listStakingRewardsByAccountId` and `getTokenRelationships` — neither of which wraps the call in a try/catch. This causes unhandled async promise rejections, which in Node.js ≥15 terminate the process by default, and in earlier versions leave the request permanently hanging.

### Finding Description

**Exact code path:**

`isValidAccount()` delegates directly to `getSingleRow()` with no error handling:

```js
// rest/service/entityService.js, lines 60-63
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);
}
``` [1](#0-0) 

`getSingleRow()` calls `getRows()`, which calls `this.pool().queryQuietly(...)` — if the DB is unreachable, `queryQuietly` throws a `DbError`. Neither `getRows` nor `getSingleRow` catches it:

```js
// rest/service/baseService.js, lines 55-66
async getRows(query, params) {
  return (await this.pool().queryQuietly(query, params)).rows;
}
async getSingleRow(query, params) {
  const rows = await this.getRows(query, params);
  ...
}
``` [2](#0-1) 

**Caller 1 — `accountController.js`:**

```js
// rest/controllers/accountController.js, lines 172-175
const isValidAccount = await EntityService.isValidAccount(accountId);
if (!isValidAccount) {
  throw new NotFoundError();
}
``` [3](#0-2) 

**Caller 2 — `tokenController.js`:**

```js
// rest/controllers/tokenController.js, lines 68-71
const isValidAccount = await EntityService.isValidAccount(accountId);
if (!isValidAccount) {
  throw new NotFoundError();
}
``` [4](#0-3) 

**Root cause and failed assumption:** The function contract (`@returns {Promise<Boolean>}`) implies it will always resolve to a boolean. The implementation silently assumes the DB is always reachable. When it is not, `DbError` (which extends `RestError` extends `Error`) is thrown and propagates as an unhandled async rejection because neither caller wraps the call in try/catch. [5](#0-4) 

**Why existing checks are insufficient:** The only check in the callers is `if (!isValidAccount)` — a boolean guard that is never reached when `isValidAccount()` rejects. There is no catch block, no `.catch()`, and no `asyncHandler` wrapper visible in either controller. [6](#0-5) 

### Impact Explanation

An unhandled promise rejection in an Express 4.x async route handler is not caught by the framework's default error handler. In Node.js ≥15 (the current LTS baseline), unhandled rejections terminate the process with exit code 1 by default (`--unhandled-rejections=throw`). Even in older Node.js, the request hangs indefinitely (no response sent, connection held open). Either outcome constitutes a denial-of-service: repeated requests during a DB outage will either crash the REST service process or exhaust connection/file-descriptor limits. The two affected endpoints are `/accounts/:id/rewards` and `/accounts/:id/tokens`, both publicly accessible without authentication.

### Likelihood Explanation

No privilege is required. Any unauthenticated user can send GET requests to the affected endpoints. The DB partition itself does not need to be attacker-induced — transient cloud SQL connectivity issues, maintenance windows, or a separate infrastructure-level attack (e.g., network-level disruption) are sufficient preconditions. Once the DB is unreachable, a single request to either endpoint triggers the unhandled rejection. The attack is trivially repeatable and requires no special knowledge beyond the public API surface.

### Recommendation

1. **Catch `DbError` inside `isValidAccount()`** and return `false` (or rethrow a typed error that callers are expected to handle):
   ```js
   async isValidAccount(accountId) {
     try {
       const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
       return !isNil(entity);
     } catch (err) {
       if (err instanceof DbError) return false; // or rethrow as a known error
       throw err;
     }
   }
   ```
2. **Alternatively**, wrap all async route handlers with an `asyncHandler` utility that forwards any rejection to Express's `next(err)` error middleware, ensuring a 503/500 response is sent rather than an unhandled rejection.
3. **Add a test** for the DB-unreachable case in `entityService.test.js` — currently only happy-path and no-match cases are covered; there is no test asserting behavior when `queryQuietly` throws. [7](#0-6) 

### Proof of Concept

1. Stand up the mirror-node REST service pointing at a real (or test) PostgreSQL instance.
2. Send a baseline request to confirm the endpoint works:
   ```
   GET /api/v1/accounts/0.0.1234/tokens
   → 200 OK (or 404 if account not found)
   ```
3. Partition the DB (e.g., `iptables -A OUTPUT -p tcp --dport 5432 -j DROP` on the REST host, or stop the DB container).
4. Send the same request again:
   ```
   GET /api/v1/accounts/0.0.1234/tokens
   ```
5. **Observed:** The request hangs with no response (Express 4.x) or the Node.js process exits with `UnhandledPromiseRejection` (Node.js ≥15), taking down the entire REST service.
6. **Expected:** A `503 Service Unavailable` or `500 Internal Server Error` JSON response, with the process remaining alive.

### Citations

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/baseService.js (L55-66)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }

  async getSingleRow(query, params) {
    const rows = await this.getRows(query, params);
    if (isEmpty(rows) || rows.length > 1) {
      return null;
    }

    return rows[0];
  }
```

**File:** rest/controllers/accountController.js (L170-203)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedRewardsParameters);
    const query = this.extractStakingRewardsQuery(filters);
    // insert account id at $1, and limit (at $2)
    query.params.unshift(accountId, query.limit);
    const stakingRewardsTransfers = await StakingRewardTransferService.getRewards(
      query.order,
      query.limit,
      query.conditions,
      query.params
    );
    const rewards = stakingRewardsTransfers.map((reward) => new StakingRewardTransferViewModel(reward));
    const response = {
      rewards,
      links: {
        next: null,
      },
    };

    if (response.rewards.length === query.limit) {
      const lastRow = last(response.rewards);
      const lastValue = {
        [filterKeys.TIMESTAMP]: lastRow.timestamp,
      };
      response.links.next = utils.getPaginationLink(req, false, lastValue, query.order);
    }

    res.locals[responseDataLabel] = response;
  };
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

**File:** rest/errors/dbError.js (L1-6)
```javascript
// SPDX-License-Identifier: Apache-2.0

import RestError from './restError';

class DbError extends RestError {}

```

**File:** rest/__tests__/service/entityService.test.js (L148-158)
```javascript
describe('EntityService.isValidAccount tests', () => {
  test('EntityService.isValidAccount - No match', async () => {
    await expect(EntityService.isValidAccount(defaultInputEntity[0].id)).resolves.toBe(false);
  });

  test('EntityService.getAccountFromAlias - Matching', async () => {
    await integrationDomainOps.loadEntities(defaultInputEntity);

    await expect(EntityService.isValidAccount(defaultInputEntity[0].id)).resolves.toBe(true);
  });
});
```
