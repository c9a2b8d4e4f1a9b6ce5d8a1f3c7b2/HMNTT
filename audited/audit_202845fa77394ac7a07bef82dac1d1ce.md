### Title
Unauthenticated DB Connection Pool Exhaustion via High-Frequency `GET /api/v1/blocks?limit=1` with No Per-IP Rate Limiting or In-Flight Request Cap

### Summary
The `extractLimitFromFilters()` function in `blockController.js` accepts any value from 1 to `maxLimit` (default 100), including `limit=1`, and passes it directly to a full DB query with no short-circuit. The REST API Helm chart middleware chain contains no `inFlightReq` or `rateLimit` middleware — only a `circuitBreaker` and a `retry` (10 attempts) — meaning an unauthenticated attacker can flood `GET /api/v1/blocks?limit=1` to exhaust the default 10-connection DB pool, while the retry middleware amplifies each incoming request up to 10-fold.

### Finding Description

**Code path:**

`extractLimitFromFilters()` at [1](#0-0)  accepts `limit=1` as a fully valid value (it is ≤ `maxLimit`). It is then passed to `getBlocks()`: [2](#0-1) 

Which calls `RecordFileService.getBlocks()`: [3](#0-2) 

Every call unconditionally executes a full `SELECT … ORDER BY … LIMIT $n` query against the `record_file` table. A `LIMIT 1` still requires an index scan setup and a connection checkout from the pool.

**Root cause — missing middleware:**

The REST API Helm chart middleware chain is: [4](#0-3) 

Only `circuitBreaker` and `retry` (10 attempts) are present. Compare with the Rosetta chart which has both `inFlightReq` (amount: 5) and `rateLimit` (average: 10): [5](#0-4) 

There is no application-level throttle in the REST JS middleware stack either — no `inFlightReq`, no `rateLimit`, no per-IP counter anywhere in `rest/middleware/`. [6](#0-5) 

**DB pool size:**

Default `maxConnections` is 10: [7](#0-6) 

**Retry amplification:**

The `retry: attempts: 10` Traefik middleware means each attacker request can be retried up to 10 times by the ingress, multiplying DB connection demand by up to 10×.

**Failed assumption:** The code assumes external infrastructure (Traefik) will enforce per-IP rate and concurrency limits before requests reach the DB pool. The REST API chart does not configure those middlewares, unlike other services in the same repo.

### Impact Explanation

With a pool of 10 connections and no concurrency cap, an attacker sending ~10–20 concurrent `GET /api/v1/blocks?limit=1` requests continuously will hold all pool slots. Legitimate requests queue behind `connectionTimeout` (20 s default), causing the REST API to become unresponsive for all users. The `statementTimeout` (20 s) provides a ceiling per query but does not prevent pool exhaustion under sustained load. This is a non-network-based DoS affecting the entire REST API surface, not just the blocks endpoint. [8](#0-7) 

### Likelihood Explanation

No authentication, API key, or IP-based credential is required. The endpoint is publicly accessible at `GET /api/v1/blocks`. The attack requires only an HTTP client capable of sending concurrent requests (e.g., `ab`, `wrk`, `curl` in a loop). The absence of `inFlightReq` and `rateLimit` in the REST chart (while present in Rosetta) indicates this is a configuration gap, not an intentional design choice. The attack is trivially repeatable and automatable from a single host.

### Recommendation

1. Add `inFlightReq` and `rateLimit` Traefik middlewares to `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta configuration: [9](#0-8) 

2. Remove or reduce the `retry: attempts: 10` for the REST API — retrying read queries on a saturated pool amplifies the attack. [10](#0-9) 

3. Consider adding an application-level concurrency guard (e.g., a semaphore on DB checkouts) so the pool cannot be fully consumed by a single source even if infrastructure-level limits are misconfigured.

### Proof of Concept

```bash
# Requires: wrk or parallel curl; no credentials needed
# Target: public REST API endpoint

# Step 1: Confirm limit=1 is accepted (HTTP 200)
curl -s "https://<mirror-node-host>/api/v1/blocks?limit=1" | head -c 200

# Step 2: Flood with 20 concurrent connections, sustained
wrk -t 4 -c 20 -d 60s "https://<mirror-node-host>/api/v1/blocks?limit=1"

# Step 3: In a separate terminal, observe legitimate requests timing out
# Expected: HTTP 503 / connection timeout after pool (10 slots) is exhausted
curl -v "https://<mirror-node-host>/api/v1/blocks" 
# → connection hangs for ~20s then fails (connectionTimeout: 20000ms)

# Step 4: Observe circuitBreaker does NOT trigger until error ratio > 25%,
# meaning the pool can be held in a degraded-but-not-erroring state
# that keeps the breaker open while blocking legitimate traffic.
```

### Citations

**File:** rest/controllers/blockController.js (L57-61)
```javascript
  extractLimitFromFilters = (filters) => {
    const limit = findLast(filters, {key: filterKeys.LIMIT});
    const maxLimit = getEffectiveMaxLimit();
    return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
  };
```

**File:** rest/controllers/blockController.js (L101-104)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);
```

**File:** rest/service/recordFileService.js (L149-161)
```javascript
  async getBlocks(filters) {
    const {where, params} = buildWhereSqlStatement(filters.whereQuery);

    const query =
      RecordFileService.blocksQuery +
      `
      ${where}
      order by ${filters.orderBy} ${filters.order}
      limit ${filters.limit}
    `;

    const rows = await super.getRows(query, params);
    return rows.map((recordFile) => new RecordFile(recordFile));
```

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```

**File:** rest/middleware/requestHandler.js (L1-30)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

import config from '../config';
import {httpStatusCodes, requestIdLabel, requestStartTime} from '../constants';
import {lowerCaseQueryValue, randomString} from '../utils';

const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};

const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};

const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};

```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
