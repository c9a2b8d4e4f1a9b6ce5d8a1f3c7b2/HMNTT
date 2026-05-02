### Title
Unauthenticated Unbounded Pagination Loop Enables DB I/O Exhaustion via `/api/v1/blocks`

### Summary
The `getBlocks()` handler in `rest/controllers/blockController.js` accepts requests from any unauthenticated caller, caps page size at 100, and generates a cursor-based `next` link for every full page. Because no per-IP rate limiting exists at the REST API layer, an attacker can follow the `next` link in a tight automated loop, issuing a continuous stream of sequential DB queries against the `record_file` table until the entire block history is scanned — and then restart from block 0. Multiplied across concurrent connections, this exhausts DB I/O and degrades service for legitimate users.

### Finding Description

**Code path:**

`getBlocks()` (lines 101–112) calls `extractSqlFromBlockFilters()` to build a WHERE clause and limit, then calls `RecordFileService.getBlocks()` which executes:

```sql
SELECT ... FROM record_file
WHERE index >= $1
ORDER BY index ASC
LIMIT 100
``` [1](#0-0) 

The limit is capped by `extractLimitFromFilters()`:

```javascript
const maxLimit = getEffectiveMaxLimit();
return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
``` [2](#0-1) 

`getEffectiveMaxLimit()` returns `responseLimit.max` (default **100**) for unauthenticated callers: [3](#0-2) 

`generateNextLink()` emits a `next` URL using the last block's `index` as the cursor whenever the page is full: [4](#0-3) 

**Root cause — no rate limiting at the REST API layer:**

The `charts/hedera-mirror-rest/values.yaml` sets `global.middleware: false` and defines **no** `rateLimit` or `inFlightReq` Traefik middleware, unlike the Rosetta API which explicitly configures both: [5](#0-4) 

Compare with Rosetta, which has per-host rate limiting and in-flight request caps: [6](#0-5) 

The application-level `authHandler` only sets a higher limit for authenticated users; it does not throttle unauthenticated ones: [7](#0-6) 

The DB pool `statementTimeout` kills individual slow queries but does not prevent a flood of fast, index-range queries.

**Exploit flow:**

1. Attacker sends: `GET /api/v1/blocks?block.number=gte:0&order=asc&limit=100`
2. Server executes `SELECT … FROM record_file WHERE index >= 0 ORDER BY index ASC LIMIT 100` → returns 100 rows + `next` link pointing to `block.number=gt:100`.
3. Attacker immediately follows the `next` link → another DB query for rows 101–200.
4. Loop repeats with no server-side delay or IP throttle until all blocks are scanned.
5. Attacker restarts from block 0 and repeats indefinitely, or runs multiple parallel loops from different IPs/threads.

### Impact Explanation

Each loop iteration issues one sequential index-range scan against the `record_file` table. On a production Hedera mainnet mirror node with tens of millions of blocks, a single attacker thread can issue hundreds of queries per minute. Multiple concurrent attackers saturate DB connection pool slots and I/O bandwidth, causing query latency to spike for all other API endpoints (transactions, accounts, tokens) that share the same DB. The GCP backend policy `maxRatePerEndpoint: 250` is a per-pod ceiling far too high to prevent this pattern. [8](#0-7) 

### Likelihood Explanation

No credentials, API key, or special network position is required. The `next` link is machine-readable and self-describing. Any script that can issue HTTP GET requests and parse JSON can automate the loop. The attack is trivially repeatable, resumable after interruption (cursor is stateless), and distributable across many IPs to evade any future IP-based block. The default configuration ships with middleware disabled, meaning most deployments are exposed out of the box.

### Recommendation

1. **Add per-IP rate limiting** to the REST API Traefik middleware chain (mirror the `rateLimit` + `inFlightReq` pattern already used by the Rosetta chart).
2. **Add an application-level request rate limiter** (e.g., `express-rate-limit`) keyed on IP for the `/api/v1/blocks` route.
3. **Require a bounded upper timestamp or block-number range** on open-ended `gte:0` queries (similar to `maxTimestampRange` / `maxTransactionsTimestampRange` already enforced for other endpoints).
4. **Set `global.middleware: true`** in the REST chart defaults and define `inFlightReq` and `rateLimit` entries in `middleware:`. [9](#0-8) 

### Proof of Concept

```bash
#!/usr/bin/env bash
# No credentials required.
URL="https://<mirror-node-host>/api/v1/blocks?block.number=gte:0&order=asc&limit=100"
while true; do
  RESPONSE=$(curl -s "$URL")
  NEXT=$(echo "$RESPONSE" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d['links'].get('next','') or '')")
  [ -z "$NEXT" ] && URL="https://<mirror-node-host>/api/v1/blocks?block.number=gte:0&order=asc&limit=100" \
                  || URL="https://<mirror-node-host>$NEXT"
  # No sleep — tight loop, one DB query per iteration
done
```

Run 10–20 parallel instances of this script. Monitor `pg_stat_activity` on the mirror DB to observe connection saturation and rising query latency across all API endpoints.

### Citations

**File:** rest/service/recordFileService.js (L149-162)
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
  }
```

**File:** rest/controllers/blockController.js (L57-61)
```javascript
  extractLimitFromFilters = (filters) => {
    const limit = findLast(filters, {key: filterKeys.LIMIT});
    const maxLimit = getEffectiveMaxLimit();
    return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
  };
```

**File:** rest/controllers/blockController.js (L90-99)
```javascript
  generateNextLink = (req, blocks, filters) => {
    return blocks.length
      ? utils.getPaginationLink(
          req,
          blocks.length !== filters.limit,
          {[filterKeys.BLOCK_NUMBER]: last(blocks).index},
          filters.order
        )
      : null;
  };
```

**File:** rest/utils.js (L533-536)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};
```

**File:** charts/hedera-mirror-rest/values.yaml (L56-57)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
```

**File:** charts/hedera-mirror-rest/values.yaml (L82-91)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
  podAnnotations: {}
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

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** docs/configuration.md (L584-586)
```markdown
| `hiero.mirror.rest.query.maxTimestampRange`                              | 7d                      | The maximum amount of time a timestamp range query param can span for some APIs.                                                                                                              |
| `hiero.mirror.rest.query.maxTransactionConsensusTimestampRange`          | 35m                     | The maximum amount of time of a transaction's consensus timestamp from its valid start timestamp.                                                                                             |
| `hiero.mirror.rest.query.maxTransactionsTimestampRange`                  | 60d                     | The maximum timestamp range to list transactions.                                                                                                                                             |
```
