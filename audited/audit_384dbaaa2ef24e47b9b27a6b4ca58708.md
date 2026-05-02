### Title
Unbounded Inner Subquery Table Scan via `spender.id=gte:1` + `token.id` Filter Combination in `getSubQuery()`

### Summary
When an unprivileged user sends a request to `/api/v1/accounts/{id}/allowances/tokens` with `spender.id=gte:1` combined with a `token.id=gt:X` filter, the multi-union query builder in `tokenAllowanceController.js` / `tokenAllowanceService.js` generates an inner subquery with only `owner = $1 AND amount > 0 AND spender > 1` — no `token_id` predicate. Because the `token_allowance` table's only index is the primary key `(owner, spender, token_id)`, this inner subquery must scan every row for the target owner where `spender > 1` (effectively all rows) and post-filter on the heap-only `amount` column. The REST API layer has no rate limiting, so an attacker can flood the endpoint with concurrent requests, multiplying the per-query scan cost against the database.

### Finding Description

**Primary key / index:**
`token_allowance` has a single index: `PRIMARY KEY (owner, spender, token_id)`. [1](#0-0) 

**Query construction path:**

1. `TokenAllowanceController.extractTokenMultiUnionQuery()` parses `spender.id=gte:1` into `bounds.primary.lower = {operator: gte, value: 1}` and `token.id=gt:X` into `bounds.secondary.lower = {operator: gt, value: X}`. [2](#0-1) 

2. `BaseController.getInnerFilters()` is called because both `primary.hasBound()` and `secondary.hasBound()` are true. It returns `[{...primary.lower, operator: gt}]` = `[{SPENDER_ID, operator: '>', value: 1}]` — **no token_id filter is included**. [3](#0-2) 

3. `TokenAllowanceService.getSubQuery()` builds the inner subquery from those filters, producing:
   ```sql
   select * from token_allowance
   where owner = $1 and amount > 0 and spender > $5
   order by spender asc, token_id asc
   limit $2
   ``` [4](#0-3) 

**Root cause:** `getInnerFilters()` intentionally strips the secondary (`token_id`) filter from the inner subquery — it only carries forward the primary (`spender`) range filter. When the primary lower bound is `gte:1` (the minimum possible entity ID), `spender > 1` matches virtually every row for the owner. The `amount > 0` predicate is not part of the primary key and cannot be satisfied by an index-only scan; PostgreSQL must fetch each heap tuple to evaluate it.

**Why the limit does not fully mitigate this:** PostgreSQL must scan rows in primary-key order `(owner, spender, token_id)` and evaluate `amount > 0` on each heap page until 25 qualifying rows are found. For an account with many revoked allowances (`amount = 0`) interspersed among active ones, the engine may read a large fraction of the owner's rows before accumulating 25 hits. Under concurrent load (many simultaneous requests targeting the same or different popular accounts), this multiplies into sustained sequential I/O against the same index/heap pages.

### Impact Explanation
The mirror node REST API shares its PostgreSQL database with the importer process that ingests ledger data. Sustained high-concurrency scans against `token_allowance` can saturate connection pool slots, inflate I/O wait, and degrade or stall the importer's write throughput, causing the mirror node to fall behind the network. While this does not directly affect consensus, it can render the mirror node's data stale and its API unavailable — a meaningful availability impact for any application relying on the mirror node.

### Likelihood Explanation
The attack requires zero privileges: the endpoint is public, the filter parameters are documented, and the exploit is a single HTTP GET request. It is trivially scriptable with tools like `curl` or `ab`. Targeting a well-known high-activity account (e.g., a DEX treasury with thousands of token allowances) maximises per-request scan cost. No authentication, API key, or rate-limiting mechanism exists on the REST API path for this endpoint. [5](#0-4) 

### Recommendation
1. **Add a secondary index** on `(owner, token_id, spender)` or a partial index `(owner, spender, token_id) WHERE amount > 0` so that queries filtering by `token_id` or filtering out zero-amount rows can use an index seek rather than a heap scan.
2. **Reject or rewrite degenerate lower bounds**: in `validateBounds` or `validateLowerBounds`, reject `spender.id=gte:1` (or any value ≤ the minimum entity ID) when combined with a secondary filter, or require a tighter primary lower bound.
3. **Add rate limiting to the REST API** (analogous to the `ThrottleManagerImpl` that exists in the `web3` module) to cap requests per IP or per second for expensive multi-union queries. [6](#0-5) 

### Proof of Concept

```
# Step 1 – identify a target account with many token allowances (e.g., account 0.0.1234)
# Step 2 – send the crafted request
GET /api/v1/accounts/0.0.1234/allowances/tokens?spender.id=gte:1&token.id=gt:1

# Step 3 – flood concurrently (no auth required)
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1234/allowances/tokens?spender.id=gte:1&token.id=gt:1" &
done
wait
```

The inner subquery generated will be:
```sql
select * from token_allowance
where owner = <encoded_id> and amount > 0 and spender > 1
order by spender asc, token_id asc
limit 25
```
This forces a near-full heap scan of all token allowances for the target owner, with no index support for the `amount > 0` predicate, repeated for every concurrent request.

### Citations

**File:** importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql (L229-233)
```sql
alter table if exists token_allowance
    add constraint token_allowance__pk primary key (owner, spender, token_id);
create index if not exists token_allowance_history__timestamp_range on token_allowance_history using gist (timestamp_range);
create index if not exists token_allowance_history__owner_spender_token_lower_timestamp
    on token_allowance_history (owner, spender, token_id, lower(timestamp_range));
```

**File:** rest/controllers/tokenAllowanceController.js (L22-59)
```javascript
  extractTokenMultiUnionQuery(filters, ownerAccountId) {
    const bounds = {
      primary: new Bound(filterKeys.SPENDER_ID, 'spender'),
      secondary: new Bound(filterKeys.TOKEN_ID, 'token_id'),
    };
    let limit = defaultLimit;
    let order = orderFilterValues.ASC;

    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.SPENDER_ID:
          bounds.primary.parse(filter);
          break;
        case filterKeys.TOKEN_ID:
          bounds.secondary.parse(filter);
          break;
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

    this.validateBounds(bounds);

    return {
      bounds,
      lower: this.getLowerFilters(bounds),
      inner: this.getInnerFilters(bounds),
      upper: this.getUpperFilters(bounds),
      order,
      ownerAccountId,
      limit,
    };
```

**File:** rest/controllers/tokenAllowanceController.js (L68-81)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/controllers/baseController.js (L56-61)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
  }
```

**File:** rest/controllers/baseController.js (L154-168)
```javascript
  getInnerFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasBound() || !secondary.hasBound()) {
      return [];
    }

    return [
      // if secondary has lower bound, the primary filter should be > ?
      {filter: primary.lower, newOperator: secondary.hasLower() ? utils.opsMap.gt : null},
      // if secondary has upper bound, the primary filter should be < ?
      {filter: primary.upper, newOperator: secondary.hasUpper() ? utils.opsMap.lt : null},
    ]
      .filter((f) => !isNil(f.filter))
      .map((f) => ({...f.filter, operator: f.newOperator || f.filter.operator}));
  }
```

**File:** rest/service/tokenAllowanceService.js (L30-46)
```javascript
  getSubQuery(filters, params, accountIdCondition, limitClause, orderClause) {
    const conditions = [
      accountIdCondition,
      TokenAllowanceService.amountCondition,
      ...filters.map((filter) => {
        params.push(filter.value);
        const column = TokenAllowanceService.columns[filter.key];
        return `${column}${filter.operator}$${params.length}`;
      }),
    ];
    return [
      TokenAllowanceService.accountTokenAllowanceQuery,
      `where ${conditions.join(' and ')}`,
      orderClause,
      limitClause,
    ].join('\n');
  }
```
