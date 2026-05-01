### Title
`UNION ALL` Duplicate Rows via Equal-Value `gte`/`lte` Spender Bounds with Token Range

### Summary
When a user supplies `spender.id=gte:N&spender.id=lte:N` (same value N) together with a `token.id` range, `getLowerFilters` and `getUpperFilters` both emit `spender = N` subqueries whose `token_id` conditions overlap. Because `getQuery` joins them with `UNION ALL` (no deduplication), any row satisfying both conditions appears twice in the response. All four validation checks pass without error for this input.

### Finding Description

**Code path:**
- `rest/controllers/tokenAllowanceController.js` → `extractTokenMultiUnionQuery()` → `validateBounds()`, `getLowerFilters()`, `getInnerFilters()`, `getUpperFilters()`
- `rest/service/tokenAllowanceService.js` → `getQuery()` lines 63–74

**Root cause — validation gap in `baseController.js`:**

`validateBoundsRange` (line 117–123) only rejects the combination of `hasBound() && hasEqual()`. It does **not** reject `gte:N` paired with `lte:N` (same N). All four validators pass cleanly for this input:

```
spender.id=gte:5  → primary.lower = {op: gte, val: 5}
spender.id=lte:5  → primary.upper = {op: lte, val: 5}
token.id=gte:100  → secondary.lower = {op: gte, val: 100}
token.id=lte:200  → secondary.upper = {op: lte, val: 200}
```

**Filter construction:**

`getLowerFilters` (line 138–141): `primary.hasLower() && secondary.hasLower()` → emits `spender = 5 AND token_id >= 100`.

`getInnerFilters` (lines 162–164): emits `spender > 5 AND spender < 5` — a logically impossible condition, always returns 0 rows.

`getUpperFilters` (lines 181–182): `primary.hasUpper() && secondary.hasUpper()` → emits `spender = 5 AND token_id <= 200`.

**Generated SQL (line 74):**
```sql
(select * from token_allowance
 where owner=$1 and amount>0 and spender=$3 and token_id>=$4
 order by spender asc, token_id asc limit $2)
union all
(select * from token_allowance
 where owner=$1 and amount>0 and spender>$5 and spender<$6   -- always empty
 order by spender asc, token_id asc limit $2)
union all
(select * from token_allowance
 where owner=$1 and amount>0 and spender=$7 and token_id<=$8
 order by spender asc, token_id asc limit $2)
order by spender asc, token_id asc limit $2
-- params: [owner, 25, 5, 100, 5, 5, 5, 200]
```

Any row with `spender=5` and `100 ≤ token_id ≤ 200` satisfies **both** the lower and upper subqueries and is returned twice.

### Impact Explanation

- **Inflated response data:** rows in the overlap range appear twice in `allowances[]`, giving callers a false picture of the account's token allowances.
- **Broken pagination:** `getPaginationLink` uses `rows.length < limit` to detect end-of-results. With duplicates consuming limit slots, the `next` cursor is computed from a wrong last-row position, causing pages to be skipped or repeated.
- **No data exfiltration beyond what the caller is already entitled to see**, but correctness of the API response is violated for any account whose allowances are queried.

### Likelihood Explanation

- Requires zero privileges — the endpoint is public for any valid account address.
- The crafted query string is trivial: one extra query parameter (`spender.id=gte:N&spender.id=lte:N`).
- Fully repeatable and deterministic; no race condition or timing dependency.
- Any automated client or script can trigger it on every paginated request.

### Recommendation

Add a check in `validateBoundsRange` (or a dedicated validator) that rejects the case where `primary.lower.value === primary.upper.value` when both are range operators (`gte`/`lte` or `gt`/`lt`). Alternatively, detect the degenerate case in `getLowerFilters`/`getUpperFilters` and collapse it into a single `spender = N AND token_id BETWEEN lower AND upper` subquery, eliminating the need for `UNION ALL` entirely when the primary range is a single point.

### Proof of Concept

**Precondition:** Account `0.0.1234` has at least one token allowance with `spender=5` and `token_id` between 100 and 200 (e.g., `token_id=150`).

**Request:**
```
GET /api/v1/accounts/0.0.1234/allowances/tokens?spender.id=gte:5&spender.id=lte:5&token.id=gte:100&token.id=lte:200
```

**Expected (correct) response:** one entry for `{spender:5, token_id:150}`.

**Actual response:** two identical entries for `{spender:5, token_id:150}` — one from the lower subquery (`spender=5 AND token_id>=100`) and one from the upper subquery (`spender=5 AND token_id<=200`).

**Verification:** compare `allowances.length` against a direct DB count of `token_allowance where owner=1234 and spender=5 and token_id between 100 and 200 and amount>0`; the API returns 2× the actual count for rows in the overlap.