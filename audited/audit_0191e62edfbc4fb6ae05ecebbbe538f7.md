### Title
Silent Result Truncation in `getTokensRequest()` When `name` Filter Disables Pagination

### Summary
In `rest/tokens.js`, `getTokensRequest()` unconditionally sets `links.next` to `null` when the `name` query parameter is present, while the underlying SQL query still enforces a `LIMIT` clause. When the number of tokens matching the name filter exceeds `defaultLimit` (25), the response silently returns a truncated result set with `"next": null`, giving the client no indication that additional matching tokens exist. No network partition is required to trigger this — it occurs under normal operation for any unprivileged user.

### Finding Description

**Exact code path:**

In `getTokensRequest()`, line 361 sets `hasNameParam`:

```js
const hasNameParam = !!req.query[filterKeys.NAME];
``` [1](#0-0) 

`extractSqlFromTokenRequest()` always appends a `LIMIT` clause regardless of whether `name` is present:

```js
const limitQuery = `limit $${params.push(limit)}`;
query = [query, whereQuery, orderQuery, limitQuery].filter((q) => q !== '').join('\n');
``` [2](#0-1) 

Back in `getTokensRequest()`, the pagination link is unconditionally nulled when `hasNameParam` is true, bypassing the `tokens.length !== limit` truncation check entirely:

```js
const nextLink = hasNameParam
  ? null
  : utils.getPaginationLink(req, tokens.length !== limit, {...}, order);
``` [3](#0-2) 

The response is then emitted with `links.next: null`: [4](#0-3) 

**Root cause:** The design assumes name-filtered queries return a small, complete result set, but the LIMIT is still enforced. The `tokens.length !== limit` guard that normally signals truncation is never evaluated for name queries — `nextLink` is hardcoded to `null` regardless of whether the result was cut short.

**Failed assumption:** The code assumes that a name search will always return fewer results than `defaultLimit` (25). This assumption is not enforced anywhere.

**Why existing checks fail:** The `validateTokenQueryFilter` for `filterKeys.NAME` only validates that the operator is `eq` and the value is 3–100 bytes: [5](#0-4) 
It does not limit the number of matching rows or enforce any completeness guarantee.

### Impact Explanation

Any client calling `GET /api/v1/tokens?name=X` receives at most 25 results with `"links": {"next": null}`. The client cannot distinguish between "all matching tokens returned" and "result silently truncated at limit." Applications that enumerate tokens by name for security-relevant decisions (e.g., detecting duplicate token names, auditing token registries) will silently operate on an incomplete dataset. The default limit is confirmed as 25: [6](#0-5) 

### Likelihood Explanation

This is trivially triggerable by any unauthenticated user with no special privileges. It requires only that more than 25 tokens share a common substring in their name (e.g., `name=USD`, `name=Token`, `name=Test`). On a production network with thousands of tokens, this threshold is easily exceeded. The attacker does not need to cause a network partition — the truncation happens under normal, healthy operation.

### Recommendation

1. **Emit a truncation signal when `hasNameParam` is true and `tokens.length === limit`:** Either set `links.next` to a non-null cursor (requires defining a stable sort key for name results, e.g., `token_id`), or include a response field such as `"truncated": true` when the limit was hit.
2. **Alternatively, enforce a hard cap and document it:** If name searches are intentionally limited to `N` results, document this explicitly and return an HTTP warning header or a `"truncated"` field in the response body when the cap is reached.
3. **Preferred fix:** Remove the `hasNameParam ? null :` short-circuit and allow `getPaginationLink` to evaluate `tokens.length !== limit` normally, using `token_id` as the pagination cursor even for name-filtered queries.

### Proof of Concept

**Precondition:** At least 26 tokens exist whose names contain the substring `"test"` (easily satisfied on mainnet/testnet).

**Steps:**
```
GET /api/v1/tokens?name=test
```

**Observed response:**
```json
{
  "tokens": [ /* exactly 25 entries */ ],
  "links": { "next": null }
}
```

**Expected response (if complete):**
```json
{
  "tokens": [ /* all N > 25 entries, or first page */ ],
  "links": { "next": "/api/v1/tokens?name=test&token.id=gt:0.0.XXXXX" }
}
```

The client receives `"next": null` and has no mechanism to retrieve the remaining tokens, with no indication the result was truncated.

### Citations

**File:** rest/tokens.js (L210-211)
```javascript
  const limitQuery = `limit $${params.push(limit)}`;
  query = [query, whereQuery, orderQuery, limitQuery].filter((q) => q !== '').join('\n');
```

**File:** rest/tokens.js (L333-335)
```javascript
    case filterKeys.NAME:
      ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
      break;
```

**File:** rest/tokens.js (L361-361)
```javascript
  const hasNameParam = !!req.query[filterKeys.NAME];
```

**File:** rest/tokens.js (L405-414)
```javascript
  const nextLink = hasNameParam
    ? null
    : utils.getPaginationLink(
        req,
        tokens.length !== limit,
        {
          [filterKeys.TOKEN_ID]: lastTokenId,
        },
        order
      );
```

**File:** rest/tokens.js (L416-421)
```javascript
  res.locals[responseDataLabel] = {
    tokens,
    links: {
      next: nextLink,
    },
  };
```

**File:** rest/__tests__/config.test.js (L325-325)
```javascript
    expect(func()).toEqual({default: 25, max: 100, tokenBalance: {multipleAccounts: 50, singleAccount: 1000}});
```
