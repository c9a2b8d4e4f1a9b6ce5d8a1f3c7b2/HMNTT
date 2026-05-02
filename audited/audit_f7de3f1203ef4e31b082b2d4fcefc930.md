### Title
Silent Zero-Row Response via Contradictory `spenderIdFilters` + `spenderIdInFilters` in `getSubQuery()`

### Summary
`NftService.getSubQuery()` blindly ANDs range-based spender filters (`spenderIdFilters`) with an `IN`-clause built from equality spender filters (`spenderIdInFilters`) without any cross-validation that the IN values fall within the range. An unprivileged user can supply contradictory filter combinations (e.g., `spender.id=gte:100&spender.id=50`) that produce a logically impossible WHERE clause, causing the database to silently return zero rows. The API then returns an empty `nfts` array with no error, making all NFT spender approvals invisible to the caller.

### Finding Description

**Exact code path:**

In `rest/controllers/accountController.js` lines 44–64, `extractNftMultiUnionQuery()` splits `SPENDER_ID` filters by operator: `eq` goes to `spenderIdInFilters`, everything else goes to `spenderIdFilters`. [1](#0-0) 

`validateFilters()` (lines 18–32) only rejects duplicate lt/lte, duplicate gt/gte, and `ne` operators. It performs **no cross-check** between the range values in `spenderIdFilters` and the values in `spenderIdInFilters`. [2](#0-1) 

In `rest/service/nftService.js`, `getSubQuery()` (lines 55–76) appends `spenderIdFilters` directly into the conditions array, then appends a separate `spender IN (...)` clause from `spenderIdInFilters`, joining everything with `AND`: [3](#0-2) 

**Root cause:** No validation that the values in `spenderIdInFilters` are actually within the bounds established by `spenderIdFilters`. The two filter sets are independently valid but jointly contradictory.

**Exploit flow:**
1. Attacker sends: `GET /api/v1/accounts/0.0.1001/nfts?spender.id=gte:100&spender.id=50`
2. `spender.id=gte:100` → `spenderIdFilters = [{operator: '>=', value: 100}]`
3. `spender.id=50` (eq) → `spenderIdInFilters = [{operator: '=', value: 50}]`
4. Generated SQL WHERE clause: `account_id = $1 AND spender >= $3 AND spender IN ($4)` with params `[ownerAccountId, limit, 100, 50]`
5. `spender >= 100 AND spender IN (50)` is always false — zero rows returned
6. API responds with `{"nfts": [], "links": {"next": null}}` — no error, no indication of the contradiction

The existing test at lines 297–322 of `nftService.test.js` confirms this behavior is treated as valid: it tests `spender lte:10` combined with `spender IN (15, 17, 22)` and expects the contradictory SQL to be generated without rejection. [4](#0-3) 

### Impact Explanation
Any caller of `GET /api/v1/accounts/{id}/nfts` who uses a crafted or attacker-supplied URL with contradictory spender filters will receive a response showing zero NFT spender approvals, even when approvals exist. This silently suppresses the spender approval history visible through the API. A wallet, dApp, or monitoring tool relying on this endpoint could be misled into believing no approvals are active, potentially causing users to miss unauthorized delegations or fail to revoke them. The underlying database state is unaffected, but the API-layer view is completely falsified for the duration of the request.

### Likelihood Explanation
The attack requires no authentication, no special privileges, and no knowledge beyond the public API documentation. Any user who can issue an HTTP GET request can trigger it. The contradictory filter combination is not rejected with an error (HTTP 400), so it is indistinguishable from a legitimate empty result. It is trivially repeatable and can be embedded in a shared link or used in automated tooling targeting specific account IDs.

### Recommendation
Add cross-validation in `validateFilters()` (or in `extractNftMultiUnionQuery()` before calling `getSubQuery()`) to detect when any value in `spenderIdInFilters` falls outside the range established by `spenderIdFilters`. Specifically:
- If a `gte`/`gt` bound exists, reject any IN value strictly below that bound.
- If a `lte`/`lt` bound exists, reject any IN value strictly above that bound.
- Throw `InvalidArgumentError` (HTTP 400) with a descriptive message rather than silently generating an impossible query.

Alternatively, if mixed range+IN spender filters are not a supported use case, reject the combination entirely when both `spenderIdFilters` and `spenderIdInFilters` are non-empty.

### Proof of Concept

```
# Assume account 0.0.1001 has NFTs with spender 0.0.50 assigned

# Step 1: Confirm NFTs are visible normally
GET /api/v1/accounts/0.0.1001/nfts?spender.id=50
# → Returns NFTs with spender 0.0.50

# Step 2: Add a contradictory range filter (spender >= 100 excludes spender 50)
GET /api/v1/accounts/0.0.1001/nfts?spender.id=gte:100&spender.id=50
# → Returns {"nfts": [], "links": {"next": null}}
# → HTTP 200, no error, all spender approvals hidden

# Generated SQL (from getSubQuery):
# WHERE account_id = $1 AND spender >= $3 AND spender IN ($4)
# params: [<accountId>, <limit>, 100, 50]
# → Always evaluates to false; zero rows returned
```

### Citations

**File:** rest/controllers/accountController.js (L18-32)
```javascript
  validateFilters(bounds, spenderIdFilters) {
    this.validateBounds(bounds);

    const spenderOperators = spenderIdFilters.map((f) => f.operator);
    if (
      spenderOperators.filter((o) => o === utils.opsMap.lte || o === utils.opsMap.lt).length > 1 ||
      spenderOperators.filter((o) => o === utils.opsMap.gte || o === utils.opsMap.gt).length > 1
    ) {
      throw new InvalidArgumentError(`Multiple range params not allowed for spender.id`);
    }

    if (spenderIdFilters.some((f) => f.operator === utils.opsMap.ne)) {
      throw new InvalidArgumentError(`Not equals (ne) comparison operator is not supported`);
    }
  }
```

**File:** rest/controllers/accountController.js (L58-60)
```javascript
        case filterKeys.SPENDER_ID:
          filter.operator === utils.opsMap.eq ? spenderIdInFilters.push(filter) : spenderIdFilters.push(filter);
          break;
```

**File:** rest/service/nftService.js (L55-76)
```javascript
  getSubQuery(filters, params, accountIdCondition, limitClause, orderClause, spenderIdInFilters, spenderIdFilters) {
    filters.push(...spenderIdFilters);
    const conditions = [
      accountIdCondition,
      ...filters.map((filter) => {
        params.push(filter.value);
        const column = NftService.columns[filter.key];
        return `${column}${filter.operator}$${params.length}`;
      }),
    ];

    if (!isEmpty(spenderIdInFilters)) {
      const paramsForCondition = spenderIdInFilters.map((filter) => {
        params.push(filter.value);
        return `$${params.length}`;
      });

      conditions.push(`${Nft.SPENDER} in (${paramsForCondition})`);
    }

    return [NftService.nftQuery, `where ${conditions.join(' and ')}`, orderClause, limitClause].join('\n');
  }
```

**File:** rest/__tests__/service/nftService.test.js (L297-322)
```javascript
    {
      name: 'spender eq in gte lte',
      query: {
        ...defaultQuery,
        spenderIdInFilters: [
          {key: SPENDER_ID, operator: eq, value: 15},
          {key: SPENDER_ID, operator: eq, value: 17},
          {key: SPENDER_ID, operator: eq, value: 22},
        ],
        spenderIdFilters: [
          {key: SPENDER_ID, operator: lte, value: 10},
          {key: SPENDER_ID, operator: gte, value: 30},
        ],
      },
      expected: {
        sqlQuery: `${selectColumnsStatement}
            from nft
            left join entity e on e.id = nft.token_id
            where account_id = $1
            and spender <= $3
            and spender >= $4
            and spender in ($5,$6,$7)
            order by token_id desc,serial_number desc
            limit $2`,
        params: [1, 20, 10, 30, 15, 17, 22],
      },
```
