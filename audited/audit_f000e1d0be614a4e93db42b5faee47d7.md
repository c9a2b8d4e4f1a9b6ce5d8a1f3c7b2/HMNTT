### Title
Pagination Record Skipping via Hardcoded `exclusive=true` for Last Sort Field in `LinkFactoryImpl.addExtractedParamsToQueryParams()`

### Summary
In `LinkFactoryImpl.addExtractedParamsToQueryParams()`, the last sort field (`token_id`) always receives `exclusive=true`, generating a next-page link of the form `account_id=gte:X&token_id=gt:Y`. When the service layer interprets this as a flat AND condition (`account_id >= X AND token_id > Y`), all records where `account_id > X AND token_id <= Y` are permanently skipped across paginated results. Any unprivileged caller of `GET /api/v1/accounts/{id}/allowances/nfts` who follows the generated `next` link will silently miss these records.

### Finding Description

**Exact code path:**

In `LinkFactoryImpl.java`, `addExtractedParamsToQueryParams()` (lines 199–224):

```java
int nextParamIndex = i + 1;
boolean exclusive = sortList.size() > nextParamIndex
    ? sortEqMap.get(sortList.get(nextParamIndex))
    : true;   // ← hardcoded true for the last sort field
``` [1](#0-0) 

The sort in `AllowancesController.getNftAllowances()` is `Sort.by(order, ACCOUNT_ID, TOKEN_ID)` — two fields. [2](#0-1) 

**Root cause — failed assumption:**

The design assumes that `account_id=gte:X&token_id=gt:Y` is equivalent to proper keyset pagination `(account_id > X) OR (account_id = X AND token_id > Y)`. It is not. The flat AND condition `account_id >= X AND token_id > Y` excludes the entire region `account_id > X AND token_id <= Y`.

**Why the existing `isEmptyRange` check is insufficient:**

`isEmptyRange()` only detects contradictory bounds (e.g., `gt:4 AND lt:5`). It does not detect the case where the generated bounds are logically consistent but structurally wrong for multi-field keyset pagination. [3](#0-2) 

**Why the service validation confirms the flat AND interpretation:**

The service enforces that `token_id=gt/gte` requires `account_id=eq/gte` to be present:

```java
if (tokenParams.getCardinality(RangeOperator.GT, RangeOperator.GTE) > 0
        && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.GTE) == 0) {
    throw new IllegalArgumentException("Requires the presence of an gte or eq account.id parameter");
}
``` [4](#0-3) 

If the repository performed proper OR-based keyset pagination, this constraint would be unnecessary. Its presence confirms the repository applies a flat AND: `account_id >= X AND token_id > Y`.

**Exploit flow:**

1. Attacker (no credentials needed) calls `GET /api/v1/accounts/0.0.100/allowances/nfts?limit=25&order=asc` (no `token.id` filter).
2. Page 1 returns 25 records; last record has `spender=0.0.50, token_id=0.0.200`.
3. `addExtractedParamsToQueryParams` computes:
   - `account_id` (i=0): `exclusive = sortEqMap.get("token_id")` = `containsEq([])` = **false** → GTE
   - `token_id` (i=1): `exclusive = true` (hardcoded) → GT
4. Generated next link: `?account_id=gte:0.0.50&token_id=gt:0.0.200`
5. Page 2 query: `account_id >= 0.0.50 AND token_id > 0.0.200`
6. Records such as `(spender=0.0.51, token_id=0.0.100)` — which sort after `(0.0.50, 0.0.200)` — are permanently excluded.

### Impact Explanation

NFT allowance records are silently omitted from paginated API responses. Any client, monitoring system, or auditing tool that iterates through all pages of `/api/v1/accounts/{id}/allowances/nfts` will receive an incomplete dataset. In a mirror node context, this breaks the correctness guarantee of the exported ledger state. The severity is **medium**: data is not corrupted or deleted, but it is invisibly incomplete, which undermines the integrity of downstream consumers (wallets, compliance tools, indexers).

### Likelihood Explanation

The trigger requires no authentication, no special parameters, and no race condition — just a standard paginated request without a `token.id` filter (the default usage pattern). The bug fires on every page boundary where the last record's `token_id` is not the maximum `token_id` for that `account_id`. This is the common case in any dataset with multiple tokens per spender. Any automated client iterating pages will silently reproduce the skip on every affected page.

### Recommendation

Replace the flat AND pagination URL with proper keyset pagination. The correct next-page condition for a two-field sort `(account_id ASC, token_id ASC)` after last record `(X, Y)` is:

```
(account_id > X) OR (account_id = X AND token_id > Y)
```

Concretely, the next-page link should use `account_id=gt:X` (exclusive, no `token_id` bound) when there is no user-supplied `token_id` filter, relying on the service to re-apply the secondary sort from the beginning for each new `account_id`. Alternatively, implement true keyset/cursor pagination by encoding the composite cursor `(X, Y)` as an opaque token and translating it to the correct OR predicate in the repository layer. Remove the hardcoded `exclusive = true` fallback at line 220 and replace it with logic that generates the correct OR-structured SQL predicate. [5](#0-4) 

### Proof of Concept

**Setup:** A mirror node with the following NFT allowances for owner `0.0.100` (sorted by spender, token_id ASC):

| spender | token_id |
|---------|----------|
| 0.0.10  | 0.0.500  |
| 0.0.20  | 0.0.100  |  ← will be skipped
| 0.0.20  | 0.0.600  |

**Step 1:** Request page 1 with limit=1:
```
GET /api/v1/accounts/0.0.100/allowances/nfts?limit=1&order=asc
```
Returns: `(spender=0.0.10, token_id=0.0.500)`
Next link generated: `?limit=1&order=asc&account.id=gte:0.0.10&token.id=gt:0.0.500`

**Step 2:** Follow the next link:
```
GET /api/v1/accounts/0.0.100/allowances/nfts?limit=1&order=asc&account.id=gte:0.0.10&token.id=gt:0.0.500
```
Repository query: `spender >= 0.0.10 AND token_id > 0.0.500`

**Result:** Returns `(spender=0.0.20, token_id=0.0.600)`.
**Skipped:** `(spender=0.0.20, token_id=0.0.100)` — never appears in any page despite being a valid allowance that sorts between the two returned records.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/LinkFactoryImpl.java (L77-119)
```java
    private static boolean isEmptyRange(
            Sort.@Nullable Order primarySort, LinkedMultiValueMap<String, String> queryParams) {
        if (primarySort == null) {
            return false;
        }

        var primaryField = primarySort.getProperty();

        var values = queryParams.get(primaryField);
        if (values == null || values.isEmpty()) {
            return false;
        }

        // Compute the effective range bounds from all query parameters
        var lower = Long.MIN_VALUE;
        var upper = Long.MAX_VALUE;

        for (var value : values) {
            var normalized = value.toLowerCase();

            try {
                // Extract the numeric value and update bounds
                if (normalized.startsWith("gt:")) {
                    long val = Long.parseLong(value.substring(3)) + 1; // gt:4 → gte:5
                    lower = Math.max(lower, val);
                } else if (normalized.startsWith("gte:")) {
                    long val = Long.parseLong(value.substring(4));
                    lower = Math.max(lower, val);
                } else if (normalized.startsWith("lt:")) {
                    long val = Long.parseLong(value.substring(3)) - 1; // lt:5 → lte:4
                    upper = Math.min(upper, val);
                } else if (normalized.startsWith("lte:")) {
                    long val = Long.parseLong(value.substring(4));
                    upper = Math.min(upper, val);
                }
            } catch (NumberFormatException e) {
                // Skip invalid values
            }
        }

        // If upper < lower, the range is empty (e.g., gt:4 AND lt:5)
        return upper < lower;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/LinkFactoryImpl.java (L219-223)
```java
            int nextParamIndex = i + 1;
            boolean exclusive = sortList.size() > nextParamIndex ? sortEqMap.get(sortList.get(nextParamIndex)) : true;
            var value = paginationParamsMap.get(key);
            queryParams.add(key, getOperator(order, exclusive) + ":" + value);
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L78-80)
```java
        var sort = Sort.by(order, ACCOUNT_ID, TOKEN_ID);
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(allowances, pageable, EXTRACTORS.get(owner));
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L50-53)
```java
        if (tokenParams.getCardinality(RangeOperator.GT, RangeOperator.GTE) > 0
                && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.GTE) == 0) {
            throw new IllegalArgumentException("Requires the presence of an gte or eq account.id parameter");
        }
```
