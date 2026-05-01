### Title
ILIKE Wildcard Injection via Unescaped `name` Filter in Token Discovery API

### Summary
The `extractSqlFromTokenRequest()` function in `rest/tokens.js` constructs an ILIKE pattern by directly concatenating user-supplied input (`'%' + filter.value + '%'`) without escaping ILIKE metacharacters (`%`, `_`). The sole validation gate, `utils.isByteRange(val, 3, 100)`, only enforces byte-length bounds and does not reject or escape wildcard characters, allowing any unprivileged caller to inject arbitrary ILIKE patterns and broaden the token match set beyond what the API intends.

### Finding Description
**Exact code path:**

`rest/tokens.js`, `extractSqlFromTokenRequest()`, line 177:
```js
conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
``` [1](#0-0) 

The value is correctly bound as a parameterized argument (no classic SQL injection), but PostgreSQL still interprets `%` and `_` inside the bound string as ILIKE pattern metacharacters. The server-side validation is:

```js
case filterKeys.NAME:
  ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
  break;
``` [2](#0-1) 

`isByteRange` enforces only a 3–100 byte length constraint; it performs no character-class filtering. A value of `%` (1 byte) would be rejected on length, but `%%%` (3 bytes) passes, and the resulting pattern `%%%%%` matches every token name. Similarly `___` (3 underscores) produces `%___%`, matching any name with ≥ 3 characters.

**Exploit flow:**
1. Attacker sends `GET /api/v1/tokens?name=%%%`
2. `validateTokenQueryFilter` accepts it (3 bytes, operator `eq`).
3. `extractSqlFromTokenRequest` builds pattern `%%%%%` and binds it as `$N`.
4. PostgreSQL evaluates `t.name ILIKE '%%%%%'` → matches every row in the `token` table.
5. Full token listing (name, symbol, token_id, type, metadata, key) is returned, identical to an unfiltered scan.

### Impact Explanation
The `name` filter is intended as a targeted substring search to retrieve a specific token by human-readable name. Wildcard injection collapses this into an unrestricted enumeration endpoint, bypassing the semantic intent of the filter. Token metadata (name, symbol, type, admin key) returned by this endpoint is consumed by off-chain indexers and routing logic that smart contracts depend on for token identification. An attacker can enumerate the entire token registry in a single request, or craft patterns (e.g., `A%Z`) that match structurally predictable name ranges, leaking metadata about tokens whose existence is not meant to be broadly advertised. Severity is bounded because the data is not encrypted at rest and no funds are directly accessible through this endpoint alone.

### Likelihood Explanation
No authentication is required. The endpoint is publicly reachable. The only precondition is knowledge that the `name` query parameter exists (documented in the OpenAPI spec). The attack is trivially repeatable with a single HTTP GET request and requires no special tooling. Any automated scanner or curious user can trigger it.

### Recommendation
Escape ILIKE metacharacters in the user-supplied value before constructing the pattern, or reject inputs containing `%` and `_` in `validateTokenQueryFilter`. The minimal fix is to escape at the point of pattern construction:

```js
// Escape ILIKE special characters before wrapping
const escaped = filter.value.replace(/([%_\\])/g, '\\$1');
conditions.push(`t.name ILIKE $${params.push('%' + escaped + '%')} ESCAPE '\\'`);
```

Alternatively, add a character-allowlist check in `validateTokenQueryFilter` for `filterKeys.NAME` that rejects any value containing `%`, `_`, or `\`.

### Proof of Concept
```
# Matches ALL tokens (pattern becomes %%%%%)
GET /api/v1/tokens?name=%%%

# Matches any token whose name contains exactly one character between two arbitrary sequences
GET /api/v1/tokens?name=_%_

# Enumerate tokens whose names start with 'H' and end with anything (pattern: %H%%)
GET /api/v1/tokens?name=H%%
```

Expected result: each request returns token rows that the name filter was not designed to surface, effectively turning a targeted lookup into a full-table scan of token metadata.

### Citations

**File:** rest/tokens.js (L176-178)
```javascript
    if (filter.key === filterKeys.NAME) {
      conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
    }
```

**File:** rest/tokens.js (L333-335)
```javascript
    case filterKeys.NAME:
      ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
      break;
```
