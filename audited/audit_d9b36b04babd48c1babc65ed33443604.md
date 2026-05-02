### Title
`SPENDER_ID` Filter Accepts Opaque EVM Address But Resolves to `null`, Causing Silent Zero-Result Query on Token Allowances

### Summary
When a user submits an opaque (non-parsable) EVM address as the `spender.id` query parameter to `/api/v1/accounts/{id}/allowances/tokens`, the value passes input validation but is silently converted to `null` during formatting. This `null` is then bound directly into the SQL query as `spender = $N`, which in PostgreSQL always evaluates to false, causing the endpoint to return zero allowance records even when allowances exist for that spender.

### Finding Description

**Step 1 — Validation passes for opaque EVM addresses.**

In `rest/utils.js`, the `SPENDER_ID` validation uses `EntityId.isValidEntityId(val)` with default arguments (`allowEvmAddress = true`, `evmAddressType = ANY`): [1](#0-0) 

`isValidEntityId` with these defaults accepts any 40-hex-char string, including opaque EVM addresses like `0x71eaa748d5252be68c1185588beca495459fdba4`: [2](#0-1) 

**Step 2 — Formatting calls `getEncodedId()` which returns `null` for opaque addresses.**

In `formatComparator`, the `SPENDER_ID` case calls `EntityId.parseString(comparator.value).getEncodedId()` with no options: [3](#0-2) 

`parseString` → `parse` → `parseCached` → `parseFromString`. For an opaque EVM address (prefix ≠ 24 zero bytes), `parseFromString` returns `[shard, realm, null, numOrEvmAddress]` — `num` is `null`: [4](#0-3) 

`getEncodedId()` then returns `null` when `this.num === null`: [5](#0-4) 

So `comparator.value` is set to `null`.

**Step 3 — `null` is bound into the SQL query.**

`TokenAllowanceService.getSubQuery` pushes `filter.value` (now `null`) directly into `params` and generates `spender = $N`: [6](#0-5) 

In PostgreSQL, `spender = NULL` is never true (NULL comparison requires `IS NULL`), so the query returns zero rows.

**Contrast with `TOKEN_ID`:** The `TOKEN_ID` case explicitly passes `allowEvmAddress: true, evmAddressType: EvmAddressType.NUM_ALIAS`, which only accepts parsable (long-zero) EVM addresses that map to a numeric entity ID. `SPENDER_ID` has no such restriction: [7](#0-6) 

### Impact Explanation
Any unprivileged external user can submit a valid-looking opaque EVM address as `spender.id` and receive an empty `allowances` array, regardless of how many allowances exist for that spender. This constitutes incorrect data disclosure — the API silently returns wrong results (HTTP 200 with empty list) instead of an error or the correct records. Downstream clients or integrations relying on this endpoint to check allowance existence will be misled. The same bug applies to the crypto allowances endpoint which shares the same `formatComparator` path.

### Likelihood Explanation
No authentication or special privilege is required. Any user who knows or discovers a spender's EVM address (publicly observable on-chain) can trigger this. The EVM address format is widely used in EVM-compatible tooling, making accidental or deliberate use highly likely. The attack is trivially repeatable with a single HTTP GET request.

### Recommendation
In `formatComparator` for `SPENDER_ID`, mirror the same EVM address handling used for `TOKEN_ID`: either reject opaque EVM addresses outright (by passing `evmAddressType: EvmAddressType.NUM_ALIAS` or `allowEvmAddress: false`), or perform a DB lookup to resolve the opaque EVM address to its canonical entity ID before using it in the query — analogous to how `EntityService.getEncodedId` resolves EVM addresses for path parameters.

Specifically, change:
```js
case constants.filterKeys.SPENDER_ID:
  // Accepted forms: shard.realm.num or num
  comparator.value = EntityId.parseString(comparator.value).getEncodedId();
  break;
```
to reject opaque EVM addresses at validation time in `isValidFilterQuery` by using `EntityId.isValidEntityId(val, true, constants.EvmAddressType.NUM_ALIAS)` (matching `TOKEN_ID`), or perform an async EVM-address-to-entity-ID resolution in the controller before building the query.

### Proof of Concept

**Preconditions:**
- Spender account `0.0.1234` has an opaque EVM address `0x71eaa748d5252be68c1185588beca495459fdba4` stored in the `entity` table.
- A token allowance exists: owner `0.0.5000`, spender `0.0.1234`, token `0.0.9999`.

**Trigger:**
```
GET /api/v1/accounts/0.0.5000/allowances/tokens?spender.id=0x71eaa748d5252be68c1185588beca495459fdba4
```

**Code path:**
1. `isValidEntityId('0x71eaa748d5252be68c1185588beca495459fdba4')` → `true` (passes validation)
2. `EntityId.parseString('0x71eaa748d5252be68c1185588beca495459fdba4').getEncodedId()` → `null`
3. SQL executed: `SELECT * FROM token_allowance WHERE owner = $1 AND amount > 0 AND spender = $3` with params `[<encoded 5000>, 25, null]`
4. PostgreSQL evaluates `spender = NULL` → always false

**Result:**
```json
{"allowances": [], "links": {"next": null}}
```
HTTP 200 with empty list, despite the allowance existing. The correct canonical query `?spender.id=0.0.1234` returns the record normally.

### Citations

**File:** rest/utils.js (L359-361)
```javascript
    case constants.filterKeys.SPENDER_ID:
      ret = EntityId.isValidEntityId(val);
      break;
```

**File:** rest/utils.js (L1408-1411)
```javascript
      case constants.filterKeys.SPENDER_ID:
        // Accepted forms: shard.realm.num or num
        comparator.value = EntityId.parseString(comparator.value).getEncodedId();
        break;
```

**File:** rest/utils.js (L1415-1421)
```javascript
      case constants.filterKeys.TOKEN_ID:
        // Accepted forms: shard.realm.num or num
        comparator.value = EntityId.parseString(comparator.value, {
          allowEvmAddress: true,
          evmAddressType: EvmAddressType.NUM_ALIAS,
        }).getEncodedId();
        break;
```

**File:** rest/entityId.js (L67-71)
```javascript
  getEncodedId() {
    if (this.encodedId === undefined) {
      if (this.num === null) {
        this.encodedId = null;
      } else {
```

**File:** rest/entityId.js (L133-140)
```javascript
const isValidEntityId = (entityId, allowEvmAddress = true, evmAddressType = constants.EvmAddressType.ANY) => {
  if ((typeof entityId === 'string' && entityIdRegex.test(entityId)) || encodedEntityIdRegex.test(entityId)) {
    // Accepted forms: shard.realm.num, realm.num, or encodedId
    return true;
  }

  return allowEvmAddress && isValidEvmAddress(entityId, evmAddressType);
};
```

**File:** rest/entityId.js (L250-253)
```javascript
    let [prefix, num] = parseFromEvmAddress(numOrEvmAddress);

    if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
      return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
```

**File:** rest/service/tokenAllowanceService.js (L34-38)
```javascript
      ...filters.map((filter) => {
        params.push(filter.value);
        const column = TokenAllowanceService.columns[filter.key];
        return `${column}${filter.operator}$${params.length}`;
      }),
```
