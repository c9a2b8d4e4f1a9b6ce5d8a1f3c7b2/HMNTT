I have verified all the referenced code. Here is my assessment:

**All claims check out against the actual code:**

- `queryCanonicalizationMap` only covers `order` and `result` — confirmed at lines 10–13 of `requestHandler.js`
- `getRecordFileBlockDetailsFromHash()` passes the hash directly as `${hash}%` with no `.toLowerCase()` — confirmed at line 144 of `recordFileService.js`
- `getByHashOrNumber()` (the path-param variant) **does** call `hash.toLowerCase()` — confirmed at line 168 of `recordFileService.js`
- When `blockData` is `null`, `contractController.js` returns `{skip: true}` producing an empty response — confirmed at lines 499–501

---

## Audit Report

## Title
Missing Hash Lowercasing in `getRecordFileBlockDetailsFromHash()` Causes Silent Empty Results for Mixed-Case `block.hash` Query Parameter

## Summary
When a caller supplies a valid but mixed-case (e.g., EIP-55 checksummed) block hash via the `block.hash` query parameter, the mirror node silently returns an empty result set instead of the correct contract results. The hash is stored lowercase in the database, but the query-parameter code path never lowercases the value before issuing a `LIKE` query, while the path-parameter code path correctly does.

## Finding Description

**Step 1 — `requestQueryParser()` does not canonicalize `block.hash` values**

`rest/middleware/requestHandler.js` defines the canonicalization map at lines 10–13: [1](#0-0) 

Only `order` and `result` receive `lowerCaseQueryValue`. `block.hash` is absent. The loop at lines 57–66 lowercases the *key* but calls `canonicalizeValue(lowerKey, value)`, which returns the value unchanged for any key not in the map: [2](#0-1) 

A value like `0xAbCd1234...` survives intact through parsing.

**Step 2 — `getRecordFileBlockDetailsFromHash()` issues a case-sensitive LIKE query without lowercasing**

The static query uses `HASH like $1`: [3](#0-2) 

The method passes the hash directly as a prefix pattern with no `.toLowerCase()`: [4](#0-3) 

**Step 3 — Contrast with `getByHashOrNumber()`**, which handles the path-parameter variant and *does* lowercase: [5](#0-4) 

**Step 4 — Caller treats a null result as "skip"**

In `contractController.js`, when `getRecordFileBlockDetailsFromHash()` returns `null` (no match), the handler returns `{skip: true}`, producing an empty response: [6](#0-5) 

## Impact Explanation
Any caller querying `/api/v1/contracts/results?block.hash=0xAbCd...` with a valid but mixed-case hash receives an empty result set instead of the correct contract results. The block and its transactions exist in the database; they are simply not returned. Valid on-chain data is silently withheld, breaking client applications that rely on case-insensitive hash lookup — consistent with Ethereum tooling conventions (EIP-55 checksummed hashes).

## Likelihood Explanation
No authentication or special privilege is required. Any HTTP client can trigger this by supplying uppercase or mixed-case hex digits in the `block.hash` query parameter. Ethereum tooling commonly produces checksummed (EIP-55 mixed-case) hashes. The bug is trivially repeatable and deterministic.

## Recommendation
In `getRecordFileBlockDetailsFromHash()`, lowercase the hash before constructing the query parameter, mirroring the fix already present in `getByHashOrNumber()`:

```js
// rest/service/recordFileService.js
async getRecordFileBlockDetailsFromHash(hash) {
  const row = await super.getSingleRow(
    RecordFileService.recordFileBlockDetailsFromHashQuery,
    [`${hash.toLowerCase()}%`]   // add .toLowerCase()
  );
  return row === null ? null : new RecordFile(row);
}
```

Alternatively, add `block.hash` to the `queryCanonicalizationMap` in `requestHandler.js` so the value is lowercased at the middleware layer before it reaches the service.

## Proof of Concept
1. Insert a block whose hash is stored as `abcd1234...` (all lowercase) in the `record_file` table.
2. Send: `GET /api/v1/contracts/results?block.hash=0xAbCd1234...`
3. The value `AbCd1234...` (after `0x` strip) is passed to `getRecordFileBlockDetailsFromHash()`.
4. The SQL executes: `WHERE hash LIKE 'AbCd1234...%'` — no rows match the lowercase-stored value.
5. `blockData` is `null`; the controller returns `{skip: true}` and the response body is `{"results": [], "links": {"next": null}}`.
6. Sending the same request with `block.hash=0xabcd1234...` (all lowercase) returns the correct results.

### Citations

**File:** rest/middleware/requestHandler.js (L10-13)
```javascript
const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};
```

**File:** rest/middleware/requestHandler.js (L71-78)
```javascript
const canonicalizeValue = (key, value) => {
  const canonicalizationFunc = queryCanonicalizationMap[key];
  if (canonicalizationFunc === undefined) {
    return value;
  }

  return Array.isArray(value) ? value.map((v) => canonicalizationFunc(v)) : canonicalizationFunc(value);
};
```

**File:** rest/service/recordFileService.js (L58-62)
```javascript
  static recordFileBlockDetailsFromHashQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.HASH} like $1
    limit 1`;
```

**File:** rest/service/recordFileService.js (L143-146)
```javascript
  async getRecordFileBlockDetailsFromHash(hash) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromHashQuery, [`${hash}%`]);

    return row === null ? null : new RecordFile(row);
```

**File:** rest/service/recordFileService.js (L164-170)
```javascript
  async getByHashOrNumber(hash, number) {
    let whereStatement = '';
    const params = [];
    if (hash) {
      hash = hash.toLowerCase();
      whereStatement += `${RecordFile.HASH} like $1`;
      params.push(hash + '%');
```

**File:** rest/controllers/contractController.js (L486-501)
```javascript
    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }

      if (blockData) {
        timestampFilters.push(
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: blockData.consensusStart},
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: blockData.consensusEnd}
        );
      } else {
        return {skip: true};
      }
```
