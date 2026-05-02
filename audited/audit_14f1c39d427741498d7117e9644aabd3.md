### Title
`getNft()` Missing Entity Join Causes Incorrect `deleted` Status for Token-Deleted NFTs

### Summary
`NftService.getNft()` uses `nftByIdQuery`, which queries only the `nft` table with no join to the `entity` table, returning the raw `nft.deleted` flag. The design specification explicitly requires `deleted` to be `true` if **either** the NFT or its parent token is deleted. When a token entity is deleted (`entity.deleted=true`) but the individual NFT row has `deleted=false`, `getNft()` incorrectly returns `deleted=false`, while `getNfts()` (which uses `nftQuery` with the entity join) correctly returns `deleted=true`.

### Finding Description

**Exact code location:**

`nftByIdQuery` — no entity join: [1](#0-0) 

`getNft()` uses only `nftByIdQuery`: [2](#0-1) 

`nftQuery` — correct logic with entity join and OR expression: [3](#0-2) 

`getNfts()` uses `nftQuery` (correct path): [4](#0-3) 

**Root cause:** `nftByIdQuery` is `select * from nft where token_id = $1 and serial_number = $2` — it returns the raw `nft.deleted` column. `nftQuery` computes `nft.deleted OR coalesce(entity.deleted, false) as deleted` via a `LEFT JOIN entity`. The design spec states `deleted` must be `true` if either the NFT or the token is deleted: [5](#0-4) [6](#0-5) 

**Exploit flow:**
1. Token entity row: `entity.id = T`, `entity.deleted = true`
2. NFT row: `nft.token_id = T`, `nft.serial_number = S`, `nft.deleted = false`
3. Attacker calls `GET /api/v1/tokens/T/nfts/S` → routes to `getNft()` → executes `nftByIdQuery` → returns `deleted: false` (**incorrect**)
4. Attacker calls `GET /api/v1/tokens/T/nfts` → routes to `getNfts()` → executes `nftQuery` → returns `deleted: true` (**correct**)

The two public endpoints for the same NFT return contradictory `deleted` values.

**Why existing checks fail:** The correct OR-logic exists in `nftQuery` but is only wired into `getNfts()`. `getNft()` was never updated to use the same query or to perform the entity join independently.

### Impact Explanation
Any downstream system (wallet, marketplace, indexer) consuming `GET /api/v1/tokens/{tokenId}/nfts/{serialNumber}` will observe `deleted: false` for NFTs whose parent token has been deleted. This misrepresents the canonical on-chain state. Systems that gate transfers, ownership checks, or display logic on this field will treat a deleted NFT as active, potentially enabling incorrect state transitions or misleading users about asset validity. Severity: **Medium** — data integrity violation with real downstream consequences, no authentication bypass required.

### Likelihood Explanation
Any unauthenticated external user can trigger this with a single HTTP GET request. No special privileges, credentials, or timing are required. The precondition (token deleted, NFT row not individually marked deleted) is a realistic on-chain state that occurs when a token is deleted via `TokenDelete` without burning all NFTs first. The inconsistency is stable and repeatable indefinitely.

### Recommendation
Replace `nftByIdQuery` in `getNft()` with a query equivalent to `nftQuery` filtered by `token_id` and `serial_number`, so the entity join and OR-deletion logic is applied:

```sql
select
  nft.account_id,
  nft.created_timestamp,
  nft.delegating_spender,
  nft.deleted or coalesce(e.deleted, false) as deleted,
  nft.metadata,
  nft.serial_number,
  nft.spender,
  nft.timestamp_range,
  nft.token_id
from nft
left join entity e on e.id = nft.token_id
where nft.token_id = $1 and nft.serial_number = $2
```

This aligns `getNft()` with the spec and with the behavior of `getNfts()`.

### Proof of Concept
1. Insert into `entity`: `(id=1500, type='TOKEN', deleted=true)`
2. Insert into `nft`: `(token_id=1500, serial_number=1, deleted=false, account_id=1001, ...)`
3. `GET /api/v1/tokens/1500/nfts/1` → response contains `"deleted": false` ← **incorrect**
4. `GET /api/v1/tokens/1500/nfts` → response contains `"deleted": true` ← **correct**
5. The two endpoints return contradictory `deleted` values for the same NFT, with the single-NFT endpoint violating the documented spec. [1](#0-0) [7](#0-6)

### Citations

**File:** rest/service/nftService.js (L20-20)
```javascript
  static nftByIdQuery = `select * from nft where ${Nft.TOKEN_ID} = $1 and ${Nft.SERIAL_NUMBER} = $2`;
```

**File:** rest/service/nftService.js (L22-34)
```javascript
  static nftQuery = `select
    ${Nft.ACCOUNT_ID},
    ${Nft.getFullName(Nft.CREATED_TIMESTAMP)},
    ${Nft.DELEGATING_SPENDER},
    ${Nft.tableAlias}.${Nft.DELETED} or coalesce(${Entity.tableAlias}.${Entity.DELETED}, false) as ${Nft.DELETED},
    ${Nft.METADATA},
    ${Nft.SERIAL_NUMBER},
    ${Nft.SPENDER},
    ${Nft.getFullName(Nft.TIMESTAMP_RANGE)},
    ${Nft.TOKEN_ID}
    from ${Nft.tableName}
    left join ${Entity.tableName} ${Entity.tableAlias} on
    ${Entity.tableAlias}.${Entity.ID} = ${Nft.tableName}.${Nft.TOKEN_ID}`;
```

**File:** rest/service/nftService.js (L38-41)
```javascript
  async getNft(tokenId, serialNumber) {
    const {rows} = await pool.queryQuietly(NftService.nftByIdQuery, [tokenId, serialNumber]);
    return isEmpty(rows) ? null : new Nft(rows[0]);
  }
```

**File:** rest/service/nftService.js (L134-138)
```javascript
  async getNfts(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new Nft(ta));
  }
```

**File:** docs/design/nft.md (L244-244)
```markdown
  - `deleted` should be true if either the nft or the token is deleted
```

**File:** docs/design/nft.md (L276-276)
```markdown
  - `deleted` should be true if either the nft or the token is deleted
```
