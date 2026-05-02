### Title
Long-Zero EVM Address Bypasses Entity Existence and Type Validation in `getEncodedId()`

### Summary
`EntityService.getEncodedId()` in `rest/service/entityService.js` silently resolves long-zero EVM addresses (e.g., `0x0000000000000000000000000000000000000abc`) directly to an encoded entity ID via the `NUM_ALIAS` path without performing any database lookup, entity existence check, or entity type validation. This allows an unprivileged user to query account-scoped endpoints (`/nfts`, `/allowances/crypto`, `/allowances/tokens`, `/tokens`, `/rewards`) for any arbitrary entity number — including contracts — bypassing the implicit assumption that the resolved entity is a valid, existing account.

### Finding Description

**Exact code path:**

In `rest/service/entityService.js` lines 118–137, `getEncodedId` branches on `entityId.evmAddress === null`:

```js
const entityId = EntityId.parseString(entityIdString, {paramName});
return entityId.evmAddress === null
  ? entityId.getEncodedId()                                    // ← no DB lookup
  : await this.getEntityIdFromEvmAddress(entityId, requireResult); // ← DB lookup
```

For a long-zero EVM address like `0x0000000000000000000000000000000000000abc`, `parseFromString` in `rest/entityId.js` lines 250–256 classifies it as an **Account num alias** (not an opaque EVM address):

```js
let [prefix, num] = parseFromEvmAddress(numOrEvmAddress);
// prefix = '000000000000000000000000' === longFormEvmAddressPrefix
// num = 2748n <= maxNum (274877906943n)

if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
  return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
} else {
  return [shard, realm, num, null];             // Account num alias ← taken
}
```

Because `num` is set and `evmAddress` is `null`, `getEncodedId` returns `entityId.getEncodedId()` directly — **no database query, no existence check, no entity type check**.

**Root cause:** The branching condition `entityId.evmAddress === null` conflates two distinct cases: (a) a plain numeric entity ID (e.g., `95622`) and (b) a long-zero EVM address that encodes a num. Case (b) should require a DB lookup to verify the entity exists and is of the correct type, but it is silently treated identically to case (a).

**Contrast with non-long-zero EVM addresses:** A non-long-zero EVM address (e.g., `0x71eaa748d5252be68c1185588beca495459fdba4`) sets `evmAddress != null`, so `getEntityIdFromEvmAddress` is called, which executes `entityFromEvmAddressQuery` against the DB and throws `NotFoundError` if no matching entity exists.

**Exploit flow:**
1. Attacker identifies a contract entity with num `N` (e.g., `0.0.2748`).
2. Attacker constructs the long-zero EVM address: `0x` + 24 zero hex chars + 16-char hex of `N`.
3. Attacker sends `GET /api/v1/accounts/0x0000000000000000000000000000000000000abc/nfts` (or `/allowances/crypto`, `/allowances/tokens`, `/tokens`, `/rewards`).
4. `getEncodedId` resolves to the encoded ID of `0.0.2748` without any DB lookup.
5. The downstream controller queries NFT/allowance/token data for entity `0.0.2748` — a contract — via the account-scoped endpoint, with no rejection.

### Impact Explanation
An unprivileged attacker can enumerate and retrieve NFT holdings, crypto allowances, token allowances, token relationships, and staking rewards for **any entity number** — including contracts, tokens, or non-existent entities — via the account-scoped REST API. This constitutes unintended data exposure: the account endpoints are semantically scoped to account-type entities, but the long-zero EVM address path bypasses that scope entirely. For non-existent entity numbers, the response is silently empty rather than a `404`, enabling entity enumeration. For contract entities that hold NFTs or have allowances, their data is returned through an endpoint not intended for them, constituting unintended smart contract behavior as defined in scope.

### Likelihood Explanation
Exploitation requires zero privileges and zero special knowledge beyond the Hedera EVM address encoding convention (publicly documented). The attacker only needs to know the target entity's num, which is publicly visible on-chain. The attack is trivially repeatable with a single HTTP GET request and no rate-limiting specific to this path. Any user of the public Mirror Node REST API can exploit this.

### Recommendation
In `getEncodedId`, after resolving a long-zero EVM address to a num alias, perform a DB existence (and optionally type) check before returning the encoded ID. Specifically, when `entityId.evmAddress === null` but the original input was an EVM address (not a plain numeric string), call `isValidAccount` or an equivalent query to verify the entity exists and is of the expected type. Alternatively, unify the resolution path so that all EVM address inputs (long-zero or not) go through `getEntityIdFromEvmAddress`, which already performs a DB lookup.

### Proof of Concept

**Precondition:** A contract entity exists at `0.0.2748` on the network.

**Trigger:**
```
GET /api/v1/accounts/0x0000000000000000000000000000000000000abc/nfts
```

**Expected result (correct behavior):** `404 Not Found` — entity `0.0.2748` is a contract, not an account.

**Actual result:** HTTP 200 with NFT data (or empty list) for contract entity `0.0.2748`, with no error or type rejection.

**Code trace:**
- `getEncodedId('0x0000000000000000000000000000000000000abc')` [1](#0-0) 
- `parseFromString` classifies it as num alias, returns `evmAddress = null` [2](#0-1) 
- `entityId.evmAddress === null` → `getEncodedId()` returned directly, no DB lookup [3](#0-2) 
- Route handler receives encoded ID for `0.0.2748` and queries account-scoped data [4](#0-3)

### Citations

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/entityId.js (L250-256)
```javascript
    let [prefix, num] = parseFromEvmAddress(numOrEvmAddress);

    if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
      return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
    } else {
      return [shard, realm, num, null]; // Account num alias
    }
```

**File:** rest/routes/accountRoute.js (L15-19)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);
```
