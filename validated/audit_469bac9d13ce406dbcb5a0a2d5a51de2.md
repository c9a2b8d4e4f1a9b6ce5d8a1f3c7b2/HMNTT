All referenced code has been verified against the actual repository. Here is the result:

---

Audit Report

## Title
`getEncodedId()` Priority Ordering Causes Alias Lookup Bypass for Inputs Satisfying Both `EntityId.isValidEntityId()` and `AccountAlias.isValid()`

## Summary
The `getEncodedId()` function in `rest/service/entityService.js` routes input through a strict if-else chain that always evaluates `EntityId.isValidEntityId()` first. A non-empty intersection exists between the character sets accepted by `evmAddressRegex` and `accountAliasRegex`. Any 40-character string composed entirely of `{A, B, C, D, E, F, 2, 3, 4, 5, 6, 7}` satisfies both validators simultaneously. For such input, the alias resolution branch is permanently unreachable, causing the system to perform an EVM-address lookup instead of an alias lookup.

## Finding Description

**Code location:** `rest/service/entityService.js`, `getEncodedId()`, lines 118–137.

The if-else chain:

```js
if (EntityId.isValidEntityId(entityIdString)) {       // always evaluated first
    const entityId = EntityId.parseString(entityIdString, {paramName});
    return entityId.evmAddress === null
      ? entityId.getEncodedId()
      : await this.getEntityIdFromEvmAddress(entityId, requireResult);
} else if (AccountAlias.isValid(entityIdString)) {    // dead code for ambiguous input
    return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
}
``` [1](#0-0) 

**Validator overlap — verified in source:**

`evmAddressRegex` in `entityId.js` line 40:
```js
const evmAddressRegex = /^(0x)?[A-Fa-f0-9]{40}$/;
``` [2](#0-1) 

`accountAliasRegex` in `accountAlias.js` line 10:
```js
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
``` [3](#0-2) 

The intersection of `[A-Fa-f0-9]` (uppercase only: `[A-F0-9]`) and `[A-Z2-7]` is `{A, B, C, D, E, F, 2, 3, 4, 5, 6, 7}`. A 40-character string drawn entirely from this set — e.g., `ABCDEF2345672345672345672345672345672345` — passes both validators.

**`isValidEntityId()` accepts it as an EVM address:**

`isValidEntityId()` with default `allowEvmAddress = true` delegates to `isValidEvmAddress()`, which with `EvmAddressType.ANY` tests `evmAddressRegex`. A 40-char string from `{A–F, 2–7}` matches `evmAddressRegex` and so `isValidEntityId()` returns `true`. [4](#0-3) [5](#0-4) 

**`AccountAlias.isValid()` also accepts it:**

The same string has no dots, so `(\d{1,5}\.){0,2}` matches zero times, and `[A-Z2-7]+` matches the entire string since all characters are in that set. [6](#0-5) 

**Divergent resolution paths:**

- EVM address path (line 91): queries `entity.evm_address = Buffer.from(input, 'hex')` → 20 decoded bytes.
- Alias path (line 43): queries `entity.alias = base32.decode(input)` → 25 decoded bytes (40 × 5 / 8). [7](#0-6) [8](#0-7) 

These are structurally different byte sequences and cannot resolve to the same database row.

## Impact Explanation

An account whose alias base32-encodes to a 40-character string from `{A–F, 2–7}` becomes unreachable via `getEncodedId()` when queried by alias. The function silently reroutes to an EVM-address lookup:

- If no entity holds that EVM address, the caller receives a `NotFoundError` for an account that genuinely exists.
- If a different entity holds that EVM address, the caller receives the wrong entity's encoded ID — a cross-account misdirection.

All downstream callers of `getEncodedId()` inherit this misbehavior, including account, token, contract, schedule, balance, and topic-message controllers. [9](#0-8) 

## Likelihood Explanation

Standard Hedera public-key aliases (ED25519 = 32 bytes → 52 base32 chars; ECDSA secp256k1 = 33 bytes → 53 base32 chars) are not 40 characters and do not trigger this path. However, the Hedera protocol permits arbitrary-byte aliases. A 25-byte alias produces exactly 40 base32 characters (25 × 8 / 5 = 40). For the bug to trigger, all 40 base32 characters must fall within `{A–F, 2–7}` (12 of the 32 base32 alphabet characters). This condition is directly constructible: any 25-byte value can be chosen such that its base32 encoding uses only those 12 characters. An attacker who can create or observe such an account alias can reliably cause the wrong resolution on every request — no special privilege beyond submitting a query parameter is required. [10](#0-9) [11](#0-10) 

## Recommendation

Add an explicit disambiguation step before the if-else routing in `getEncodedId()`. The simplest fix is to check `AccountAlias.isValid()` **before** `EntityId.isValidEntityId()`, since a valid alias string is never a valid `shard.realm.num` or encoded integer — the ambiguity only arises with EVM-address-shaped strings. Alternatively, add a length or character-set pre-check: if the input is exactly 40 characters and contains no `0x` prefix, test `AccountAlias.isValid()` first. A more robust approach is to require that EVM address inputs be prefixed with `0x` when the caller intends an EVM address lookup, eliminating the overlap entirely. [9](#0-8) 

## Proof of Concept

1. Construct a 25-byte alias value whose base32 encoding uses only `{A, B, C, D, E, F, 2, 3, 4, 5, 6, 7}`. Example base32 alias string: `ABCDEF2345672345672345672345672345672345` (40 chars, all in the intersection set).
2. Create a Hedera account with this 25-byte alias on a network that permits arbitrary-byte aliases.
3. Query the mirror node REST API with the alias string as the `id` parameter (e.g., `GET /api/v1/accounts/ABCDEF2345672345672345672345672345672345`).
4. Observe that `getEncodedId()` routes to `getEntityIdFromEvmAddress()` instead of `getAccountIdFromAlias()`.
5. The EVM address lookup queries `entity.evm_address = 0xABCDEF2345672345672345672345672345672345` (20 bytes). The alias lookup would have queried `entity.alias = base32.decode("ABCDEF2345672345672345672345672345672345")` (25 bytes). These are different queries against different columns.
6. Result: the account created in step 2 is unreachable by alias — the API returns either `NotFoundError` or the wrong entity. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/service/entityService.js (L43-43)
```javascript
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
```

**File:** rest/service/entityService.js (L91-91)
```javascript
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/service/entityService.js (L118-137)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
    } catch (ex) {
      if (ex instanceof InvalidArgumentError) {
        throw InvalidArgumentError.forParams(paramName);
      }
      // rethrow
      throw ex;
    }

    throw InvalidArgumentError.forParams(paramName);
  }
```

**File:** rest/entityId.js (L39-40)
```javascript
const evmAddressShardRealmRegex = /^(\d{1,4}\.)?(\d{1,5}\.)?[A-Fa-f0-9]{40}$/;
const evmAddressRegex = /^(0x)?[A-Fa-f0-9]{40}$/;
```

**File:** rest/entityId.js (L121-123)
```javascript
  if (evmAddressType === constants.EvmAddressType.ANY) {
    return evmAddressRegex.test(address) || evmAddressShardRealmRegex.test(address);
  }
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

**File:** rest/accountAlias.js (L8-11)
```javascript
// limit the alias to the base32 alphabet excluding padding, other checks will be done in base32.decode. We need
// the check here because base32.decode allows lower case letters, padding, and auto corrects some typos.
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
```

**File:** rest/accountAlias.js (L41-44)
```javascript
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
  }
```
