### Title
Partial Content (206) Response Incorrectly Cached in Redis, Serving Stale Incomplete Data to All Subsequent Clients

### Summary
`httpStatusCodes.isSuccess()` returns `true` for any 2xx code including 206, and `responseCacheUpdateHandler` has no exclusion for 206 responses. When the mirror node is in a transient partial-data state (e.g., `callResult` is nil for a contract result), any unprivileged user who queries the affected endpoint during that window causes the incomplete 206 response to be stored in Redis under a stable URL-derived cache key with a TTL up to 600 seconds, blocking all subsequent clients from receiving the complete 200 response even after the mirror node finishes ingesting the full data.

### Finding Description

**Root cause — `isSuccess()` is too broad:**

`rest/constants.js` line 159:
```js
isSuccess: (code) => code >= 200 && code < 300,
```
This returns `true` for 206 PARTIAL_CONTENT.

**Cache update gate — no 206 exclusion:**

`rest/middleware/responseCacheHandler.js` line 95:
```js
if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```
The only guards are: non-empty body, cache key present, and `isSuccess` or 304. There is no check to exclude 206.

**206 is triggered by a deterministic data condition, not operator action:**

`rest/controllers/contractController.js` lines 1026–1029:
```js
if (isNil(contractResults[0].callResult)) {
  res.locals.statusCode = httpStatusCodes.PARTIAL_CONTENT.code;
}
```
Also at line 1198–1201 for `getContractResultsByTransactionIdOrHash`, and `rest/tokens.js` line 1048–1051 for NFT transfer history when `nft.createdTimestamp == null`. These are transient states during normal mirror node data ingestion — no privilege is required to encounter them.

**Cache key is stable and TTL is long:**

`rest/middleware/responseCacheHandler.js` line 151–152:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
The key is purely URL-derived. The `cache-control` header for `/api/v1/contracts/{id}/results/{id}` is `public, max-age=600` (confirmed in `rest/__tests__/specs/contracts/{id}/results/{id}/responseHeaders.json`), so the TTL passed to `getCache().setSingle()` is 600 seconds.

**Stored status code is 206:**

`rest/middleware/responseCacheHandler.js` line 114–116:
```js
const statusCode = isUnmodified ? httpStatusCodes.OK.code : res.statusCode;
const cachedResponse = new CachedApiResponse(statusCode, headers, responseBody, ...);
await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
```
`res.statusCode` is 206, so 206 is stored. On cache hit (`responseCacheCheckHandler` line 54), `cachedResponse.statusCode` (206) is replayed to all subsequent clients.

**Exploit flow:**
1. Attacker observes a new contract transaction on-chain (public information).
2. Attacker immediately queries `GET /api/v1/contracts/{contractId}/results/{timestamp}` before the mirror node has finished ingesting the full record file.
3. `contractResults[0].callResult` is nil → `res.locals.statusCode = 206`.
4. `responseHandler` sets `cache-control: public, max-age=600` and sends the body.
5. `responseCacheUpdateHandler` runs: `isSuccess(206)` → `true`, TTL=600 → `getCache().setSingle(key, 600, cachedResponse206)`.
6. For the next 600 seconds, `responseCacheCheckHandler` serves the stale 206 with `call_result: "0x"`, `gas_used: null`, etc. to every client.
7. After the mirror node completes ingestion and would return 200 with full data, the cache still serves 206 until TTL expires.

### Impact Explanation
All clients querying the affected endpoint during the 600-second cache window receive incomplete contract result data (e.g., null `gas_used`, empty `call_result`, missing state changes). Smart contract developers, block explorers, and automated systems relying on this data will observe incorrect results. For NFT transfer history endpoints the same applies when `createdTimestamp` is null. The impact is data integrity corruption at the API layer, affecting all consumers of the cached key simultaneously.

### Likelihood Explanation
No privileges are required. The attacker only needs to send a standard GET request at the right moment — immediately after a contract transaction is submitted. Since contract transactions are publicly visible on the Hedera network, an attacker can automate this: watch the network for new transactions, immediately query the mirror node REST API, and reliably hit the transient partial-data window. The attack is repeatable for every new contract transaction and requires no authentication, no special headers, and no rate-limit bypass.

### Recommendation
Explicitly exclude 206 from the caching condition in `responseCacheUpdateHandler`. Change line 95 of `rest/middleware/responseCacheHandler.js` from:

```js
if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```
to:
```js
if (responseBody && responseCacheKey && (isUnmodified || res.statusCode === httpStatusCodes.OK.code)) {
```

Or, define a separate `isCacheable()` predicate that explicitly whitelists only 200 (and 304 via the `isUnmodified` branch), rather than using the broad `isSuccess` range. Alternatively, add `&& res.statusCode !== httpStatusCodes.PARTIAL_CONTENT.code` as an additional guard.

### Proof of Concept
```
# 1. Identify a contract transaction that was just submitted to the network.
#    CONTRACT_ID = 0.0.5001, TIMESTAMP = 167654.000123456 (example)

# 2. Immediately query the mirror node (before full ingestion):
curl -v "http://mirror-node:5551/api/v1/contracts/0.0.5001/results/167654.000123456"
# Expected during partial state: HTTP 206, body contains call_result: "0x", gas_used: null

# 3. Wait for mirror node to fully ingest the record file (a few seconds).

# 4. Query again — should now return 200 with full data, but instead:
curl -v "http://mirror-node:5551/api/v1/contracts/0.0.5001/results/167654.000123456"
# Actual: HTTP 206, same incomplete body served from Redis cache

# 5. Confirm via Redis:
redis-cli GET "<md5(url)>-v1"
# Returns the serialized CachedApiResponse with statusCode=206 and TTL ~600s

# 6. All clients receive 206 + incomplete data for up to 600 seconds.
```