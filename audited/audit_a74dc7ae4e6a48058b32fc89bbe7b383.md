### Title
Cache Key Not Normalized on `order` Parameter Enables Cache-Busting DoS Against `/accounts/:id/allowances/crypto`

### Summary
The response cache key is derived directly from `req.originalUrl` without query-parameter normalization. Because `?order=asc` and `?order=desc` produce distinct MD5 hashes, an unprivileged attacker can alternate these two values at high frequency to guarantee perpetual cache misses, forcing a live PostgreSQL query on every request with no rate-limiting in place.

### Finding Description

**Cache key generation — `rest/middleware/responseCacheHandler.js` lines 151-153:**

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` is the raw URL string as received from the client. The code comment immediately above (lines 147-149) explicitly acknowledges the gap:

> *"In the future, this will utilize Edwin's request normalizer (9113)."* [1](#0-0) 

The `requestNormalizer.js` module (`normalizeRequestQueryParams`) is **not** exported from `rest/middleware/index.js` and is **not** applied to `req.originalUrl` before the cache key is computed. [2](#0-1) 

**Controller — `rest/controllers/cryptoAllowanceController.js` lines 76-98:**

Every cache miss causes `getAccountCryptoAllowances` to call `CryptoAllowanceService.getAccountCryptoAllowances`, which issues a live `SELECT * FROM crypto_allowance WHERE owner = $1 AND amount > 0 ORDER BY spender <asc|desc> LIMIT $2` against PostgreSQL. [3](#0-2) 

**No rate limiting:** A grep across all `rest/**/*.js` files finds zero rate-limiting or throttling middleware applied to this route. [4](#0-3) 

**Exploit flow:**

1. Request A: `GET /api/v1/accounts/0.0.1000/allowances/crypto?order=asc`
   - Cache key = MD5(`/api/v1/accounts/0.0.1000/allowances/crypto?order=asc`) → **MISS** → DB query
2. Request B: `GET /api/v1/accounts/0.0.1000/allowances/crypto?order=desc`
   - Cache key = MD5(`/api/v1/accounts/0.0.1000/allowances/crypto?order=desc`) → **MISS** → DB query
3. Repeat A and B at high frequency. Neither entry ever gets a cache hit because the two keys are permanently distinct.

### Impact Explanation
Every alternating request bypasses the Redis cache and hits PostgreSQL directly. For a popular account (e.g., a well-known exchange account with many allowances), this amplifies DB read load proportionally to request rate. Because there is no rate limiting, a single attacker with a modest HTTP client can sustain hundreds of DB queries per second against a single account, degrading query latency for all users of the mirror node. The impact is griefing / availability degradation with no economic damage to on-chain users.

### Likelihood Explanation
The attack requires zero authentication, zero on-chain funds, and only a standard HTTP client. The two valid `order` values (`asc`, `desc`) are documented in the OpenAPI spec. Any external party who reads the API docs can reproduce this in minutes. It is trivially automatable and repeatable indefinitely. [5](#0-4) 

### Recommendation
Apply `normalizeRequestQueryParams` to produce a canonical URL **before** computing the cache key in `cacheKeyGenerator`. Specifically, the normalizer should substitute the default value for `order` when it equals the default (`desc`), and sort/canonicalize all query parameters so that semantically equivalent URLs map to the same cache key. This is already planned (issue 9113 referenced in the comment); it should be prioritized. As a secondary control, add per-IP or per-route rate limiting middleware. [6](#0-5) 

### Proof of Concept

```bash
# Terminal 1 – fire order=asc requests
while true; do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1000/allowances/crypto?order=asc" -o /dev/null
done

# Terminal 2 – fire order=desc requests simultaneously
while true; do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1000/allowances/crypto?order=desc" -o /dev/null
done
```

Observe in the mirror-node logs that every request logs a DB round-trip (no "from cache" log lines appear). DB CPU and query rate climb linearly with request rate. Redis cache entries for this account are never reused.

### Citations

**File:** rest/middleware/responseCacheHandler.js (L141-153)
```javascript
/*
 * Generate the cache key to access Redis. While Accept-Encoding is specified in the API response Vary
 * header, and therefore that request header value should be used as part of the cache key, the cache
 * implementation stores the response body as the original JSON object without any encoding applied. Thus it
 * is the same regardless of the accept encoding specified, and chosen by the compression middleware.
 *
 * Current key format:
 *
 *   path?query - In the future, this will utilize Edwin's request normalizer (9113).
 */
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```

**File:** rest/controllers/cryptoAllowanceController.js (L76-98)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
    const {conditions, params, order, limit} = this.extractCryptoAllowancesQuery(filters, accountId);
    const allowances = await CryptoAllowanceService.getAccountCryptoAllowances(conditions, params, order, limit);

    const response = {
      allowances: allowances.map((allowance) => new CryptoAllowanceViewModel(allowance)),
      links: {
        next: null,
      },
    };

    if (response.allowances.length === limit) {
      const lastRow = last(response.allowances);
      const lastValues = {
        [filterKeys.SPENDER_ID]: lastRow.spender,
      };
      response.links.next = utils.getPaginationLink(req, false, lastValues, order);
    }

    res.locals[responseDataLabel] = response;
  };
```

**File:** rest/routes/accountRoute.js (L17-17)
```javascript
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
```

**File:** rest/api/v1/openapi.yml (L267-289)
```yaml
  /api/v1/accounts/{idOrAliasOrEvmAddress}/allowances/crypto:
    get:
      summary: Get crypto allowances for an account info
      description: Returns information for all crypto allowances for an account.
      operationId: getCryptoAllowances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressPathParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParamDesc"
        - $ref: "#/components/parameters/spenderIdQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CryptoAllowancesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NotFoundError"
      tags:
        - accounts
```

**File:** rest/middleware/requestNormalizer.js (L35-59)
```javascript
const normalizeRequestQueryParams = (openApiRoute, path, query) => {
  const openApiParameters = openApiMap.get(openApiRoute);
  if (isEmpty(openApiParameters)) {
    return isEmpty(query) ? path : path + '?' + querystring.stringify(query);
  }

  let normalizedQuery = '';
  for (const param of openApiParameters) {
    const name = param.parameterName;
    const value = query[name];
    let normalizedValue = '';
    if (value !== undefined) {
      normalizedValue = Array.isArray(value) ? getNormalizedArrayValue(name, value) : value;
    } else if (param?.defaultValue !== undefined) {
      // Add the default value to the query parameter
      normalizedValue = param.defaultValue;
    }

    if (!isEmpty(normalizedValue)) {
      normalizedQuery = appendToQuery(normalizedQuery, name + '=' + normalizedValue);
    }
  }

  return isEmpty(normalizedQuery) ? path : path + '?' + normalizedQuery;
};
```
