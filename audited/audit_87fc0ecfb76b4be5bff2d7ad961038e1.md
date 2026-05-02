### Title
Unauthenticated DB Connection Pool Exhaustion via Non-Existent Transaction Hash Lookups

### Summary
The `getTransactionsByIdOrHash` handler in `rest/transactions.js` performs an unconditional database query for every syntactically valid transaction hash, regardless of whether it exists. No rate limiting is applied to this endpoint, and 404 responses are never cached, meaning an unprivileged attacker can flood the endpoint with valid-format but non-existent hashes to exhaust the PostgreSQL connection pool and degrade service for all users.

### Finding Description

**Code path:**

1. `GET /api/v1/transactions/:transactionIdOrHash` is registered with no rate-limiting middleware in `rest/server.js` line 133. The only middleware applied is `authHandler`, `requestLogger`, `metricsHandler`, and an optional Redis response cache check — none of which throttle requests. [1](#0-0) 

2. `getTransactionsByIdOrHash` calls `extractSqlFromTransactionsByIdOrHashRequest` unconditionally: [2](#0-1) 

3. Inside `extractSqlFromTransactionsByIdOrHashRequest`, `isValidTransactionHash` is evaluated. The regex is:
   ```
   /^([\dA-Za-z+\-\/_]{64}|(0x)?[\dA-Fa-f]{96})$/
   ```
   A 64-character string composed of hex characters (a strict subset of `[\dA-Za-z]`) satisfies the first branch and returns `true`. [3](#0-2) 

4. When `isValidTransactionHash` returns `true`, `getTransactionHash()` is called immediately, issuing a real `pool.queryQuietly` against the database: [4](#0-3) [5](#0-4) 

5. If the hash does not exist in the DB, `rows.length === 0` and `NotFoundError` is thrown at line 774 — **after** the DB round-trip has already been consumed. [6](#0-5) 

6. The response cache update handler only stores responses when `httpStatusCodes.isSuccess(res.statusCode)` is true. A 404 `NotFoundError` is never cached, so every repeated request for the same non-existent hash re-executes the DB query: [7](#0-6) 

**Root cause:** The failed assumption is that syntactic hash validation is sufficient to guard the DB lookup. There is no semantic pre-check (e.g., a Bloom filter or in-memory negative cache), no per-IP or global request rate limit, and no negative-response caching.

### Impact Explanation
Each request with a valid-format but non-existent hash consumes one DB connection for the duration of the `get_transaction_info_by_hash` stored-procedure call. Under sustained parallel flooding, the PostgreSQL connection pool is exhausted, causing all subsequent queries (including those for legitimate users on all other endpoints) to queue or fail. This is a denial-of-service against the mirror node REST API with no economic cost to the attacker.

### Likelihood Explanation
The attack requires zero authentication, zero on-chain activity, and zero funds. Any attacker with network access to the public REST API can script it with a single `curl` loop generating random 64-character hex strings. The endpoint is publicly documented and reachable. The attack is trivially repeatable and parallelizable.

### Recommendation
1. **Rate limiting**: Apply a per-IP rate limit (e.g., via `express-rate-limit`) specifically on `GET /api/v1/transactions/:transactionIdOrHash` before the handler is invoked.
2. **Negative response caching**: Cache 404 responses for hash lookups in Redis with a short TTL (e.g., 5–10 seconds) so repeated lookups for the same non-existent hash do not re-hit the DB.
3. **Connection pool protection**: Configure a query timeout and a maximum wait-queue depth on the `pg` pool so that pool exhaustion causes fast-fail 503 responses rather than cascading hangs.

### Proof of Concept

```bash
# Generate and flood with valid-format but non-existent 64-char hex hashes
for i in $(seq 1 10000); do
  HASH=$(openssl rand -hex 32)   # 64 hex chars — passes isValidTransactionHash
  curl -s "https://<mirror-node>/api/v1/transactions/${HASH}" &
done
wait
```

**Preconditions:** Public network access to the mirror node REST API. No credentials required.

**Trigger:** Each request passes `isValidTransactionHash`, calls `getTransactionHash` → `pool.queryQuietly`, finds no rows, throws `NotFoundError`. The 404 is not cached.

**Result:** DB connection pool saturated; legitimate API requests begin timing out or receiving 500/503 errors.

### Citations

**File:** rest/server.js (L131-133)
```javascript
// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);
```

**File:** rest/transactions.js (L766-775)
```javascript
  if (isTransactionHash) {
    const encoding = transactionIdOrHash.length === Transaction.BASE64_HASH_SIZE ? 'base64url' : 'hex';
    if (transactionIdOrHash.length === Transaction.HEX_HASH_WITH_PREFIX_SIZE) {
      transactionIdOrHash = transactionIdOrHash.substring(2);
    }

    const rows = await getTransactionHash(Buffer.from(transactionIdOrHash, encoding));
    if (rows.length === 0) {
      throw new NotFoundError();
    }
```

**File:** rest/transactions.js (L923-928)
```javascript
const getTransactionsByIdOrHash = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedSingleTransactionParameters);
  const {query, params, scheduled, isTransactionHash} = await extractSqlFromTransactionsByIdOrHashRequest(
    req.params.transactionIdOrHash,
    filters
  );
```

**File:** rest/transactionHash.js (L21-36)
```javascript
const getTransactionHash = async (hash, {order = orderFilterValues.ASC, timestampFilters = []} = {}) => {
  const normalized = normalizeTransactionHash(hash);
  const params = [normalized];

  const timestampConditions = [];
  for (const filter of timestampFilters) {
    timestampConditions.push(`${TransactionHash.CONSENSUS_TIMESTAMP} ${filter.operator} $${params.push(filter.value)}`);
  }

  const query = `${mainQuery}
    ${timestampConditions.length !== 0 ? `where ${timestampConditions.join(' and ')}` : ''}
    ${orderClause} ${order}
    ${limitClause}`;

  const {rows} = await pool.queryQuietly(query, params);
  return normalized !== hash ? rows.filter((row) => row.hash.equals(hash)) : rows;
```

**File:** rest/transactionHash.js (L42-44)
```javascript
const transactionHashRegex = /^([\dA-Za-z+\-\/_]{64}|(0x)?[\dA-Fa-f]{96})$/;

const isValidTransactionHash = (hash) => transactionHashRegex.test(hash);
```

**File:** rest/middleware/responseCacheHandler.js (L90-97)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
```
