### Title
Sequential Unauthenticated DB Lookups via Repeated `from=` EVM Address Filters Exhaust Connection Pool

### Summary
`extractContractResultsByIdQuery()` in `rest/controllers/contractController.js` iterates over all `from=` query filters sequentially, calling `await EntityService.getEncodedId()` (a DB query) for each EVM address value inside a `for...of` loop. Because the REST API has no per-IP rate limiting and the only guard (`maxRepeatedQueryParameters`) merely caps the count per single request, an unprivileged attacker flooding concurrent requests can drive many sequential DB lookups simultaneously, exhausting the connection pool and degrading service for all users.

### Finding Description

**Exact code path:**

`GET /api/v1/contracts/results` → `getContractResults()` (line 1050) → `buildAndValidateFilters()` (validates format and count only) → `extractContractResultsByIdQuery(filters)` (line 1067).

Inside `extractContractResultsByIdQuery`, the for loop at lines 439–484 processes every filter sequentially:

```js
// rest/controllers/contractController.js lines 439-454
for (const filter of filters) {
  switch (filter.key) {
    case filterKeys.FROM:
      // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
      if (EntityId.isValidEvmAddress(filter.value)) {
        filter.value = await EntityService.getEncodedId(filter.value);  // ← DB query, awaited serially
      }
      ...
``` [1](#0-0) 

`EntityService.getEncodedId()` issues a real DB query (`entityFromEvmAddressQuery`) for each EVM address: [2](#0-1) 

**Root cause:** The `await` is inside a `for...of` loop, not a `Promise.all`. Each EVM address `from=` value causes a separate, sequential DB round-trip before the main query even runs. This is not a single lookup — it is N sequential lookups per request.

**Only guard — `maxRepeatedQueryParameters`:** `buildFilters()` rejects arrays longer than `config.query.maxRepeatedQueryParameters`: [3](#0-2) 

This caps N per request but does not limit concurrent requests. There is no rate limiter on the REST API layer (the throttle configuration found in the codebase applies only to the `web3` Java module, not the Node.js REST service): [4](#0-3) 

**Why the check is insufficient:** With `maxRepeatedQueryParameters` = M and C concurrent attacker requests, the DB receives up to M × C sequential lookup queries simultaneously, each holding a connection slot open for the duration of the serial chain.

### Impact Explanation

DB connection pool slots are finite. Each attacker request with M EVM address `from=` values occupies a connection for M sequential round-trips before releasing it. Under concurrent flood, the pool saturates, causing legitimate requests to queue or time out. This is a griefing denial-of-service with no economic damage to the attacker — matching the stated scope.

### Likelihood Explanation

- No authentication or API key required.
- The endpoint `GET /api/v1/contracts/results` is publicly documented.
- Valid 20-byte EVM addresses (e.g., `0x0000000000000000000000000000000000000001`) pass format validation and are accepted as `from=` values.
- A single attacker with modest bandwidth can sustain hundreds of concurrent requests.
- The attack is trivially repeatable and scriptable (e.g., `ab`, `wrk`, or a simple loop with `curl`).

### Recommendation

1. **Parallelize the lookups** — replace the serial `await` in the loop with `Promise.all` so all EVM address resolutions for a single request share one time window rather than chaining.
2. **Add per-IP or global rate limiting** to the REST API (e.g., `express-rate-limit`) at the middleware layer, independent of `maxRepeatedQueryParameters`.
3. **Lower the default `maxRepeatedQueryParameters`** for the `from=` key specifically, or add a dedicated cap for filters that trigger DB pre-resolution.
4. **Cache EVM-address → encoded-id mappings** (short TTL) so repeated lookups for the same address do not hit the DB.

### Proof of Concept

```bash
# Generate M distinct valid EVM addresses for from= params
PARAMS=$(python3 -c "
import sys
n = 10  # maxRepeatedQueryParameters default
args = '&'.join(f'from=0x{i:040x}' for i in range(1, n+1))
print(args)
")

# Flood with C concurrent requests, each triggering N sequential DB lookups
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>/api/v1/contracts/results?${PARAMS}" &
done
wait
# Observe: legitimate requests begin timing out / returning 503
# DB connection pool metrics show saturation
```

Each request triggers up to `maxRepeatedQueryParameters` sequential calls to `EntityService.getEncodedId()` before the main query runs, multiplied across all concurrent connections.

### Citations

**File:** rest/controllers/contractController.js (L439-454)
```javascript
    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.FROM:
          // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
          }
          this.updateConditionsAndParamsWithInValues(
            filter,
            contractResultFromInValues,
            params,
            conditions,
            contractResultSenderFullName,
            conditions.length + 1
          );
          break;
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** rest/utils.js (L1240-1249)
```javascript
    if (Array.isArray(values)) {
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
      }
```

**File:** rest/server.js (L67-99)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}

```
