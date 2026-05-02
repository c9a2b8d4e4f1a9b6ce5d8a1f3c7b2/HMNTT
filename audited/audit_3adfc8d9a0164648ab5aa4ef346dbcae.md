### Title
Unauthenticated Repeated DB Join Execution via Active Schedule Lookups with 1-Second Cache TTL and No Rate Limiting

### Summary
`getScheduleById()` in `rest/schedules.js` executes a multi-table LEFT JOIN with `json_agg` aggregation on every cache miss. For active (non-executed, non-expired) schedules, the response cache TTL is effectively **1 second** (`DEFAULT_REDIS_EXPIRY`), and no rate limiting exists anywhere in the REST middleware stack. An unprivileged attacker can sustain continuous database load by cycling through many valid schedule IDs or re-querying the same active schedule IDs every second.

### Finding Description

**Query construction** (`rest/schedules.js`, lines 46–64):
```js
const getScheduleByIdQuery = `
  select ...
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
``` [1](#0-0) 

Every cache miss executes this query, which aggregates all `transaction_signature` rows for the schedule via `json_agg`. For schedules with many signatures, this aggregation is non-trivial.

**Cache TTL for active schedules** (`rest/schedules.js`, lines 130–146):
`getScheduleCacheControlHeader()` returns `{}` (empty object) for schedules that are not yet executed or expired. [2](#0-1) 

**`responseCacheUpdateHandler`** (`rest/middleware/responseCacheHandler.js`, lines 96 and 155–163):
When no `cache-control` header is present (active schedule case), `getCacheControlExpiryOrDefault(undefined)` returns `DEFAULT_REDIS_EXPIRY = 1` second. [3](#0-2) [4](#0-3) 

**Cache key is per-URL** (`rest/middleware/responseCacheHandler.js`, line 152):
```js
const cacheKeyGenerator = (req) =>
  crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
``` [5](#0-4) 

Each unique schedule ID produces a distinct cache key, so N different schedule IDs = N independent DB queries.

**No rate limiting exists**: A grep across all `rest/**/*.js` files for `rateLimit`, `throttle`, or `rateLimiter` returns zero matches. The `authHandler` only enforces a custom query limit for authenticated users with credentials; unauthenticated requests are not restricted. [6](#0-5) 

### Impact Explanation
An attacker can sustain continuous database join+aggregation load by:
- Querying N distinct valid schedule IDs (each a separate DB query, no shared cache benefit)
- Re-querying the same active schedule IDs every ~1 second as their cache entries expire

With a large `transaction_signature` table, the `json_agg` aggregation per schedule amplifies per-query cost. Sustained high-frequency requests can exhaust DB connection pool capacity or CPU, degrading or denying service to legitimate users. This is a non-network-based DoS requiring no privileges.

### Likelihood Explanation
Schedule IDs are sequential numeric entity IDs, publicly enumerable via `GET /api/v1/schedules`. No authentication, API key, or IP-based rate limiting is enforced. Any external user can automate requests at high frequency using standard HTTP tooling. The 1-second cache window for active schedules means the attack is continuously sustainable, not a one-time burst.

### Recommendation
1. **Increase active schedule cache TTL**: Return a non-zero `max-age` (e.g., 5–10 seconds) for active schedules instead of an empty header, so `DEFAULT_REDIS_EXPIRY = 1` is not the fallback.
2. **Implement rate limiting**: Add per-IP (or global) rate limiting middleware (e.g., `express-rate-limit`) to the REST API, particularly for lookup-by-ID endpoints.
3. **Ensure `transaction_signature.entity_id` is indexed**: Confirm an index exists on `transaction_signature(entity_id)` to bound the per-query cost regardless of table size.

### Proof of Concept
```bash
# Step 1: Enumerate valid schedule IDs
curl "https://<mirror-node>/api/v1/schedules?limit=100" | jq '.schedules[].schedule_id'

# Step 2: Continuously hammer many distinct active schedule IDs
while true; do
  for id in 0.0.1001 0.0.1002 0.0.1003 ... 0.0.2000; do
    curl -s "https://<mirror-node>/api/v1/schedules/$id" &
  done
  sleep 1  # re-trigger after 1-second cache expiry for active schedules
done
```
Each iteration fires N parallel requests, each hitting a distinct cache key and executing the full LEFT JOIN + `json_agg` query against the database. No credentials required.

### Citations

**File:** rest/schedules.js (L46-64)
```javascript
const getScheduleByIdQuery = `
  select
    s.consensus_timestamp,
    s.creator_account_id,
    e.deleted,
    s.executed_timestamp,
    s.expiration_time,
    e.key,
    e.memo,
    s.payer_account_id,
    s.schedule_id,
    s.transaction_body,
    s.wait_for_expiry,
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

**File:** rest/schedules.js (L130-146)
```javascript
const getScheduleCacheControlHeader = (schedule) => {
  const nowNs = utils.nowInNs();
  const executedTimestamp = schedule.executed_timestamp;
  const expirationTime = schedule.expiration_time;
  const consensusTimestamp = schedule.consensus_timestamp;

  const hasExecuted = executedTimestamp !== null || schedule.deleted;
  const hasAutoExpired =
    expirationTime === null && nowNs >= consensusTimestamp + constants.THIRTY_ONE_MINUTES * constants.NANOS_PER_SECOND;
  const hasExpired =
    expirationTime !== null && nowNs >= expirationTime + constants.SIXTY_SECONDS * constants.NANOS_PER_SECOND;

  if (hasExecuted || hasAutoExpired || hasExpired) {
    return LONGER_SCHEDULE_CACHE_CONTROL_HEADER;
  }
  return {};
};
```

**File:** rest/middleware/responseCacheHandler.js (L24-24)
```javascript
const DEFAULT_REDIS_EXPIRY = 1;
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/middleware/responseCacheHandler.js (L155-163)
```javascript
const getCacheControlExpiryOrDefault = (headerValue) => {
  if (headerValue) {
    const maxAge = headerValue.match(CACHE_CONTROL_REGEX);
    if (maxAge && maxAge.length === 2) {
      return parseInt(maxAge[1], 10);
    }
  }

  return DEFAULT_REDIS_EXPIRY;
```

**File:** rest/middleware/authHandler.js (L15-20)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }
```
