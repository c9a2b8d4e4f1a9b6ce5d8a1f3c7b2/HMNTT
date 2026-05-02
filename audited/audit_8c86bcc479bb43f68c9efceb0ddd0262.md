### Title
Redis Failure Causes `TypeError` in `getSingleWithTtl`, Turning All Requests into 500 Errors (Effective DoS)

### Summary
When Redis fails after the connection is established (`this.ready === true`), the `.catch()` in `getSingleWithTtl` swallows the error by returning `undefined` (the return value of `logger.warn()`). The immediately following `result[1][1]` access then throws a `TypeError`. This TypeError propagates through `responseCacheCheckHandler`, is caught by `wrap()` in `extendExpress`, and forwarded to `handleError`, which returns HTTP 500 to every client. The server process does **not** crash, but the cache middleware's failure to gracefully degrade causes a complete API-level denial of service for the duration of the Redis outage.

### Finding Description

**Code path:**

`rest/cache.js`, `getSingleWithTtl()`, lines 69–77:
```js
const result = await this.redis
  .multi()
  .ttl(key)
  .get(key)
  .exec()
  .catch((err) => logger.warn(`Redis error during ttl/get: ${err.message}`));
// ^^^ .catch returns undefined (logger.warn returns void)

const rawValue = result[1][1];   // TypeError: Cannot read properties of undefined
```

**Root cause:** The `.catch()` handler at line 74 absorbs the Redis error but returns `undefined` (the implicit return of `logger.warn()`). `result` is therefore `undefined`. The unconditional property access `result[1][1]` at line 77 throws `TypeError: Cannot read properties of undefined (reading '1')`. There is no `try/catch` inside `getSingleWithTtl` to handle this.

**Why the `this.ready` guard does not help:** `this.ready` is set to `false` inside the `retryStrategy` callback (line 31 of `cache.js`), which fires asynchronously only when ioredis begins a reconnection attempt. Between the moment a Redis connection drops and the moment `retryStrategy` fires, `this.ready` remains `true`. During that window every incoming request passes the guard, issues the `multi().exec()`, receives an error, and hits the `result[1][1]` crash path.

**Propagation through `wrap`:** `responseCacheCheckHandler` is registered via `app.useExt()` (server.js line 97), which wraps it with `wrap()` from `extendExpress.js`. `wrap` does catch the TypeError (lines 42–44 of `extendExpress.js`) and calls `next(err)`. `handleError` (httpErrorHandler.js line 14) maps it to HTTP 500. The server process survives, but **every single request** returns 500 for the duration of the Redis failure instead of falling through to the real route handler.

**Why existing checks are insufficient:**
- `this.ready` guard: race-condition window described above.
- `.catch()` on the Redis pipeline: catches the Redis error but returns `undefined`, creating a new TypeError downstream.
- `wrap()` / `handleError`: catches the TypeError but converts it to a 500, not a graceful cache-miss pass-through.
- `process.on('unhandledRejection', handleRejection)`: not reached because `wrap` catches first; irrelevant to this path.

### Impact Explanation
Any Redis failure (network partition, connection exhaustion, Redis restart) causes 100% of API requests to return HTTP 500 for the entire duration of the outage. The cache layer was designed to degrade gracefully (fall through to the database handler on a miss), but the bug inverts this: instead of a cache miss, every request becomes a hard error. This is an effective total API denial of service without any database or application logic being involved.

### Likelihood Explanation
An unprivileged external attacker can trigger this by exhausting the Redis connection pool (e.g., opening many TCP connections to the Redis port, or sending malformed commands that consume connection slots). No authentication is required. The attack is repeatable and can be sustained as long as the attacker maintains the connection pressure. Even non-malicious events (Redis restart, network blip) trigger the same outcome, making this a high-likelihood reliability bug as well as a security issue.

### Recommendation
Fix `getSingleWithTtl` to guard against `result` being `undefined` before accessing `result[1][1]`:

```js
async getSingleWithTtl(key) {
  if (!this.ready) return undefined;

  const result = await this.redis
    .multi()
    .ttl(key)
    .get(key)
    .exec()
    .catch((err) => {
      logger.warn(`Redis error during ttl/get: ${err.message}`);
      return null;   // explicit sentinel
    });

  if (!result) return undefined;   // <-- add this guard

  const rawValue = result[1][1];
  if (rawValue) {
    return {ttl: result[0][1], value: JSONParse(rawValue)};
  }
  return undefined;
}
```

Additionally, set `this.ready = false` synchronously on the `'error'` event (not only inside `retryStrategy`) to close the race-condition window.

### Proof of Concept

1. Deploy the mirror-node REST service with Redis enabled (`config.cache.response.enabled = true`, `config.redis.enabled = true`).
2. Wait for the service to connect to Redis (`this.ready = true`).
3. From an external host, exhaust Redis connections:
   ```bash
   # Open many TCP connections to Redis port without sending AUTH/QUIT
   for i in $(seq 1 200); do nc <redis-host> 6379 & done
   ```
4. While connections are saturated, send any API request:
   ```bash
   curl http://<mirror-node>/api/v1/accounts
   ```
5. **Observed**: HTTP 500 `Internal Server Error` for every request.
6. **Expected**: Cache miss → request forwarded to database handler → normal 200 response.
7. Confirm in server logs: `TypeError: Cannot read properties of undefined (reading '1')` originating from `cache.js:77`.