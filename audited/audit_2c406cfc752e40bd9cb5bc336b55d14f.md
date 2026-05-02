### Title
Unauthenticated `/health/readiness` Endpoint Enables DB Pool Exhaustion Leading to Forced Not-Ready State

### Summary
The `createTerminus` call in `rest/server.js` registers `/health/readiness` directly on the raw HTTP server, bypassing all Express middleware (including `authHandler` and any rate limiting). Each request to this endpoint executes a live database query against the shared connection pool. An unprivileged external attacker can flood this endpoint to exhaust the pool's 10 default connections, causing the Kubernetes readiness probe — which calls the same endpoint — to time out and mark the pod not-ready, removing it from load-balancer rotation and creating an intermittent network partition for legitimate users.

### Finding Description

**Code path:**

`rest/server.js` lines 159–166: `createTerminus` is called with the raw `server` object (not the Express `app`). `@godaddy/terminus` intercepts requests at the `http.Server` `request` event level, before Express middleware runs. This means `/health/readiness` and `/health/liveness` are served entirely outside the Express middleware chain — `authHandler`, rate limiting, and any other middleware registered via `app.use()` or `app.useExt()` never execute for these paths. [1](#0-0) 

`rest/health.js` lines 22–33: `readinessCheck` calls `pool.query(readinessQuery)` on the **shared global pool** — the same pool used by all API request handlers. There is no dedicated health-check connection, no circuit breaker, and no timeout shorter than the pool's `connectionTimeoutMillis`. [2](#0-1) 

`rest/dbpool.js` lines 13–14: The pool is configured with `max: config.db.pool.maxConnections`. The documented default is **10 connections** with a `connectionTimeoutMillis` of **20,000 ms**. [3](#0-2) [4](#0-3) 

**Root cause:** The failed assumption is that health check endpoints are only called by internal Kubernetes probes. In reality, `createTerminus` exposes them as unauthenticated, rate-unlimited HTTP endpoints on the public-facing port (`0.0.0.0:5551`), and each invocation consumes a shared DB pool connection.

**Exploit flow:**
1. Attacker sends ≥10 concurrent HTTP GET requests to `http://<host>:5551/health/readiness`.
2. Each request calls `pool.query('select true from address_book limit 1')`, acquiring a pool connection.
3. While those connections are held (or while the attacker sustains the flood), the pool is at capacity.
4. The Kubernetes readiness probe fires (default `periodSeconds: 10`, `timeoutSeconds: 2`). It calls the same endpoint; `pool.query()` blocks waiting for a free connection.
5. The probe's 2-second timeout elapses before a connection is released → terminus returns 503 → Kubernetes marks the pod not-ready → the pod is removed from the Service's endpoint slice.
6. Legitimate user traffic is redirected away (network partition). When the attacker pauses, the pod recovers. Repeated bursts cause oscillation.

**Why existing checks fail:**

- `authHandler` (`rest/middleware/authHandler.js`) is registered on the Express `app`, not on the raw `http.Server`. Terminus intercepts the request before Express sees it, so `authHandler` is never invoked for `/health/readiness`. [5](#0-4) 
- There is no `healthCheckInterval` or `healthChecks` caching option passed to `createTerminus`, so every HTTP request triggers a fresh DB query. [1](#0-0) 
- No network policy, ingress rate limit, or connection limit is applied to the health-check path in the Helm chart values. [6](#0-5) 

### Impact Explanation
A successful attack removes one or more REST API pods from the Kubernetes Service endpoint slice, making the mirror node REST API unavailable to all legitimate users routed to those pods. Because the attack is repeatable on a cycle matching the Kubernetes probe interval (default 10 s), the attacker can sustain the not-ready state indefinitely with a low-rate flood (≥10 concurrent requests every few seconds). This constitutes a full availability denial for the affected pod(s) with no data exfiltration required.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public port number, and no exploit tooling beyond `curl` or any HTTP load tool. The pool size of 10 is small enough that even a single attacker with modest bandwidth can exhaust it. The endpoint is reachable from the internet in any deployment that exposes the REST API publicly (the default Helm chart enables an ingress). The attack is fully repeatable and leaves no persistent state.

### Recommendation
1. **Dedicate a separate DB connection (or use a lightweight check):** Replace `pool.query(readinessQuery)` in `readinessCheck` with a connection that is not drawn from the shared application pool, or replace the DB query with a check that does not consume a pool slot (e.g., check `pool.totalCount < pool.options.max`).
2. **Cache the health result in terminus:** Pass `healthCheckInterval` to `createTerminus` so the result is cached between Kubernetes probe calls rather than re-evaluated on every HTTP request.
3. **Restrict the health endpoints to internal/cluster traffic only:** Apply a Kubernetes `NetworkPolicy` or ingress rule that allows `/health/*` only from the kubelet CIDR and internal monitoring, not from the public internet.
4. **Apply rate limiting at the raw server level:** If the endpoints must remain public, add a per-IP rate limiter that fires before terminus handles the request (e.g., via an ingress annotation or a Node.js `http` interceptor registered before terminus).

### Proof of Concept
```bash
# Exhaust the 10-connection pool with concurrent requests
# (repeat in a loop to sustain the not-ready state)
for i in $(seq 1 20); do
  curl -s http://<mirror-node-host>:5551/health/readiness &
done
wait

# Observe Kubernetes pod readiness oscillation:
kubectl get endpoints <mirror-rest-service> -w
# Pod will disappear from ENDPOINTS list within one probe cycle (~10s)
# and reappear when the flood stops, demonstrating oscillation.
```

### Citations

**File:** rest/server.js (L159-166)
```javascript
  createTerminus(server, {
    healthChecks: {
      '/health/readiness': health.readinessCheck,
      '/health/liveness': health.livenessCheck,
    },
    logger: (msg, err) => logger.error(msg, err),
    onShutdown: health.onShutdown,
  });
```

**File:** rest/health.js (L22-33)
```javascript
const readinessCheck = async () => {
  return pool
    .query(readinessQuery)
    .catch((err) => {
      throw new DbError(err.message);
    })
    .then((results) => {
      if (results.rowCount !== 1) {
        throw new NotFoundError('Application readiness check failed');
      }
    });
};
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** charts/hedera-mirror-rest/values.yaml (L300-309)
```yaml
startupProbe:
  failureThreshold: 120
  httpGet:
    path: /health/liveness
    port: http
  initialDelaySeconds: 0
  periodSeconds: 1
  timeoutSeconds: 2

terminationGracePeriodSeconds: 60
```
