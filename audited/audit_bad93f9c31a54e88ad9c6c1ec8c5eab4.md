### Title
Indefinite Goroutine Hang in `resolveAccountAliases()` When DB Statement Timeout Is Disabled

### Summary
When `statementTimeout` is configured to `0` or a negative value, `GetDbWithContext()` in `rosetta/app/db/client.go` attaches no deadline to the database context and returns a no-op cancel function. During a network partition affecting the PostgreSQL backend, any call to `c.accountRepo.GetAccountId()` inside `resolveAccountAliases()` will block indefinitely. An unprivileged attacker who sends repeated `/construction/metadata` requests with the `account_aliases` option during such a partition can accumulate unbounded hanging goroutines, exhausting server memory and causing a denial of service.

### Finding Description
**Exact code path:**

`ConstructionMetadata()` → `resolveAccountAliases()` → `c.accountRepo.GetAccountId(ctx, accountId)` → `ar.dbClient.GetDbWithContext(ctx)` → `db.Raw(...).First(&entity)` blocks.

In `rosetta/app/db/client.go` lines 22–28, when `d.statementTimeout <= 0`, the function returns the GORM DB instance with only the caller-supplied context and a `noop` cancel function — no child context with a deadline is created:

```go
if d.statementTimeout <= 0 {
    db := d.db
    if ctx != nil {
        db = db.WithContext(ctx)
    }
    return db, noop   // ← no timeout, noop cancel
}
```

The `ctx` passed in is the raw HTTP request context from Go's `net/http`. Go's `net/http` `WriteTimeout` (default 10 s) closes the TCP connection to the client but **does not cancel `r.Context()`**. The handler goroutine continues running. Because no deadline exists on the context, the GORM `First()` call at `account.go:150` blocks indefinitely waiting for a response from the unreachable database.

`resolveAccountAliases()` at `construction_service.go:575–584` iterates over every alias in the comma-separated `account_aliases` option, calling `GetAccountId()` for each one synchronously. Each call blocks the goroutine for the entire duration of the partition.

**Why existing checks are insufficient:**

- The default `statementTimeout` is 20 s (documented in `docs/configuration.md:662`), which would normally bound the hang. However, the code explicitly supports `statementTimeout <= 0` as a valid operational mode (the branch at `client.go:23` is intentional), and operators may set it to `0` to remove query-level timeouts for performance reasons.
- The HTTP `WriteTimeout` (default 10 s, `main.go:226`) only terminates the client-facing TCP write; it does not propagate cancellation into the handler goroutine's context.
- There is no per-request context deadline injected by the Rosetta SDK router or any middleware visible in the codebase.
- There is no rate-limiting or concurrency cap on `/construction/metadata` requests in the middleware chain (`main.go:217–219`).

### Impact Explanation
With `statementTimeout = 0`, every `/construction/metadata` request carrying an `account_aliases` option during a DB partition spawns a goroutine that never terminates until the partition ends or the process is killed. Go goroutines consume ~8 KB of stack each (growing as needed). An attacker sending requests at even a modest rate (e.g., 100 req/s) accumulates tens of thousands of goroutines within minutes, exhausting heap memory and crashing the process. Even before OOM, the DB connection pool (default max 100 open connections, `docs/configuration.md:660`) is saturated, blocking all other legitimate DB-dependent endpoints (block queries, balance queries, etc.), causing a full service outage.

### Likelihood Explanation
The attack requires no credentials — the Rosetta `/construction/metadata` endpoint is a public, unauthenticated HTTP POST endpoint. The attacker only needs to supply a JSON body with `options.account_aliases` set to any syntactically valid alias string (e.g., `"0.0.12345"`). The network partition is an external precondition, but it can be induced by an attacker with network-layer access (BGP hijack, firewall rule injection, cloud security-group manipulation) or exploited opportunistically during any infrastructure incident. The attack is trivially repeatable with a simple HTTP client loop and requires no special knowledge of the system beyond the public Rosetta API specification.

### Recommendation
1. **Enforce a minimum positive `statementTimeout`**: Remove the `<= 0` bypass branch or treat `0` as "use a safe default" rather than "no timeout". A value of `0` should not disable the timeout entirely.
2. **Inject a per-request deadline at the HTTP handler layer**: Wrap the server's base context with `context.WithTimeout` in a middleware before it reaches any handler, so all downstream DB calls inherit a hard deadline regardless of `statementTimeout` configuration.
3. **Validate configuration at startup**: Reject or warn loudly if `statementTimeout <= 0` is configured, since it removes the only DB-level safety net.
4. **Add concurrency limiting middleware**: Apply a semaphore or token-bucket rate limiter on `/construction/metadata` to cap the number of in-flight requests.

### Proof of Concept
**Preconditions:**
- Rosetta server running in online mode with `hiero.mirror.rosetta.db.statementTimeout: 0` (or any value ≤ 0).
- Network partition between the Rosetta server and its PostgreSQL backend (e.g., `iptables -A OUTPUT -p tcp --dport 5432 -j DROP` on the Rosetta host).

**Steps:**
```bash
# 1. Induce partition (on Rosetta host or network device)
iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# 2. Flood /construction/metadata with account_aliases from any unprivileged client
while true; do
  curl -s -X POST http://<rosetta-host>:5700/construction/metadata \
    -H 'Content-Type: application/json' \
    -d '{
      "network_identifier": {"blockchain":"Hedera","network":"mainnet"},
      "options": {
        "operation_type": "CRYPTO_TRANSFER",
        "account_aliases": "0.0.800"
      }
    }' &
done

# 3. Observe goroutine accumulation via pprof or process memory growth
curl http://<rosetta-host>:5700/debug/pprof/goroutine?debug=1
```

**Result:** Each background `curl` spawns a server goroutine that blocks indefinitely inside `db.Raw(...).First(&entity)` at `account.go:150`. Memory grows unboundedly; the process eventually OOMs or the DB connection pool is exhausted, denying service to all users.