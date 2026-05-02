### Title
Unauthenticated `/block` Endpoint Triggers Unbounded Sequential DB Calls in `updateOperationAccountAlias()`, Enabling DB Connection Pool Exhaustion DoS

### Summary
The Rosetta `/block` endpoint requires no authentication and, for each uncached operation across all returned transactions, synchronously calls `GetAccountAlias()` which acquires a database connection. An attacker sending many concurrent `/block` requests targeting blocks with many transactions (each with many operations) and using unique account IDs to defeat the LRU cache can exhaust the DB connection pool (default: 100 connections), rendering the Rosetta API unable to serve any further requests.

### Finding Description

**Exact code path:**

`rosetta/app/services/block_service.go`, `Block()` (lines 47–74) calls `updateOperationAccountAlias()` (lines 104–130) after capping transactions to `maxTransactionsInBlock`. Inside `updateOperationAccountAlias()`, for every operation whose `accountId.GetId()` is not in the LRU cache, it calls:

```go
result, err := s.accountRepo.GetAccountAlias(ctx, accountId)  // line 116
```

`GetAccountAlias()` in `rosetta/app/persistence/account.go` (lines 109–136) calls:

```go
db, cancel := ar.dbClient.GetDbWithContext(ctx)  // line 113
defer cancel()
db.Raw(selectCryptoEntityWithAliasById, ...).First(&entity)  // line 117
```

`GetDbWithContext()` in `rosetta/app/db/client.go` (lines 22–38) creates a child context with a `statementTimeout`-bounded deadline and returns a `*gorm.DB` backed by the shared `database/sql` connection pool. Each `.First()` call acquires a connection from the pool, executes the query, and releases it — but across many concurrent goroutines (one per HTTP request), the pool is shared.

**Root cause:** There is no application-level rate limiting, concurrency cap, or request-level DB call budget in the Rosetta server itself. The server is wired in `rosetta/main.go` (lines 217–219) with only CORS, metrics, and tracing middleware — no throttle. The Traefik middleware (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–166) providing `inFlightReq: amount: 5` and `rateLimit: average: 10` is optional Kubernetes infrastructure not present in standalone deployments.

**Cache bypass:** The LRU cache (default `maxSize` = 524288, per `docs/configuration.md` line 654) is keyed by `accountId.GetId()` (the numeric entity ID). On a live network with many distinct accounts, or by targeting blocks containing transactions from many unique accounts never previously queried, an attacker trivially causes cache misses for every operation.

**Failed assumption:** The design assumes the entity cache will absorb most lookups. This holds for a warm cache under normal load but fails under adversarial conditions with unique account IDs.

### Impact Explanation

With the default pool of 100 open connections (`hiero.mirror.rosetta.db.pool.maxOpenConnections` = 100, `docs/configuration.md` line 660), an attacker running ~20–50 concurrent `/block` requests, each processing `maxTransactionsInBlock` transactions with many operations and unique account IDs, can saturate all available connections. Once the pool is exhausted, every subsequent DB call blocks until a connection is freed or the statement timeout (default 20 seconds) fires. This causes all Rosetta API endpoints — `/block`, `/account/balance`, `/network/status` — to time out or return errors, making the Rosetta mirror node unable to confirm or report new transactions. The importer's separate connection pool is unaffected, but the Rosetta API becomes completely unavailable.

### Likelihood Explanation

The `/block` endpoint is publicly documented and requires zero credentials. An attacker needs only HTTP access to port 5700. Identifying blocks with many transactions is trivial via `/network/status` to get the latest block index, then iterating. On Hedera mainnet, blocks regularly contain hundreds of transactions. The attack is repeatable, requires no special knowledge, and can be automated with a simple script. Without Traefik or an external WAF, there is no defense at the application layer.

### Recommendation

1. **Batch DB lookups**: Replace the per-operation `GetAccountAlias()` loop with a single bulk query fetching aliases for all unique account IDs in the request, reducing N DB calls to 1.
2. **Add application-level concurrency limiting**: Use a semaphore or worker pool to cap the number of concurrent in-flight `/block` requests processed at the DB layer.
3. **Enforce `maxTransactionsInBlock` and add a per-transaction operation cap**: Bound the maximum number of operations processed per request to limit worst-case DB calls.
4. **Make Traefik middleware mandatory**: Document and enforce the `inFlightReq` and `rateLimit` middleware as required, not optional, for production deployments.
5. **Consider request-scoped DB call budgets**: Return an error if a single request would require more than a configurable number of DB calls.

### Proof of Concept

```bash
# 1. Identify a block with many transactions
BLOCK=$(curl -s -X POST http://<rosetta-host>:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  | jq '.current_block_identifier.index')

# 2. Send 100 concurrent /block requests targeting that block
for i in $(seq 1 100); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
         \"block_identifier\":{\"index\":$BLOCK}}" &
done
wait

# 3. Observe subsequent requests timing out or returning DB errors
curl -X POST http://<rosetta-host>:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
# Expected: timeout or {"code":500,...} due to pool exhaustion
```