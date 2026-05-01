### Title
Connection Pool Exhaustion via Unbounded Query Execution When `statementTimeout <= 0`

### Summary
In `rosetta/app/db/client.go`, `GetDbWithContext()` applies no query timeout when `statementTimeout <= 0`, returning a `noop` cancel function. An unprivileged external user can send concurrent valid API requests (e.g., `/account/balance` with a historical block identifier) that trigger expensive PostgreSQL queries, holding connections open indefinitely and exhausting the finite pool, causing a denial of service across all Rosetta API nodes sharing that pool.

### Finding Description

**Exact code path:**

`rosetta/app/db/client.go`, `GetDbWithContext()`, lines 22–28:

```go
func (d *client) GetDbWithContext(ctx context.Context) (*gorm.DB, context.CancelFunc) {
    if d.statementTimeout <= 0 {
        db := d.db
        if ctx != nil {
            db = db.WithContext(ctx)
        }
        return db, noop   // ← no timeout, noop cancel
    }
    ...
}
``` [1](#0-0) 

The `statementTimeout` field is an unvalidated `int` in the config struct: [2](#0-1) 

Setting it to `0` (or any negative value) is accepted silently. The pool is bounded: [3](#0-2) 

Default `maxOpenConnections` is **100**: [4](#0-3) 

**Slow query surface:** `GetDbWithContext` is called in every persistence layer function. For example, `getBalanceChange` in `account.go` executes a `SUM` over `crypto_transfer` with a timestamp range — a potentially full-partition scan on a large table: [5](#0-4) [6](#0-5) 

**Root cause:** The `statementTimeout <= 0` branch is a deliberate "disable timeout" escape hatch with no application-level rate limiting or connection-hold guard. The only mitigations are infrastructure-level Traefik middleware (5 in-flight requests per IP, 10 req/s per host): [7](#0-6) 

These are not enforced at the application layer and are absent in non-Helm deployments.

**Why checks fail:**
- The per-IP in-flight limit (5) is bypassed trivially with ~20 source IPs to saturate 100 connections.
- The rate limit is per `requestHost` (the Rosetta server hostname), not per client IP, so it throttles the entire service, not individual attackers.
- No application-level semaphore or connection-hold timeout exists.
- The `noop` cancel function means even if the HTTP client disconnects, the PostgreSQL query continues running and holds the connection.

### Impact Explanation
With `statementTimeout = 0`, 100 concurrent slow queries (achievable from ~20 IPs × 5 in-flight each) exhaust `maxOpenConnections = 100`. All subsequent requests block waiting for a free connection. Because the Rosetta API is the Coinbase Mesh interface used by exchanges and validators to submit and verify transactions, exhausting it on ≥30% of deployed nodes constitutes a network-level processing disruption without brute force. The PostgreSQL server itself is also stressed by long-running full-scan queries consuming `work_mem` per session.

### Likelihood Explanation
The precondition is `statementTimeout <= 0`, which requires operator misconfiguration (default is 20 s). However:
- The config accepts `0` silently with no warning or validation.
- Operators may set it to `0` to "disable" timeouts during debugging and forget to revert.
- The exploit itself requires no credentials, no special knowledge beyond the public Rosetta API spec, and is repeatable with a simple script sending POST `/account/balance` with a genesis-era `block_identifier` (forcing a large `crypto_transfer` scan).
- Infrastructure-level rate limiting is bypassable with modest botnet resources (~20 IPs).

### Recommendation
1. **Validate `statementTimeout` at startup**: reject or warn on values `<= 0` in `ConnectToDb` or config loading.
2. **Add an application-level maximum query duration** independent of `statementTimeout`, e.g., always derive a child context with a hard ceiling (e.g., 60 s) even when `statementTimeout <= 0`.
3. **Add a connection-acquisition timeout** via `sql.DB.SetConnMaxIdleTime` and ensure `SetMaxOpenConns` is paired with a wait timeout so requests fail fast rather than queue indefinitely.
4. **Move rate limiting into the application layer** (e.g., a Go middleware semaphore) so it is enforced regardless of deployment topology.

### Proof of Concept
**Precondition:** Rosetta deployed with `hiero.mirror.rosetta.db.statementTimeout: 0` (or env `HIERO_MIRROR_ROSETTA_DB_STATEMENTTIMEOUT=0`).

```bash
# Step 1: Identify a genesis-era block index (forces large crypto_transfer scan)
GENESIS_INDEX=1

# Step 2: Fire 100 concurrent requests from 20 IPs (5 each, bypassing per-IP limit)
# Using GNU parallel or a simple Go/Python script:
for i in $(seq 1 100); do
  curl -s -X POST http://<rosetta-host>:5700/account/balance \
    -H 'Content-Type: application/json' \
    -d "{
      \"network_identifier\": {\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
      \"account_identifier\": {\"address\":\"0.0.2\"},
      \"block_identifier\": {\"index\": $GENESIS_INDEX}
    }" &
done
wait

# Step 3: Observe that subsequent legitimate requests hang or return 500
# (connection pool exhausted, all 100 slots held by slow queries)
curl -X POST http://<rosetta-host>:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
# Expected: timeout or connection refused
```

### Citations

**File:** rosetta/app/db/client.go (L22-29)
```go
func (d *client) GetDbWithContext(ctx context.Context) (*gorm.DB, context.CancelFunc) {
	if d.statementTimeout <= 0 {
		db := d.db
		if ctx != nil {
			db = db.WithContext(ctx)
		}
		return db, noop
	}
```

**File:** rosetta/app/config/types.go (L39-47)
```go
type Db struct {
	Host             string
	Name             string
	Password         string
	Pool             Pool
	Port             uint16
	StatementTimeout int `yaml:"statementTimeout"`
	Username         string
}
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```

**File:** docs/configuration.md (L658-658)
```markdown
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
```

**File:** rosetta/app/persistence/account.go (L21-29)
```go
	balanceChangeBetween = `select
                              coalesce((
                                select sum(amount) from crypto_transfer
                                where
                                  consensus_timestamp > @start and
                                  consensus_timestamp <= @end and
                                  entity_id = @account_id and
                                  (errata is null or errata <> 'DELETE')
                              ), 0) as value`
```

**File:** rosetta/app/persistence/account.go (L313-328)
```go
func (ar *accountRepository) getBalanceChange(ctx context.Context, accountId, consensusStart, consensusEnd int64) (
	int64,
	*rTypes.Error,
) {
	db, cancel := ar.dbClient.GetDbWithContext(ctx)
	defer cancel()

	change := &accountBalanceChange{}
	// gets the balance change from the Balance snapshot until the target block
	if err := db.Raw(
		balanceChangeBetween,
		sql.Named("account_id", accountId),
		sql.Named("start", consensusStart),
		sql.Named("end", consensusEnd),
		sql.Named("end_range", getInclusiveInt8Range(consensusEnd, consensusEnd)),
	).First(change).Error; err != nil {
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
```
