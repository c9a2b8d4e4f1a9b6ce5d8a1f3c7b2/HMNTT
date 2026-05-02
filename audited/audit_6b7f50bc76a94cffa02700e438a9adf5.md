### Title
Unauthenticated Connection Pool Exhaustion via Concurrent `/block` Requests (DoS)

### Summary
The Rosetta API exposes the `/block` endpoint with no authentication, no rate limiting, and no per-client concurrency control. Each request acquires one or more DB connections from a bounded pool (`Pool.MaxOpenConnections`) and holds them for up to `Db.StatementTimeout` seconds via a Go context deadline. An unprivileged attacker can flood the endpoint with concurrent requests, exhaust the pool, and force all subsequent legitimate block queries to queue indefinitely, effectively freezing the API's ability to serve block and transaction data.

### Finding Description

**Code path:**

`rosetta/app/config/types.go` defines the bounded pool and timeout: [1](#0-0) [2](#0-1) 

`rosetta/app/db/db.go` enforces the hard cap on open connections: [3](#0-2) 

`rosetta/app/db/client.go` wraps every query in a context that lives for the full `statementTimeout` duration: [4](#0-3) 

`rosetta/main.go` assembles the middleware stack with **no rate-limiting layer**: [5](#0-4) 

`rosetta/app/services/block_service.go` issues multiple sequential DB calls per `/block` request (`RetrieveBlock`, `FindBetween`, `updateOperationAccountAlias`), each independently acquiring a connection: [6](#0-5) 

**Root cause:** `database/sql`'s `SetMaxOpenConns` creates a hard ceiling on concurrent connections. When that ceiling is reached, new `db.Raw(...)` calls block until a connection is freed. The maximum time any connection is held equals `statementTimeout` seconds (the context deadline). Because Go's `net/http` spawns a goroutine per request with no admission control, an attacker can trivially saturate the pool.

**Failed assumption:** The design assumes that the statement timeout is a *safety valve* that bounds connection hold time. In practice it becomes the *attack window*: the attacker only needs to keep `MaxOpenConnections` requests in-flight simultaneously, each for up to `statementTimeout` seconds, to deny service to all other callers.

### Impact Explanation
All legitimate `/block`, `/block/transaction`, `/network/status`, and `/account/balance` calls share the same pool. Once exhausted, every new query blocks in `database/sql`'s internal wait queue with no timeout of its own. The Rosetta API becomes unresponsive for the duration of the attack. Because the Rosetta API is the interface through which indexers and exchanges observe finalized blocks and transactions, sustained pool exhaustion prevents any downstream system from confirming transaction finality — matching the "freezing transaction processing" criterion in the question.

### Likelihood Explanation
No privileges, credentials, or special network position are required. The `/block` endpoint is publicly reachable, accepts unauthenticated POST requests, and the Rosetta protocol specification does not mandate authentication. The attack is trivially scriptable with any HTTP load tool (`wrk`, `hey`, `ab`). The attacker needs only to keep `MaxOpenConnections` goroutines alive simultaneously, which is achievable from a single machine. The attack is repeatable and stateless.

### Recommendation
1. **Add a concurrency/rate-limiting middleware** before the router (e.g., `golang.org/x/time/rate` or a semaphore-based middleware) to cap simultaneous in-flight requests per IP and globally.
2. **Set a short `Pool.MaxOpenConnections`-aware queue timeout** by passing a deadline-bounded context from the HTTP layer all the way through, so queued DB waiters fail fast rather than accumulating.
3. **Propagate the HTTP server's `WriteTimeout` as the outer context deadline** for each request, ensuring that even if the DB pool is saturated, the HTTP handler returns an error before the write deadline expires rather than holding a goroutine indefinitely.
4. **Consider a PostgreSQL-side `statement_timeout`** (a `SET LOCAL statement_timeout` at the session level) as a defense-in-depth measure independent of the Go context.

### Proof of Concept
```bash
# Assuming MaxOpenConnections=20, StatementTimeout=10 (seconds)
# Step 1: flood with 50 concurrent /block requests (latest block, no index/hash)
seq 1 50 | xargs -P50 -I{} curl -s -X POST http://<rosetta-host>:8082/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{}}' &

# Step 2: immediately issue a legitimate /block request and measure latency
time curl -s -X POST http://<rosetta-host>:8082/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{}}'

# Expected result: the legitimate request hangs for up to StatementTimeout seconds
# (or until a connection slot is freed), demonstrating pool exhaustion.
```

### Citations

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

**File:** rosetta/app/config/types.go (L77-81)
```go
type Pool struct {
	MaxIdleConnections int `yaml:"maxIdleConnections"`
	MaxLifetime        int `yaml:"maxLifetime"`
	MaxOpenConnections int `yaml:"maxOpenConnections"`
}
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```

**File:** rosetta/app/db/client.go (L22-38)
```go
func (d *client) GetDbWithContext(ctx context.Context) (*gorm.DB, context.CancelFunc) {
	if d.statementTimeout <= 0 {
		db := d.db
		if ctx != nil {
			db = db.WithContext(ctx)
		}
		return db, noop
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// #nosec G118
	childCtx, cancel := context.WithTimeout(ctx, time.Duration(d.statementTimeout)*time.Second)
	return d.db.WithContext(childCtx), cancel
}
```

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** rosetta/app/services/block_service.go (L51-73)
```go
	block, err := s.RetrieveBlock(ctx, request.BlockIdentifier)
	if err != nil {
		return nil, err
	}

	if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
		return nil, err
	}

	var otherTransactions []*rTypes.TransactionIdentifier
	if len(block.Transactions) > s.maxTransactionsInBlock {
		otherTransactions = make([]*rTypes.TransactionIdentifier, 0, len(block.Transactions)-s.maxTransactionsInBlock)
		for _, transaction := range block.Transactions[s.maxTransactionsInBlock:] {
			otherTransactions = append(otherTransactions, &rTypes.TransactionIdentifier{Hash: transaction.Hash})
		}
		block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
	}

	if err = s.updateOperationAccountAlias(ctx, block.Transactions...); err != nil {
		return nil, err
	}

	return &rTypes.BlockResponse{Block: block.ToRosetta(), OtherTransactions: otherTransactions}, nil
```
