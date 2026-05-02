### Title
Insecure Default Allows Connection Pool Exhaustion via Unbounded Query Execution in `GetDbWithContext()`

### Summary
When `statementTimeout` is not explicitly configured, its Go zero-value (`0`) causes `GetDbWithContext()` to skip all application-level query timeouts. Combined with `MaxOpenConnections` also defaulting to `0` (unlimited in `database/sql`), an unprivileged attacker can flood the Rosetta API with expensive queries that hold PostgreSQL connections indefinitely, exhausting the pool and denying service to all Hashgraph history queries.

### Finding Description
**Exact code path:**

In `rosetta/app/db/client.go` lines 23–29: [1](#0-0) 

When `d.statementTimeout <= 0`, the function returns the DB with only the raw request context attached — no `context.WithTimeout` is applied. The `statementTimeout` field is an `int` in `config.Db`: [2](#0-1) 

Go's zero value for `int` is `0`, so any deployment that omits `statementTimeout` from its config silently enters the no-timeout branch. This is wired directly from config in `db.go`: [3](#0-2) 

The connection pool is configured from `Pool.MaxOpenConnections`: [4](#0-3) 

`Pool.MaxOpenConnections` is also an `int` defaulting to `0`. In Go's `database/sql`, `SetMaxOpenConns(0)` means **unlimited** open connections. The HTTP server timeouts (`ReadTimeout`, `WriteTimeout`, etc.) are `time.Duration` fields: [5](#0-4) 

These also default to `0` (no timeout) if unconfigured. No rate-limiting middleware is present in the visible codebase. The result: with all three defaults in place, every inbound HTTP request can open a new PostgreSQL connection and hold it for an arbitrarily long time.

**Root cause / failed assumption:** The code assumes operators will always set a positive `statementTimeout`. There is no enforcement of a safe minimum, no fallback default, and no rate limiting to bound concurrent connections.

### Impact Explanation
An attacker can exhaust all available PostgreSQL connections, causing every subsequent Rosetta API call that invokes `GetDbWithContext()` — including `account.go`, `block.go`, `transaction.go`, and `address_book_entry.go` — to block or fail. This renders the entire Hashgraph history query surface unavailable (full DoS). PostgreSQL itself may also become unresponsive to other consumers of the same database. [6](#0-5) 

### Likelihood Explanation
The precondition (default zero-value config) is the **out-of-the-box state** for any deployment that does not explicitly set `statementTimeout`, `maxOpenConnections`, and HTTP timeouts. No authentication or privilege is required to call Rosetta API endpoints. The attack is trivially repeatable with any HTTP load tool (e.g., `ab`, `wrk`, `hey`) and requires no special knowledge of the system.

### Recommendation
1. **Enforce a safe default**: In `NewDbClient` or `ConnectToDb`, if `statementTimeout <= 0`, apply a hardcoded safe default (e.g., 30 seconds) rather than skipping the timeout entirely.
2. **Enforce a connection pool cap**: Never call `SetMaxOpenConns(0)`; require a positive value or apply a safe default (e.g., 10–50).
3. **Enforce HTTP server timeouts**: Validate that `ReadTimeout` and `WriteTimeout` are non-zero at startup.
4. **Add rate limiting**: Apply a per-IP or global concurrency limit middleware on the HTTP server.

### Proof of Concept
**Preconditions:** Rosetta deployed with default config (no `statementTimeout`, no `maxOpenConnections`, no HTTP timeouts set).

**Steps:**
```bash
# 1. Identify a slow/expensive Rosetta endpoint (e.g., /block/transaction with a large block)
# 2. Flood it with concurrent requests
hey -n 10000 -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{"index":1}}' \
  http://<rosetta-host>:5700/block

# 3. Observe PostgreSQL connection count spike to system max:
psql -c "SELECT count(*) FROM pg_stat_activity;"

# 4. All subsequent legitimate requests return errors or hang indefinitely.
```

**Result:** PostgreSQL connection pool saturated; Rosetta API unable to serve any Hashgraph history queries.

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

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```

**File:** rosetta/app/db/db.go (L35-35)
```go
	return NewDbClient(db, dbConfig.StatementTimeout)
```

**File:** rosetta/app/persistence/block.go (L1-5)
```go
// SPDX-License-Identifier: Apache-2.0

package persistence

import (
```
