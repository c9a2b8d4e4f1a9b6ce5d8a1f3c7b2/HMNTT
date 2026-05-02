### Title
Hardcoded `sslmode=disable` in Rosetta DB DSN Exposes All Database Traffic to Plaintext Interception

### Summary
The `GetDsn()` method in `rosetta/app/config/types.go` unconditionally appends `sslmode=disable` to every PostgreSQL connection string, forcing all Rosetta-to-database traffic to be unencrypted. Unlike other components (e.g., Web3 API), there is no configuration field or override mechanism to enable TLS. Any attacker with passive network access on the path between the Rosetta service and the database can read all SQL queries and responses in plaintext.

### Finding Description
**Exact code location:**

`rosetta/app/config/types.go`, `GetDsn()`, line 51:
```go
return fmt.Sprintf(
    "host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
    db.Host, db.Port, db.Username, db.Name, db.Password,
)
```

The `Db` struct (lines 39–47) has no `SslMode` field. The string literal `sslmode=disable` is hardcoded and cannot be overridden by any configuration key — the Rosetta configuration table (docs lines 652–675) lists no SSL option for the DB, in contrast to `hiero.mirror.web3.db.sslMode` which exists for the Web3 component.

`ConnectToDb()` in `rosetta/app/db/db.go` line 18 calls `dbConfig.GetDsn()` directly, and the health check in `rosetta/app/middleware/health.go` line 42 also calls `rosettaConfig.Db.GetDsn()` — both inherit the hardcoded `sslmode=disable`.

In PostgreSQL's libpq, `sslmode=disable` is an **absolute directive**: the client refuses to negotiate TLS even if the server requires it. This is not a default that can be overridden server-side.

**Root cause:** The DSN builder hardcodes the SSL mode as a string literal rather than reading it from a configurable struct field, making it impossible to enable encryption without modifying source code.

### Impact Explanation
Every SQL query issued by the Rosetta service — including account balance lookups, transaction history, and block data — travels over the network in plaintext. An attacker who can observe traffic on the database network segment (e.g., via ARP spoofing on a shared LAN, a compromised network device, or a cloud VPC mirror) can:
- Read all query results, including financial/ledger data
- Capture database credentials transmitted in the DSN (password field) on reconnect
- Perform passive, undetectable, ongoing surveillance of all Rosetta DB activity

Severity: **High** — confidentiality of all database communication is permanently broken with no operator recourse.

### Likelihood Explanation
The precondition is network-level access between the Rosetta process and the PostgreSQL server. In cloud deployments this is achievable via a compromised host on the same subnet, a misconfigured security group, or a cloud provider's traffic mirroring feature. In on-premise deployments, ARP poisoning or a rogue switch port achieves the same. The attack is entirely passive (no packets sent to the target), repeatable indefinitely, and leaves no application-layer log entries. The hardcoded nature means **every** Rosetta deployment is affected regardless of operator intent.

### Recommendation
1. Add an `SslMode string` field to the `Db` struct in `rosetta/app/config/types.go`.
2. Change `GetDsn()` to interpolate the field: `sslmode=%s` using `db.SslMode`.
3. Set the default value in the embedded default config YAML to `require` (or `verify-full` for mutual TLS).
4. Document the new `hiero.mirror.rosetta.db.sslMode` configuration key, mirroring the existing `hiero.mirror.web3.db.sslMode` option.
5. Update `TestDbGetDsn` to assert the new default.

### Proof of Concept
**Preconditions:** Attacker has passive packet capture capability on the network path between the Rosetta service host and the PostgreSQL host (e.g., same subnet).

**Steps:**
1. Start `tcpdump` or Wireshark on the relevant interface filtering for port 5432:
   ```
   tcpdump -i eth0 -A 'tcp port 5432'
   ```
2. Trigger any Rosetta API call (e.g., `POST /network/status`).
3. Observe in the capture output: the PostgreSQL wire protocol startup message, query strings (e.g., `SELECT ... FROM transaction ...`), and full result rows — all in plaintext ASCII.
4. The DSN used is confirmed by the unit test `TestDbGetDsn` in `rosetta/app/config/types_test.go` line 24, which asserts the output contains `sslmode=disable`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rosetta/app/config/types.go (L49-58)
```go
func (db Db) GetDsn() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
		db.Host,
		db.Port,
		db.Username,
		db.Name,
		db.Password,
	)
}
```

**File:** rosetta/app/db/db.go (L17-18)
```go
func ConnectToDb(dbConfig config.Db) interfaces.DbClient {
	db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), &gorm.Config{Logger: gormlogrus.New()})
```

**File:** rosetta/app/middleware/health.go (L42-43)
```go
			Check:     postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
		},
```

**File:** rosetta/app/config/types_test.go (L24-26)
```go
	expected := "host=127.0.0.1 port=5432 user=mirror_user dbname=mirror_node password=mirror_user_pass sslmode=disable"

	assert.Equal(t, expected, db.GetDsn())
```
