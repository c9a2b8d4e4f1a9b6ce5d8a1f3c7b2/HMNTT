### Title
Hardcoded `sslmode=disable` in `GetDsn()` Enables Network-Level PostgreSQL Credential and Data Interception

### Summary
`GetDsn()` in `rosetta/app/config/types.go` hardcodes `sslmode=disable` unconditionally in the PostgreSQL DSN, with no configuration field to override it. This forces all PostgreSQL wire-protocol traffic — including the authentication handshake and all query data — to travel unencrypted. An attacker with access to the network path between the Rosetta service and the PostgreSQL instance can passively capture and decode this traffic, extracting credentials and sensitive ledger data.

### Finding Description
**Exact code location:** [1](#0-0) 

`GetDsn()` constructs the DSN with a hardcoded `sslmode=disable` literal. The `Db` struct has no `SSLMode` field: [2](#0-1) 

This DSN is consumed directly by the production database connection in `ConnectToDb()`: [3](#0-2) 

**Root cause:** `sslmode=disable` is a compile-time constant in the format string. There is no `SSLMode` field in `Db`, no environment variable override path for it, and no YAML config key for it. Even a security-conscious operator cannot enable TLS for this connection without modifying source code.

**Exploit flow:**
1. Attacker gains a position on the L2/L3 path between the Rosetta pod and the PostgreSQL instance (e.g., compromised sidecar, ARP poisoning on a flat cloud VPC subnet, compromised network device, or a co-tenant in a shared Kubernetes namespace using a CNI without network policy).
2. Attacker runs a passive capture (`tcpdump -i eth0 port 5432 -w capture.pcap`).
3. When Rosetta starts or reconnects, the PostgreSQL startup message transmits the `Username` field in cleartext as part of the wire protocol.
4. Depending on `pg_hba.conf` auth method:
   - **`password` (cleartext):** Password transmitted verbatim — full credential recovery.
   - **`md5`:** Server sends a 4-byte salt in cleartext; client responds with `md5(md5(password||username)||salt)`. Attacker captures both, performs offline dictionary/brute-force attack against the MD5 hash.
   - **`scram-sha-256`:** Full SCRAM exchange captured unencrypted; offline attack is harder but the entire exchange is available.
5. Beyond credentials, every SQL query and result set (containing mirror node ledger data) is also captured in cleartext.

**Why existing checks are insufficient:**
The config loader in `config.go` masks the password in logs (`mirrorConfig.Rosetta.Db.Password = "***"`): [4](#0-3) 

This only prevents log-based leakage. It has no effect on the wire-level exposure caused by `sslmode=disable`. There is no network-layer encryption, no TLS certificate validation, and no mechanism to enforce SSL from the application side.

The test harness also hardcodes `sslmode=disable` for its Docker-based PostgreSQL, confirming this is a systemic pattern and not an isolated oversight: [5](#0-4) 

### Impact Explanation
- **Credential theft:** Username is always exposed in cleartext in the PostgreSQL startup message. Password is exposed in cleartext or as a crackable MD5 hash depending on server configuration.
- **Data exfiltration:** All SQL queries and responses (mirror node transaction data, account data, balances) are transmitted unencrypted.
- **No operator mitigation path:** Because `sslmode=disable` is hardcoded and `Db` has no `SSLMode` field, operators cannot enable TLS without patching source code. This makes the vulnerability permanent in any deployed binary.
- **Severity: High** — complete loss of confidentiality for the database channel.

### Likelihood Explanation
- **Precondition:** Attacker must be on the network path between Rosetta and PostgreSQL. In Kubernetes/cloud deployments without strict network policy, this is achievable by a compromised workload in the same namespace or VPC subnet.
- **Skill required:** Passive packet capture with `tcpdump`/Wireshark is entry-level. MD5 cracking with `hashcat` is well-documented.
- **Repeatability:** Every connection attempt (startup, reconnect) re-exposes credentials. The attack is passive and leaves no application-level trace.
- **Realistic deployment context:** Mirror node is a public blockchain infrastructure component. Its database contains sensitive operational data, making it a high-value target. Cloud-native deployments on flat subnets are common.

### Recommendation
1. Add an `SSLMode` field to the `Db` struct with a secure default (e.g., `"require"` or `"verify-full"`):
   ```go
   type Db struct {
       ...
       SSLMode string `yaml:"sslMode"`
   }
   ```
2. Update `GetDsn()` to use the configurable value:
   ```go
   func (db Db) GetDsn() string {
       sslMode := db.SSLMode
       if sslMode == "" {
           sslMode = "require" // secure default
       }
       return fmt.Sprintf(
           "host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
           db.Host, db.Port, db.Username, db.Name, db.Password, sslMode,
       )
   }
   ```
3. Set the default in `application.yml` to `require` or `verify-full` and document the CA certificate configuration.
4. For production deployments, use `sslmode=verify-full` with a trusted CA to prevent both eavesdropping and MITM attacks.

### Proof of Concept
```bash
# 1. On a host with network access to the Rosetta→PostgreSQL path:
tcpdump -i eth0 -w pg_capture.pcap 'tcp port 5432'

# 2. Restart or wait for Rosetta to connect to PostgreSQL.
#    The PostgreSQL startup message will contain the username in cleartext.

# 3. Open capture in Wireshark; apply filter: pgsql
#    The "Startup Message" frame will show: user=mirror_user (cleartext)
#    If pg_hba.conf uses 'password' method, the PasswordMessage frame
#    will contain the password in cleartext.

# 4. If pg_hba.conf uses 'md5':
#    Extract the AuthenticationMD5Password salt (4 bytes) and
#    the PasswordMessage hash from the capture, then:
hashcat -m 11400 -a 0 captured_md5_hash wordlist.txt
# Format: md5(md5(password||username)||salt)

# 5. Use recovered credentials to connect directly to PostgreSQL:
psql -h <db_host> -U mirror_user -d mirror_node
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

**File:** rosetta/app/config/config.go (L93-96)
```go
	var password = mirrorConfig.Rosetta.Db.Password
	mirrorConfig.Rosetta.Db.Password = "***" // Don't print password
	log.Infof("Using configuration: %+v", &config)
	mirrorConfig.Rosetta.Db.Password = password
```

**File:** rosetta/test/db/db.go (L84-86)
```go
func (d dbParams) toDsn() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", ownerUsername, d.ownerPassword, d.endpoint, dbName)
}
```
