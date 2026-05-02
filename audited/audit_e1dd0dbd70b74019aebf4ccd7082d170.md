### Title
Hardcoded `sslmode=disable` in `GetDsn()` Enables Plaintext Credential Sniffing on PostgreSQL Connections

### Summary
The `GetDsn()` function in `rosetta/app/config/types.go` unconditionally hardcodes `sslmode=disable` in the PostgreSQL DSN string, with no configuration field in the `Db` struct to override it. This forces all Rosetta-to-PostgreSQL connections to be unencrypted, allowing any attacker with passive network access to the path between the Rosetta service and the database to capture the PostgreSQL authentication handshake and extract the database username and password in cleartext.

### Finding Description
**Exact code location:** `rosetta/app/config/types.go`, `GetDsn()`, line 51.

```go
func (db Db) GetDsn() string {
    return fmt.Sprintf(
        "host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
        db.Host, db.Port, db.Username, db.Name, db.Password,
    )
}
```

**Root cause:** The `sslmode=disable` token is a string literal baked into the format string. The `Db` struct (lines 39–47) contains no `SslMode` or TLS-related field whatsoever — confirmed by a full grep of the `rosetta/` tree for any SSL/TLS configuration key returning zero matches. There is no environment variable, YAML key, or code path that can override this value at runtime.

**Call site:** `rosetta/app/db/db.go` line 18 passes the DSN directly to the GORM/pgx driver:
```go
db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), &gorm.Config{...})
```

**Why checks fail:**
- The `Db` struct has no `SslMode` field; the importer's equivalent `DBProperties.java` (line 50) does have `private SslMode sslMode = SslMode.DISABLE` and is configurable — the rosetta component deliberately omits this.
- The standalone `hedera-mirror-rosetta` Helm chart has no `NetworkPolicy` template (confirmed: glob search for `charts/hedera-mirror-rosetta/templates/networkpolicy*` returns nothing), so there is no Kubernetes-level control restricting which pods can reach port 5432.
- The combined chart's network policy (`charts/hedera-mirror/templates/networkpolicy.yaml`) is opt-in (`if .Values.networkPolicy.enabled`) and scoped only to pgpool, not to the rosetta chart.
- `sslmode=disable` instructs the PostgreSQL client to actively refuse SSL negotiation even if the server offers it, bypassing any server-side SSL enforcement.

**Exploit flow:**
1. Attacker gains passive network access to the segment carrying Rosetta→PostgreSQL traffic (same Kubernetes node via a compromised pod, same cloud VPC subnet, ARP poisoning on a shared LAN, or a rogue container in the same namespace with no network policy blocking it).
2. Attacker runs `tcpdump -i eth0 port 5432 -w capture.pcap` or equivalent.
3. On the next Rosetta startup or reconnect, the PostgreSQL authentication handshake is transmitted in plaintext. The `StartupMessage` contains the username; the `PasswordMessage` (md5 hash or SCRAM exchange) follows immediately.
4. With md5 authentication, the hash is trivially crackable offline. With SCRAM-SHA-256, the full exchange is captured and subject to offline dictionary attack. With `password` auth (cleartext), credentials are directly visible.
5. Attacker replays or cracks credentials to gain direct database access.

### Impact Explanation
An attacker who recovers the `mirror_rosetta` database credentials gains direct read access to the mirror node PostgreSQL database, which contains the full Hedera ledger history including account balances, transaction records, and token data. Because `sslmode=disable` cannot be overridden without a code change, no operator-level mitigation (certificate deployment, server-side SSL enforcement) can protect this connection path. Severity: **High** — confidentiality of database credentials and all data accessible to the `mirror_rosetta` role is compromised.

### Likelihood Explanation
In Kubernetes deployments without network policies (the default for the standalone rosetta chart), any pod in the same namespace can reach port 5432 and sniff traffic. In cloud deployments where PostgreSQL is a managed external service (e.g., Cloud SQL, RDS) reachable over a VPC subnet, an attacker with access to any VM or container in that subnet can passively capture traffic. No privileges on the Rosetta service or database host are required — only network adjacency. The attack is passive, repeatable on every connection/reconnect, and leaves no application-level log trace.

### Recommendation
1. Add a `SslMode string` field to the `Db` struct in `rosetta/app/config/types.go`, defaulting to `"require"` or `"verify-full"`.
2. Replace the hardcoded literal in `GetDsn()`:
   ```go
   "host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
   db.Host, db.Port, db.Username, db.Name, db.Password, db.SslMode,
   ```
3. Update `rosetta/app/config/application.yml` default to `sslmode: require`.
4. Add a `NetworkPolicy` to the `hedera-mirror-rosetta` Helm chart restricting port 5432 access to only the rosetta pod's service account/label.
5. Mirror the pattern already used in `importer/src/main/java/org/hiero/mirror/importer/db/DBProperties.java` where `SslMode` is a configurable, validated field.

### Proof of Concept
**Preconditions:** Attacker has a container/pod in the same Kubernetes namespace as the rosetta deployment, or is on the same network segment as the PostgreSQL host. No privileges on either the Rosetta pod or the database are required.

```bash
# Step 1: From attacker pod, identify the PostgreSQL service IP
kubectl get svc -n <namespace> | grep postgres   # or use DNS

# Step 2: Start passive capture on the network interface
tcpdump -i eth0 host <postgres-ip> and port 5432 -w /tmp/pg.pcap &

# Step 3: Wait for Rosetta to connect (startup or reconnect after pod restart)
# The StartupMessage and PasswordMessage are sent in plaintext

# Step 4: Inspect the capture
strings /tmp/pg.pcap | grep -A2 "user\|password\|mirror_rosetta"
# OR use Wireshark: filter "pgsql" to decode the full authentication handshake

# Step 5: With md5 auth, crack the hash:
# md5 hash = md5(password + username), trivially reversible with hashcat:
hashcat -m 11100 captured_hash /usr/share/wordlists/rockyou.txt
```

The captured `StartupMessage` will contain `user=mirror_rosetta` and `database=mirror_node` in plaintext. The subsequent `PasswordMessage` contains the credential material. This is directly caused by `sslmode=disable` being hardcoded at: [1](#0-0) 

with no override path through the `Db` struct: [2](#0-1) 

consumed unconditionally at: [3](#0-2)

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
