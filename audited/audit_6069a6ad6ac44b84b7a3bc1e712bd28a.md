### Title
Hardcoded `sslmode=disable` in PostgreSQL DSN Enables Plaintext MITM and Data Injection

### Summary
The `GetDsn()` function in `rosetta/app/config/types.go` unconditionally hardcodes `sslmode=disable` into every PostgreSQL connection string, with no configuration override possible. This forces all database traffic over unencrypted TCP, allowing any attacker with network-path access to intercept credentials, read query results, and inject forged PostgreSQL protocol responses — including false records — into the mirror node export stream.

### Finding Description
**Exact code path:**

`rosetta/app/config/types.go`, `GetDsn()`, line 51:
```go
return fmt.Sprintf(
    "host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
    db.Host, db.Port, db.Username, db.Name, db.Password,
)
``` [1](#0-0) 

This DSN is consumed directly in `ConnectToDb()`:
```go
db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), ...)
``` [2](#0-1) 

The `Db` struct has no `SSLMode`, `SSLCert`, or `SSLRootCert` fields, so there is no operator-level path to re-enable TLS: [3](#0-2) 

The test suite confirms this is the intended, tested behavior — `sslmode=disable` is asserted as the expected output: [4](#0-3) 

**Root cause:** SSL/TLS is unconditionally disabled at the code level. The failed assumption is that the network between the Rosetta service and PostgreSQL is always trusted and isolated. In practice, cloud VPCs, shared Kubernetes clusters, and container networks are not equivalent to a physically isolated wire.

**Exploit flow:**
1. Attacker gains a foothold on any host sharing the same network segment as the Rosetta pod/VM and the PostgreSQL instance (e.g., a compromised sidecar, another tenant in a shared subnet, or a cloud metadata-service SSRF pivot).
2. Attacker performs ARP poisoning or BGP/route injection to position themselves on the TCP path between Rosetta and PostgreSQL.
3. Because `sslmode=disable` prevents the client from ever sending a TLS handshake, all PostgreSQL wire-protocol traffic is plaintext. The attacker reads the startup message, capturing the username and password in cleartext.
4. With credentials in hand — or by injecting forged `DataRow` / `CommandComplete` PostgreSQL protocol messages directly into the TCP stream — the attacker causes `ConnectToDb()` to receive fabricated query results.
5. These fabricated results propagate through the Rosetta persistence layer and are exported as false records in the mirror node stream.

**Why existing checks are insufficient:** There are none. `sslmode=disable` is not a default that can be overridden; it is a hardcoded string literal. The `Db` config struct provides no field to supply `sslmode`, `sslcert`, `sslkey`, or `sslrootcert`. Even a security-conscious operator deploying this code cannot enable TLS without modifying the source.

### Impact Explanation
An attacker who can inject forged PostgreSQL `DataRow` responses can cause the Rosetta mirror node to export arbitrary false transaction records, account balances, or block data. This directly undermines the integrity guarantee of the mirror node — the core security property of the system. Credential theft from the plaintext startup message also enables direct database access, allowing persistent data manipulation. Severity is **High** (integrity + confidentiality breach of the mirror node's authoritative data source).

### Likelihood Explanation
The precondition is network-path access, not application-level access — no account, API key, or authentication token is required. In cloud-native deployments (Kubernetes, AWS ECS, GCP Cloud Run), the application and database frequently share a VPC subnet. ARP poisoning within a subnet is a well-documented, tooled attack (e.g., `arpspoof`, `ettercap`, Scapy). A compromised co-tenant, a misconfigured network policy, or an SSRF vulnerability in any adjacent service is sufficient. The attack is repeatable and leaves no application-layer log trace because the Rosetta service itself sees only normal query responses.

### Recommendation
1. **Remove the hardcoded `sslmode=disable`** from `GetDsn()` in `rosetta/app/config/types.go`.
2. **Add SSL fields to the `Db` struct** (`SSLMode`, `SSLCert`, `SSLKey`, `SSLRootCert`) and include them in the DSN format string.
3. **Default `SSLMode` to `verify-full`** (or at minimum `require`) in the default configuration, so TLS is enforced unless explicitly relaxed.
4. **Rotate the database password** after any deployment where this code was used over a non-loopback network, as credentials were transmitted in plaintext.

### Proof of Concept
```bash
# 1. On attacker host in same subnet as Rosetta and PostgreSQL:
sudo arpspoof -i eth0 -t <rosetta_ip> <postgres_ip> &
sudo arpspoof -i eth0 -t <postgres_ip> <rosetta_ip> &
sudo sysctl net.ipv4.ip_forward=1

# 2. Capture the PostgreSQL startup message (contains cleartext password):
sudo tcpdump -i eth0 -A 'tcp port 5432' | grep -A5 'user='

# 3. To inject a forged DataRow, use a transparent proxy (e.g., mitmproxy with
#    a custom PostgreSQL protocol script) that intercepts the TCP stream on
#    port 5432 and replaces legitimate DataRow packets with attacker-controlled
#    row data before forwarding to Rosetta.
#    Because sslmode=disable guarantees no TLS wrapper, the wire format is
#    always the raw PostgreSQL frontend/backend protocol — no decryption needed.
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

**File:** rosetta/app/db/db.go (L18-18)
```go
	db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), &gorm.Config{Logger: gormlogrus.New()})
```

**File:** rosetta/app/config/types_test.go (L24-26)
```go
	expected := "host=127.0.0.1 port=5432 user=mirror_user dbname=mirror_node password=mirror_user_pass sslmode=disable"

	assert.Equal(t, expected, db.GetDsn())
```
