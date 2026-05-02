### Title
Hardcoded `sslmode=disable` in Rosetta DB DSN Enables Plaintext MITM on Predictably-Recycled Connections

### Summary
`GetDsn()` in `rosetta/app/config/types.go` hardcodes `sslmode=disable` unconditionally, meaning every database connection opened by `ConnectToDb()` is unencrypted with no option to enable TLS via configuration. `SetConnMaxLifetime` in `rosetta/app/db/db.go` causes the pool to recycle connections at a fixed, operator-visible interval, giving a network-positioned attacker a predictable window to inject a spoofed TCP session carrying false Hashgraph block data.

### Finding Description
**Code path:**

- `rosetta/app/config/types.go`, `GetDsn()`, line 51: `sslmode=disable` is a string literal — not a config field, not a default that can be overridden.
- `rosetta/app/db/db.go`, `ConnectToDb()`, line 18: DSN is passed directly to `gorm.Open(postgres.Open(...))`.
- `rosetta/app/db/db.go`, line 32: `sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)` — lifetime is expressed in whole minutes, making the recycle boundary coarse and predictable.

**Root cause:** The DSN format string `"host=%s port=%d user=%s dbname=%s password=%s sslmode=disable"` bakes in `sslmode=disable` with no conditional or configurable path. Even if an operator wanted TLS, the code provides no mechanism to enable it. The failed assumption is that the network between the Rosetta service and PostgreSQL is trusted; in any shared, cloud, or container-overlay network this assumption does not hold.

**Exploit flow:**
1. Attacker gains a network-adjacent position (same pod network, same VLAN, ARP-spoofed LAN, or compromised sidecar) — no application credentials required.
2. Attacker reads `MaxLifetime` from the public Helm chart / config docs (default values are documented) or observes TCP RST/FIN patterns to infer the recycle interval.
3. Just before the lifetime boundary, attacker pre-positions a TCP intercept (ARP poison or iptables REDIRECT on a compromised node) on the DB port.
4. When the pool closes the old connection and dials a new one, the attacker completes the TCP handshake on behalf of the server (no TLS challenge to fail).
5. Attacker responds to PostgreSQL wire-protocol startup with a crafted authentication success, then serves fabricated query results — e.g., false block hashes, tampered transaction records — back to the Rosetta API.
6. Because `sslmode=disable` suppresses all certificate and channel-binding checks, the Go `pq`/`pgx` driver accepts the session unconditionally.

**Why existing checks are insufficient:** There are no checks. `sslmode=disable` removes every layer of transport security: no server certificate validation, no channel encryption, no HMAC on the wire. The health-check in `rosetta/app/middleware/health.go` line 42 also calls `rosettaConfig.Db.GetDsn()`, so it too connects without TLS and cannot detect a MITM.

### Impact Explanation
An attacker who can inject false query responses controls what block data the Rosetta API returns to clients. This means fabricated transaction histories, false balance proofs, and incorrect block hashes — directly undermining the integrity guarantee of the Hashgraph mirror. Severity is **Critical** for integrity and **High** for confidentiality (credentials and all query data travel in plaintext, including the DB password visible in the DSN on the wire).

### Likelihood Explanation
Precondition is network adjacency, not application privilege. In Kubernetes (the documented deployment target per the Helm charts), any compromised pod on the same node or namespace can intercept pod-to-pod traffic before a NetworkPolicy is applied. Cloud environments with shared virtual switches, misconfigured CNI plugins, or lateral-movement from another service all satisfy the precondition. The `MaxLifetime` interval (whole minutes, operator-visible in config) makes the timing window repeatable and scriptable. This is not a theoretical attack; tools like `arpspoof`, `ettercap`, and `pg_mitm` automate exactly this flow.

### Recommendation
1. Remove the hardcoded `sslmode=disable` literal from `GetDsn()` in `rosetta/app/config/types.go` and replace it with a configurable `SslMode` field on the `Db` struct (mirroring the pattern already used in `importer/src/main/java/org/hiero/mirror/importer/db/DBProperties.java` which has `SslMode sslMode = SslMode.DISABLE` as a configurable field).
2. Set the production default to at minimum `sslmode=require`; prefer `sslmode=verify-full` with a CA cert path.
3. Add `SslRootCert`, `SslCert`, `SslKey` fields to the `Db` config struct and include them in the DSN when set.
4. The `MaxLifetime` issue is secondary — fixing the transport encryption eliminates the MITM window regardless of recycle timing.

### Proof of Concept
```
# Precondition: attacker has a pod on the same Kubernetes node as the rosetta service.

# 1. Identify the DB pod IP
kubectl get pod -o wide | grep postgres   # e.g. 10.0.1.5

# 2. ARP-poison the rosetta pod to redirect DB traffic to attacker
arpspoof -i eth0 -t <rosetta-pod-ip> <db-pod-ip>

# 3. Forward all traffic except port 5432 normally; intercept 5432
iptables -t nat -A PREROUTING -p tcp --dport 5432 -j REDIRECT --to-port 15432

# 4. Run a fake PostgreSQL server on :15432 that:
#    a. Completes the PostgreSQL startup/auth handshake (no TLS negotiation
#       is attempted because sslmode=disable skips the SSLRequest message)
#    b. Returns crafted rows for any SELECT on record_file / transaction tables

# 5. Wait for MaxLifetime boundary (observable from config or by watching
#    TCP connection age with `ss -tnp`); the pool dials a fresh connection
#    which lands on the attacker's listener.

# 6. Rosetta API now serves attacker-controlled Hashgraph block data to all
#    downstream clients with no error or warning logged.
``` [1](#0-0) [2](#0-1)

### Citations

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

**File:** rosetta/app/db/db.go (L17-33)
```go
func ConnectToDb(dbConfig config.Db) interfaces.DbClient {
	db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), &gorm.Config{Logger: gormlogrus.New()})
	if err != nil {
		log.Warn(err)
	} else {
		log.Info("Successfully connected to database")
	}

	sqlDb, err := db.DB()
	if err != nil {
		log.Errorf("Failed to get sql DB: %s", err)
		return nil
	}

	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```
