### Title
TLS Server Certificate Verification Disabled (`rejectUnauthorized: false`) Enables MITM on PostgreSQL Connection

### Summary
In `rest/dbpool.js`, when TLS is enabled for the database connection, `poolConfig.ssl` is constructed with `rejectUnauthorized: false`. This instructs Node.js's TLS stack to skip server certificate verification entirely, rendering the loaded CA certificate meaningless. Any network-adjacent attacker can present an arbitrary certificate and successfully complete the TLS handshake, intercepting or corrupting all data between the REST server and PostgreSQL.

### Finding Description
**Exact code location**: `rest/dbpool.js` lines 18–25, executed at module load time and consumed by `initializePool()` at `rest/server.js` line 49.

```js
if (config.db.tls.enabled) {
  poolConfig.ssl = {
    ca: fs.readFileSync(config.db.tls.ca).toString(),   // loaded but never enforced
    cert: fs.readFileSync(config.db.tls.cert).toString(),
    key: fs.readFileSync(config.db.tls.key).toString(),
    rejectUnauthorized: false,                           // ← disables all server-cert checks
  };
}
```

**Root cause**: In Node.js's `tls` module (and by extension `node-postgres`), `rejectUnauthorized: false` instructs the TLS engine to skip the certificate chain validation step entirely. The `ca` field is loaded into memory but is never consulted during the handshake. The failed assumption is that loading a CA cert implies it will be used for verification — it will not when `rejectUnauthorized` is `false`.

**Exploit flow**:
1. Attacker gains a network-adjacent position between the REST server and PostgreSQL (same Kubernetes namespace, shared VLAN, ARP-poisoned segment, or DNS-spoofed resolution of `config.db.host`/`config.db.primaryHost`).
2. Attacker intercepts the TCP SYN to port 5432 and completes the TCP handshake on behalf of the real PostgreSQL server.
3. Attacker presents a self-signed or attacker-controlled TLS certificate during the TLS handshake.
4. Because `rejectUnauthorized: false`, the `pg` pool client accepts the certificate unconditionally and completes the handshake.
5. Attacker now sits as a transparent TLS proxy: all SQL queries (including credentials in the initial auth message) and all result rows flow through the attacker in plaintext.

**Why existing checks fail**: The only guard is the `if (config.db.tls.enabled)` branch — it gates whether TLS is used at all, but does nothing to enforce certificate validity once TLS is active. There is no secondary check, no pinning, and no hostname verification. A grep across the entire repository confirms `rejectUnauthorized` appears exactly once, always set to `false`. [1](#0-0) 

### Impact Explanation
- **Confidentiality**: All SQL query results (account balances, transaction records, token data) are readable by the attacker in cleartext after TLS termination.
- **Integrity**: The attacker can inject fabricated SQL result rows, causing the REST API to serve corrupted blockchain data to end users.
- **Authentication bypass**: The PostgreSQL wire-protocol password (sent after TLS handshake) is exposed to the attacker, enabling direct database access with the `mirror_api` credentials.
- Severity: **High** — complete loss of transport-layer security guarantees for the DB channel despite TLS being explicitly enabled by the operator.

### Likelihood Explanation
- Requires network-adjacent position, not OS-level privilege on either host. In Kubernetes deployments without strict `NetworkPolicy`, any pod in the same namespace can ARP-spoof or intercept cluster-internal traffic.
- DNS-based redirection (e.g., corrupting the in-cluster DNS record for the DB service) requires no special privilege and is a well-documented attack in shared-tenant clusters.
- The `primaryPool` path (`config.db.primaryHost`) shares the same `poolConfig` object via shallow spread (`{...poolConfig}`), so both the replica and primary connections are equally vulnerable. [2](#0-1) 
- During a network partition and subsequent reconnection, the pool will re-establish connections, giving the attacker a repeatable interception window.

### Recommendation
Change `rejectUnauthorized` to `true` (or remove the field entirely, as `true` is the Node.js default):

```js
if (config.db.tls.enabled) {
  poolConfig.ssl = {
    ca: fs.readFileSync(config.db.tls.ca).toString(),
    cert: fs.readFileSync(config.db.tls.cert).toString(),
    key: fs.readFileSync(config.db.tls.key).toString(),
    rejectUnauthorized: true,   // enforce CA chain + hostname verification
  };
}
```

Additionally, ensure the CA cert in `config.db.tls.ca` is the actual issuing CA for the PostgreSQL server certificate, and consider adding `checkServerIdentity` if the server's CN/SAN must be pinned to a specific hostname.

### Proof of Concept
**Preconditions**: `hiero.mirror.rest.db.tls.enabled = true`; attacker has network-adjacent access (e.g., a pod in the same Kubernetes namespace).

```bash
# 1. On attacker pod: start a rogue TLS proxy on port 5432 with a self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout rogue.key -out rogue.crt \
  -days 1 -nodes -subj "/CN=rogue-db"

# Use socat or a custom proxy to terminate TLS with rogue.crt/rogue.key
# and forward plaintext to the real PostgreSQL
socat \
  OPENSSL-LISTEN:5432,cert=rogue.crt,key=rogue.key,verify=0,fork \
  TCP:real-postgres-host:5432

# 2. Redirect DNS / ARP so that the REST server resolves config.db.host
#    to the attacker's IP (standard ARP spoofing or CoreDNS record injection).

# 3. Observe: the REST server connects, presents its client cert, and the
#    pool handshake completes successfully despite the rogue certificate.
#    All SQL traffic (including the md5/scram auth exchange and query results)
#    is now visible in plaintext on the attacker's socat stdout.
```

### Citations

**File:** rest/dbpool.js (L18-25)
```javascript
if (config.db.tls.enabled) {
  poolConfig.ssl = {
    ca: fs.readFileSync(config.db.tls.ca).toString(),
    cert: fs.readFileSync(config.db.tls.cert).toString(),
    key: fs.readFileSync(config.db.tls.key).toString(),
    rejectUnauthorized: false,
  };
}
```

**File:** rest/dbpool.js (L39-43)
```javascript
  if (config.db.primaryHost) {
    const primaryPoolConfig = {...poolConfig};
    primaryPoolConfig.host = config.db.primaryHost;
    global.primaryPool = new Pool(primaryPoolConfig);
    handlePoolError(global.primaryPool);
```
