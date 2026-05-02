All code references have been verified against the actual source. The claim is accurate.

- `fetchMirrorNodeNetwork()` lines 113–128: only syntactic checks, no reachability validation. [1](#0-0) 
- `newClient()` lines 18–22: client built once from the unvalidated map. [2](#0-1) 
- `main.go` line 41: one-time init, never refreshed. [3](#0-2) 
- `transfer.go` line 33: every transfer executes against the poisoned client. [4](#0-3) 
- `main.go` lines 28–39: liveness goroutine runs independently, masking the failure. [5](#0-4) 

No SECURITY.md exclusion applies: the finding is not a pure DDoS, not a TLS best-practice note, and not limited to local-network-only attack vectors (DNS poisoning and mirror node compromise are remote vectors). [6](#0-5) 

---

Audit Report

## Title
Mirror Node REST Response Poisoning Causes Permanent DoS of HBAR Transfers via Unvalidated Dead Endpoints

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` accepts any syntactically valid endpoint from the mirror node REST response without validating reachability or address legitimacy. Because `newClient()` in `pinger/sdk_client.go` builds the Hiero SDK client exactly once from this response and never refreshes it, an attacker who can control the mirror node REST response can permanently poison the network map with unreachable addresses, causing every `Execute(client)` call in `pinger/transfer.go` to time out for the lifetime of the process.

## Finding Description
`fetchMirrorNodeNetwork()` applies only two syntactic guards before accepting an endpoint:

```go
// pinger/mirror_node_client.go lines 113–124
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {   // syntactic only
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId
}
```

A string like `"0.0.0.0"` with port `50211` passes both checks. The final guard `len(network) == 0` passes as long as at least one syntactically valid entry exists. There is no reachability probe, no IP-range exclusion, no TLS on the HTTP fetch, and no cross-validation against known-good addresses.

The poisoned map is passed directly to `hiero.ClientForNetwork(netmap)` in `pinger/sdk_client.go` (lines 18–22), and that client is created once in `pinger/main.go` (line 41) and reused for every ticker tick. Every subsequent transfer calls `cryptoTransfer.Execute(client)` (line 33 of `pinger/transfer.go`) against the poisoned client.

## Impact Explanation
All HBAR transfers from the operator account via the pinger service fail permanently until the process is restarted and the mirror node returns valid data. Critically, the liveness goroutine in `pinger/main.go` (lines 28–39) writes `/tmp/alive` on an independent ticker, so the Kubernetes liveness exec probe continues to succeed even while every transfer is timing out. The outage is completely masked from the orchestration layer.

## Likelihood Explanation
The attacker must be able to influence the HTTP response from the mirror node REST endpoint. Realistic vectors:

1. **Plain HTTP (default `http://mirror-rest:5551`)** — no TLS, so any on-path attacker (ARP spoofing, rogue container on the same Docker/K8s overlay network, compromised sidecar) can inject a crafted response.
2. **DNS poisoning** — redirect the mirror node hostname to an attacker-controlled server; no local network access required.
3. **Mirror node compromise** — if the mirror node itself is compromised, the attacker controls the REST response directly.

The attack is repeatable: every time the pinger restarts (crash, rolling update, OOM kill), it re-fetches the mirror node response and can be re-poisoned.

## Recommendation
1. **Validate reachability before use**: perform a TCP dial (with a short timeout) to each candidate endpoint before adding it to the network map; discard endpoints that do not respond.
2. **Reject reserved/private address ranges**: refuse RFC-1918, loopback, link-local, and unspecified (`0.0.0.0`) addresses unless the deployment is explicitly configured to allow them.
3. **Enforce HTTPS for the mirror node REST fetch**: require TLS with certificate verification so on-path injection is not possible.
4. **Periodic client refresh**: rebuild the SDK client on a configurable interval (or on consecutive transfer failures) rather than initialising it once at startup, so a poisoned state is self-healing.
5. **Decouple liveness from transfer health**: only write `/tmp/alive` when a transfer has succeeded within the last N intervals, so Kubernetes can detect a sustained transfer outage.

## Proof of Concept
1. Stand up a mock HTTP server that returns a valid JSON `nodesEnvelope` with one node entry whose `service_endpoints` contains `ip_address_v4: "192.0.2.1"` (TEST-NET, unreachable) and `port: 50211`.
2. Point `MIRROR_REST` at the mock server.
3. Start the pinger with `NETWORK=other`.
4. `newClient()` calls `buildNetworkFromMirrorNodes()`, which calls `fetchMirrorNodeNetwork()`. The single entry passes both syntactic checks; `len(network) == 1`; the function returns successfully.
5. `hiero.ClientForNetwork({"192.0.2.1:50211": <accountID>})` is stored as the sole client.
6. Every ticker tick calls `submitWithRetry()` → `cryptoTransfer.Execute(client)` → gRPC dial to `192.0.2.1:50211` → connection timeout after the SDK's deadline.
7. Meanwhile, `/tmp/alive` is refreshed every 15 seconds; `kubectl exec -- cat /tmp/alive` shows a recent timestamp, and the liveness probe never fires.
8. The pinger logs `transfer failed` on every tick but is never restarted by Kubernetes, so the DoS persists indefinitely.

### Citations

**File:** pinger/mirror_node_client.go (L113-131)
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
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}

	return network, false, nil
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

**File:** pinger/main.go (L28-39)
```go
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
			}
		}
	}()
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/transfer.go (L33-33)
```go
		resp, err := cryptoTransfer.Execute(client)
```

**File:** SECURITY.md (L1-65)
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

The following activities are prohibited by default on bug bounty programs on Immunefi. Projects may add further restrictions to their own program.

- Any testing on mainnet or public testnet deployed code; all testing should be done on local forks of either public testnet or mainnet.
- Any testing with pricing oracles or third-party smart contracts.
- Attempting phishing or other social engineering attacks against employees and/or customers.
- Any testing with third-party systems and applications (e.g. browser extensions), as well as websites (e.g. SSO providers, advertising networks).
- Any denial-of-service attacks that are executed against project assets.
- Automated testing of services that generates significant amounts of traffic.
- Public disclosure of an unpatched vulnerability in an embargoed bounty.
```
