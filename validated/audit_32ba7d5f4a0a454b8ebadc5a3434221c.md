The actual code in the repository confirms the claim. Let me verify the exact lines: [1](#0-0) 

The code at lines 27–39 matches the report exactly. The `live` case stats `/tmp/alive`, computes `age := time.Since(fi.ModTime())`, and only guards with `age > 2*time.Minute` — no lower-bound check exists. The SECURITY.md does not exclude this class of attack (local container shell access is not listed as out of scope). [2](#0-1) 

---

## Audit Report

## Title
Future mtime on `/tmp/alive` Permanently Spoofs Liveness Healthcheck

## Summary
The liveness healthcheck in `pinger/cmd/healthcheck/main.go` uses `time.Since(fi.ModTime())` to compute heartbeat age. When `/tmp/alive` carries a future mtime, this returns a negative `time.Duration`. The sole staleness guard (`age > 2*time.Minute`) is never true for a negative value, so the healthcheck unconditionally exits 0 (healthy) regardless of actual pinger state.

## Finding Description
**File:** `pinger/cmd/healthcheck/main.go`
**Function:** `main()` — `case "live":` branch
**Lines:** 27–39

```go
fi, err := os.Stat("/tmp/alive")   // line 27
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}

age := time.Since(fi.ModTime())    // line 34 — negative when mtime is future
if age > 2*time.Minute {           // line 35 — always false for negative age
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
os.Exit(0)                         // line 39 — always reached
```

`time.Since(t)` is `time.Now().Sub(t)`, which is a signed `int64` nanosecond count. A future `t` produces a large negative integer. Comparing a large negative integer against the positive constant `2*time.Minute` is always `false`. The code never validates that `age >= 0`.

## Impact Explanation
A dead pinger is never restarted by the orchestrator (e.g., Kubernetes liveness probe) because every probe invocation exits 0. Any downstream service relying on the pinger — network reachability monitoring, alerting pipelines — silently fails for an indefinite period. The attacker achieves a persistent denial-of-monitoring condition with a single, non-privileged command.

## Likelihood Explanation
Preconditions are minimal: local shell access to the container and write permission to `/tmp` (world-writable by default on Linux). No elevated privileges, no special tools, and no race conditions are required. In Kubernetes pods where multiple containers share a filesystem namespace, any compromised sidecar or init container can perform this attack. The effect persists until an operator manually inspects and corrects the file's mtime.

## Recommendation
Add a non-negative lower-bound check immediately after computing `age`:

```go
age := time.Since(fi.ModTime())
if age < 0 || age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale or invalid timestamp")
    os.Exit(1)
}
```

This ensures a future-dated mtime is treated as a stale/invalid heartbeat rather than a fresh one. Optionally, restrict `/tmp/alive` to be writable only by the pinger process (e.g., via a dedicated tmpfs mount with appropriate permissions) to reduce the attack surface further.

## Proof of Concept
```bash
# 1. Set a far-future mtime on the heartbeat file (no privileges required)
touch -d "2099-01-01" /tmp/alive

# 2. Kill the real pinger
kill $(pgrep pinger)

# 3. Every subsequent healthcheck invocation exits 0 (healthy)
/app/healthcheck live; echo "exit code: $?"
# Output: exit code: 0
```

### Citations

**File:** pinger/cmd/healthcheck/main.go (L27-39)
```go
		fi, err := os.Stat("/tmp/alive")
		if err != nil {
			// Missing/invalid heartbeat file => not alive
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		age := time.Since(fi.ModTime())
		if age > 2*time.Minute {
			fmt.Fprintln(os.Stderr, "heartbeat stale")
			os.Exit(1)
		}
		os.Exit(0)
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
