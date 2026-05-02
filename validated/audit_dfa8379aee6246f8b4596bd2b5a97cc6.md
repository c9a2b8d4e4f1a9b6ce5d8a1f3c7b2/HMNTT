Let me verify the exact line numbers and behavior claimed in the report against the actual code.

All code references are verified against the actual source. Every line number, function, and behavioral claim is accurate.

**Verification summary:**
- `pinger/cmd/healthcheck/main.go` line 20: `os.Stat("/tmp/ready")` with no `fi.Mode()` check — confirmed. [1](#0-0) 
- `pinger/main.go` line 47: `os.WriteFile("/tmp/ready", ...)` — confirmed. [2](#0-1) 
- Heartbeat goroutine (lines 28–39) is launched **before** the blocking `WriteFile` call — confirmed. [3](#0-2) 
- Liveness probe checks `fi.ModTime()` staleness on `/tmp/alive`, not `/tmp/ready` — confirmed. [4](#0-3) 
- SECURITY.md contains no exclusion covering this attack class. [5](#0-4) 

---

# Audit Report

## Title
FIFO Pre-Creation at `/tmp/ready` Causes Pinger Deadlock While Readiness Probe Reports Healthy

## Summary
An attacker with code execution inside the pinger pod can pre-create `/tmp/ready` as a named pipe (FIFO). This causes `os.WriteFile("/tmp/ready", ...)` in `pinger/main.go` to block indefinitely (POSIX: `open(2)` with `O_WRONLY` on a FIFO without `O_NONBLOCK` blocks until a reader appears). Simultaneously, the Kubernetes readiness probe calls `os.Stat("/tmp/ready")`, which succeeds immediately on a FIFO (POSIX: `stat(2)` never blocks), reporting the pod as ready. The liveness probe also continues to pass because the heartbeat goroutine was launched before the blocking call. The pod is permanently deadlocked with no automatic recovery.

## Finding Description

**Code path 1 — readiness probe** (`pinger/cmd/healthcheck/main.go`, `main()`, line 20):
```go
if _, err := os.Stat("/tmp/ready"); err != nil {
    fmt.Fprintln(os.Stderr, "not ready")
    os.Exit(1)
}
os.Exit(0)
```
`os.Stat` invokes `stat(2)`, which returns immediately for any filesystem object including FIFOs. The returned `err` is `nil`, so the probe exits 0 (healthy). There is no check on `fi.Mode()&os.ModeNamedPipe` or `fi.Mode()&os.ModeType`. [6](#0-5) 

**Code path 2 — pinger startup** (`pinger/main.go`, `main()`, line 47):
```go
if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
    log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
}
```
`os.WriteFile` internally calls `os.OpenFile(name, O_WRONLY|O_CREATE|O_TRUNC, perm)`. On Linux, `open(2)` on a FIFO with `O_WRONLY` and without `O_NONBLOCK` blocks indefinitely until a reader opens the other end. No reader ever does. `log.Fatalf` is never reached, so no error is logged and the main goroutine hangs permanently. [7](#0-6) 

**Why the liveness probe also passes:** The heartbeat goroutine is launched at lines 28–39, before the blocking `os.WriteFile` call at line 47. It continues writing `/tmp/alive` every 15 seconds. The liveness probe checks only that `/tmp/alive` exists and has a `ModTime` within the last 2 minutes — both conditions remain satisfied indefinitely. [3](#0-2) [4](#0-3) 

**Root cause:** The code assumes that the existence of `/tmp/ready` implies the pinger successfully completed initialization. `os.Stat` does not distinguish regular files from special files. A FIFO satisfies the existence check without requiring the pinger to have written it.

## Impact Explanation
The pinger pod is marked both live and ready by Kubernetes and receives no restart or remediation. The main goroutine is permanently blocked at `os.WriteFile`; no Hiero transfers are submitted for the lifetime of the pod. Because the liveness probe also passes, Kubernetes never kills and restarts the pod. The disruption is silent (no error is logged, no alert fires) and persistent until the pod is manually restarted or the attacker's access is revoked. Monitoring and pinging functionality is completely disabled for the duration.

## Likelihood Explanation
**Precondition:** The attacker requires code execution inside the pod (e.g., via RCE in the pinger binary, a compromised dependency, or `kubectl exec` access). The `/tmp` volume is a pod-specific `emptyDir`, so host-level `/tmp` access is insufficient. Once inside the pod, the attack is a single command (`mkfifo /tmp/ready`) requiring no elevated privileges. The `emptyDir` is cleared on pod restart, but an attacker with persistent exec access can re-create the FIFO after each restart. The attack is repeatable and leaves no obvious log trace.

## Recommendation
Replace the bare existence check with a check that verifies the file is a regular file and was written by the pinger itself:

**In `pinger/cmd/healthcheck/main.go`:**
```go
fi, err := os.Stat("/tmp/ready")
if err != nil || !fi.Mode().IsRegular() {
    fmt.Fprintln(os.Stderr, "not ready")
    os.Exit(1)
}
os.Exit(0)
```

**In `pinger/main.go`:**
Use a write-to-temp-then-rename pattern to make the creation atomic and avoid blocking on a pre-existing FIFO:
```go
tmp, err := os.CreateTemp("/tmp", ".ready-*")
if err != nil {
    log.Fatalf("failed to create readiness temp file: %v", err)
}
if _, err := tmp.WriteString("ok\n"); err != nil {
    log.Fatalf("failed to write readiness file: %v", err)
}
tmp.Close()
if err := os.Rename(tmp.Name(), "/tmp/ready"); err != nil {
    log.Fatalf("failed to rename readiness file: %v", err)
}
```
`os.CreateTemp` creates a new regular file with `O_RDWR|O_CREATE|O_EXCL`, which never blocks on a pre-existing FIFO at the temp path, and `os.Rename` atomically replaces any existing `/tmp/ready` entry.

## Proof of Concept
```bash
# Inside the pinger pod, before the pinger process starts:
mkfifo /tmp/ready

# The pinger process starts:
# - Heartbeat goroutine launches and begins writing /tmp/alive every 15s
# - os.WriteFile("/tmp/ready", ...) opens the FIFO O_WRONLY, blocks forever
# - No transfers are ever submitted

# Readiness probe (run by kubelet):
# healthcheck ready
# => os.Stat("/tmp/ready") returns nil (FIFO exists) => exits 0 => pod marked Ready

# Liveness probe (run by kubelet after 15s):
# healthcheck live
# => os.Stat("/tmp/alive") returns nil, ModTime < 2min => exits 0 => pod marked Live

# Result: pod is Live+Ready, zero transfers submitted, no restart triggered.
```

### Citations

**File:** pinger/cmd/healthcheck/main.go (L18-24)
```go
	case "ready":
		// Ready if init marker exists
		if _, err := os.Stat("/tmp/ready"); err != nil {
			fmt.Fprintln(os.Stderr, "not ready")
			os.Exit(1)
		}
		os.Exit(0)
```

**File:** pinger/cmd/healthcheck/main.go (L26-39)
```go
	case "live":
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

**File:** pinger/main.go (L46-49)
```go
	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
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
