The code in both files is confirmed. Let me verify the exact claims against the actual source.

**`pinger/cmd/healthcheck/main.go` lines 26–39:** [1](#0-0) 

`os.Stat("/tmp/alive")` is called with no subsequent `fi.Mode().IsRegular()` check — confirmed.

**`pinger/main.go` line 36:** [2](#0-1) 

`os.WriteFile` error is silently discarded with `_` — confirmed.

Both code flaws are real and the line references are exact. The SECURITY.md does not exclude this class of finding. [3](#0-2) 

---

# Audit Report

## Title
Liveness Probe Bypass / Restart-Loop via Unix Domain Socket at `/tmp/alive`

## Summary
The pinger's liveness mechanism has two compounding flaws: the healthcheck binary accepts any filesystem entry (socket, FIFO, directory) at `/tmp/alive` as a valid heartbeat file, and the heartbeat writer silently discards write errors. An unprivileged process with write access to `/tmp` before pinger startup can pre-create `/tmp/alive` as a Unix domain socket, causing the heartbeat to silently fail and eventually driving the pod into a permanent `CrashLoopBackOff`.

## Finding Description

**File:** `pinger/cmd/healthcheck/main.go`, `main()`, lines 27–38

```go
fi, err := os.Stat("/tmp/alive")   // succeeds for socket, FIFO, dir, symlink, etc.
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
age := time.Since(fi.ModTime())
if age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
os.Exit(0)
``` [4](#0-3) 

`os.Stat(2)` returns successfully for any inode type. The code never calls `fi.Mode().IsRegular()`, so a socket, FIFO, or directory at `/tmp/alive` passes the existence check.

**File:** `pinger/main.go`, heartbeat goroutine, line 36

```go
_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
``` [5](#0-4) 

`os.WriteFile` internally calls `open(path, O_WRONLY|O_CREATE|O_TRUNC)`. On Linux, `open(2)` on a Unix domain socket returns `ENXIO`. The error is discarded, so the heartbeat silently stops updating the mtime of the socket.

## Impact Explanation
The pinger's sole purpose is to submit periodic Hedera transactions and signal liveness. A persistent restart loop prevents it from ever completing a transaction cycle. Kubernetes applies exponential back-off (`CrashLoopBackOff`), making the pinger effectively unavailable for extended periods. The monitoring and health-signalling function of the service is completely neutralised. No funds are at risk, but service availability is permanently degraded until the pod is deleted (not just restarted), which clears the `emptyDir` volume.

## Likelihood Explanation
Precondition: write access to `/tmp` inside the pod before or concurrently with pinger startup. In Kubernetes this is achievable without elevated privileges via a sidecar or init container in the same pod sharing an `emptyDir` at `/tmp` — a common pattern for log shipping, proxies, and service meshes. The technique requires no kernel exploits, no root, and is fully repeatable across container restarts since `emptyDir` volumes persist across container restarts within the same pod lifetime.

## Recommendation

**Fix 1 — Add a regular-file check in the healthcheck binary** (`pinger/cmd/healthcheck/main.go`):

```go
fi, err := os.Stat("/tmp/alive")
if err != nil || !fi.Mode().IsRegular() {
    fmt.Fprintln(os.Stderr, "heartbeat file missing or invalid type")
    os.Exit(1)
}
```

**Fix 2 — Log heartbeat write errors in the pinger** (`pinger/main.go`):

```go
if err := os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644); err != nil {
    log.Printf("heartbeat write failed: %v", err)
}
```

**Fix 3 (defence-in-depth):** On startup, if `/tmp/alive` exists and is not a regular file, remove it before starting the heartbeat goroutine.

## Proof of Concept

```bash
# In a sidecar or init container sharing emptyDir at /tmp:
python3 -c "
import socket, os
s = socket.socket(socket.AF_UNIX)
s.bind('/tmp/alive')
# socket is now created; do not listen or connect — just leave it
"

# Pinger starts; every 15s it attempts:
#   open("/tmp/alive", O_WRONLY|O_CREATE|O_TRUNC) -> ENXIO (silently discarded)
# mtime of /tmp/alive is frozen at socket creation time.

# After ~2 minutes:
#   healthcheck live -> os.Stat succeeds, age > 2min -> exit(1)
#   Kubernetes restarts the container.
# On restart, emptyDir is NOT cleared -> socket persists -> loop repeats.
```

### Citations

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

**File:** pinger/main.go (L35-37)
```go
			case <-t.C:
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
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
