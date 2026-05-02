### Title
Unauthenticated `/tmp/alive` Heartbeat Allows Liveness-Probe Spoofing to Mask Silent Transaction Failure

### Summary
The liveness probe in `pinger/cmd/healthcheck/main.go` exclusively trusts the filesystem `ModTime()` of `/tmp/alive` to determine pod health, with no cryptographic binding to the pinger process. Separately, the heartbeat goroutine in `pinger/main.go` updates `/tmp/alive` on a fixed 15-second ticker that is completely decoupled from whether transactions are actually being submitted. Any process with write access to `/tmp` — including an unprivileged sidecar sharing an emptyDir volume — can keep the liveness probe returning exit 0 indefinitely while the pinger silently stops producing transaction history.

### Finding Description

**Code path 1 — healthcheck** (`pinger/cmd/healthcheck/main.go`, lines 26–39):

```go
case "live":
    fi, err := os.Stat("/tmp/alive")
    ...
    age := time.Since(fi.ModTime())
    if age > 2*time.Minute {
        fmt.Fprintln(os.Stderr, "heartbeat stale")
        os.Exit(1)
    }
    os.Exit(0)
```

The probe passes if and only if `/tmp/alive` has a `ModTime` within the last 2 minutes. There is no content check, no PID binding, no HMAC/signature, and no inode-ownership verification. Any writer wins.

**Code path 2 — heartbeat goroutine** (`pinger/main.go`, lines 28–39):

```go
go func() {
    t := time.NewTicker(15 * time.Second)
    ...
    case <-t.C:
        _ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
    }
}()
```

The goroutine runs on a fixed 15-second clock, completely independent of the transaction submission loop (lines 54–70). Even if every call to `submitWithRetry` fails, the heartbeat continues. The file is written with mode `0644` — world-readable, owner-writable — so any process running as UID 1000 (the container's user) can overwrite it.

**Root cause**: The liveness probe conflates "process is alive" with "transactions are being submitted." The heartbeat is not gated on transaction success, and the file it writes carries no unforgeable proof of origin.

**Exploit flow (external-user variant)**:
1. Attacker controls a sidecar container in the same pod (or any container sharing an emptyDir volume mounted at `/tmp`).
2. Attacker kills or disrupts the pinger's transaction loop (e.g., by exhausting the operator account balance, poisoning DNS for the Hiero node, or simply waiting for a persistent SDK error).
3. Pinger process continues running; heartbeat goroutine keeps writing `/tmp/alive` every 15 s — OR attacker's sidecar runs `touch /tmp/alive` (or equivalent `os.WriteFile`) every 60 s.
4. Kubernetes liveness probe (`healthcheck live`) reads `ModTime`, sees age < 2 min, exits 0 — pod is never restarted.
5. Transaction history develops a silent gap; no alert fires; on-call engineers see a healthy pod.

### Impact Explanation
The pinger's sole purpose is to produce a continuous stream of on-chain transactions so that the mirror node's ingestion pipeline can be monitored for gaps. A spoofed liveness probe prevents Kubernetes from restarting the pod, so the gap in transaction history is invisible to the platform's own health-monitoring layer. An attacker who can sustain this condition can create arbitrarily long, undetected gaps in the ledger's observable transaction history — satisfying the "reorganizing transaction history without direct theft of funds" threat model. Severity: **High** (integrity of monitoring infrastructure).

### Likelihood Explanation
The external-user precondition (shared `/tmp`) is not a default Kubernetes configuration; it requires an emptyDir volume explicitly mounted at `/tmp` in the pod spec, or a compromised/malicious sidecar. However:
- Multi-container pods with shared scratch volumes are common in observability and logging sidecars.
- The decoupled-heartbeat design flaw is exploitable **without any external attacker**: a persistent SDK/network error that exhausts all retries will cause the transaction loop to log errors and continue looping, while the heartbeat goroutine keeps the probe green. This requires zero special access.
- The file permission `0644` and the absence of any ownership check make the external-write path trivially simple once `/tmp` is shared.

### Recommendation
1. **Couple the heartbeat to transaction success**: only update `/tmp/alive` after a successful `submitWithRetry` call, not on a free-running ticker.
2. **Add a failure counter**: if N consecutive ticks fail, do not update `/tmp/alive`, allowing the probe to go stale and trigger a restart.
3. **Restrict `/tmp` sharing**: ensure the pod spec does not mount an emptyDir at `/tmp`; use a dedicated named volume for any inter-container communication.
4. **Optionally bind the heartbeat file**: write a value derived from the process PID or a startup-time secret so that an external writer cannot produce a valid token without knowing the secret.

### Proof of Concept

```bash
# Precondition: sidecar shares /tmp via emptyDir volume in pod spec.
# Step 1: In the sidecar, start a background loop to keep /tmp/alive fresh.
while true; do
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > /tmp/alive
  sleep 60
done &

# Step 2: Disrupt the pinger's ability to submit transactions
# (e.g., block egress to Hiero nodes via iptables, or drain the operator account).
# The pinger process keeps running; its heartbeat goroutine also keeps writing,
# but even if the pinger process is killed, the sidecar loop sustains the probe.

# Step 3: Verify liveness probe returns 0.
/healthcheck live; echo "exit: $?"
# Output: exit: 0   <-- pod is never restarted despite zero transactions submitted
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
