### Title
Directory Substitution Attack Blinds Liveness Probe via `/tmp/alive`

### Summary
An unprivileged user can create `/tmp/alive` as a directory before (or instead of) the legitimate heartbeat file. `os.Stat` succeeds on directories, so the healthcheck never errors out, and the attacker can keep the directory's `ModTime` fresh by periodically touching it. This permanently blinds the liveness probe, preventing the orchestrator from restarting a dead pinger pod.

### Finding Description
**Heartbeat writer** — `pinger/main.go` line 36:
```go
_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
```
`os.WriteFile` internally opens the path with `O_WRONLY|O_CREATE|O_TRUNC`. When `/tmp/alive` is a directory, this syscall returns `EISDIR`. The error is **silently discarded** (`_ =`), so the goroutine continues looping without ever updating the heartbeat.

**Liveness checker** — `pinger/cmd/healthcheck/main.go` lines 27–38:
```go
fi, err := os.Stat("/tmp/alive")
if err != nil { ... os.Exit(1) }
age := time.Since(fi.ModTime())
if age > 2*time.Minute { ... os.Exit(1) }
os.Exit(0)
```
`os.Stat` succeeds on a directory. There is **no `fi.Mode().IsRegular()` check**. The code only verifies that the path exists and that its `ModTime` is recent — both conditions are trivially satisfied by a directory the attacker controls. [1](#0-0) [2](#0-1) 

### Impact Explanation
The liveness exec probe is the sole mechanism by which Kubernetes (or any container orchestrator) detects that the pinger process has hung or crashed and triggers a pod restart. With this attack, the probe always exits 0 regardless of the actual health of the pinger. A dead or hung pinger pod will never be restarted, meaning the network-health monitoring function it provides is silently lost. Severity is **Medium** (griefing / availability impact, no direct economic loss).

### Likelihood Explanation
`/tmp` is world-writable on every Linux system. No privileges are required. The attack is a single `mkdir /tmp/alive` command executable by any process or user sharing the pod's filesystem (e.g., a sidecar container, an init container, or any co-tenant in a shared-`/tmp` environment). Keeping the directory mtime fresh requires only a periodic `touch /tmp/alive` (also unprivileged). The attack is fully repeatable and survives pinger restarts as long as the directory is not removed.

### Recommendation
1. **Check file type** in the healthcheck — add `fi.Mode().IsRegular()` after the successful `os.Stat`:
   ```go
   fi, err := os.Stat("/tmp/alive")
   if err != nil || !fi.Mode().IsRegular() {
       fmt.Fprintln(os.Stderr, "heartbeat file missing or invalid")
       os.Exit(1)
   }
   ```
2. **Handle the write error** in `pinger/main.go` — log or act on `os.WriteFile` failures instead of discarding them with `_ =`.
3. Optionally, use a path outside `/tmp` that is only writable by the pinger process's UID, or use a named pipe / socket that cannot be replaced by a directory. [3](#0-2) [1](#0-0) 

### Proof of Concept
```bash
# 1. Before (or while) the pinger container starts, create the directory:
mkdir /tmp/alive

# 2. The pinger heartbeat goroutine fires every 15 s and silently fails:
#    os.WriteFile("/tmp/alive", ...) -> EISDIR, error discarded

# 3. Keep the directory mtime fresh (run in background):
while true; do touch /tmp/alive; sleep 60; done

# 4. Invoke the liveness probe as the orchestrator would:
healthcheck live
# exits 0 (reports alive) even though no real heartbeat was ever written

# 5. Kill the pinger process entirely:
kill <pinger-pid>

# 6. Probe still exits 0 — pod is never restarted by Kubernetes.
healthcheck live; echo $?   # prints 0
```

### Citations

**File:** pinger/main.go (L36-36)
```go
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
```

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
