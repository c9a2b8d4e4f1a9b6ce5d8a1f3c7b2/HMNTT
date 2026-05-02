### Title
Symlink Attack on `/tmp/alive` Causes Permanent Liveness Probe Failure via Silent Write Error

### Summary
`os.Stat` in Go follows symlinks, so if `/tmp/alive` is replaced with a symlink pointing to a file with a stale mtime that the pinger process cannot write to, the heartbeat update silently fails (error is discarded) while the healthcheck reads the old mtime of the symlink target. This causes the Kubernetes liveness probe to permanently report "heartbeat stale", triggering an infinite container restart loop.

### Finding Description

**Healthcheck** (`pinger/cmd/healthcheck/main.go`, lines 27–38):
```go
fi, err := os.Stat("/tmp/alive")   // follows symlinks — returns FileInfo of TARGET
...
age := time.Since(fi.ModTime())
if age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
```
`os.Stat` unconditionally follows symlinks. The mtime it returns belongs to the symlink **target**, not to `/tmp/alive` itself.

**Pinger heartbeat writer** (`pinger/main.go`, line 36):
```go
_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
```
The write error is **silently discarded** with `_`. If `/tmp/alive` is a symlink to a file the pinger cannot write to (e.g., a read-only kernel pseudo-file like `/proc/1/exe`, or a Kubernetes-injected read-only mount such as `/etc/hostname`), the write fails without any log, alert, or fallback.

**Exploit flow:**
1. Attacker gains write access to `/tmp` in the container (e.g., via a shared `emptyDir` volume in the same pod, or via code execution in the container).
2. Attacker removes `/tmp/alive` and creates: `ln -s /proc/1/exe /tmp/alive` (or any read-only file with mtime > 2 minutes old).
3. Pinger's next tick calls `os.WriteFile("/tmp/alive", ...)` → follows symlink → write to `/proc/1/exe` fails → error silently dropped → `/tmp/alive` symlink remains intact.
4. Every subsequent pinger tick repeats step 3 — the heartbeat is **permanently broken**.
5. Healthcheck: `os.Stat("/tmp/alive")` → follows symlink → returns mtime of `/proc/1/exe` (set at boot, always stale) → `age > 2*time.Minute` → `os.Exit(1)`.
6. Kubernetes sees liveness probe failure → kills and restarts container → attacker re-creates symlink after each restart → **infinite restart loop**.

**Why existing checks fail:** There is no `os.Lstat` call to detect symlinks, no `O_NOFOLLOW` flag, no check that `/tmp/alive` is a regular file, and no error handling on the write path.

### Impact Explanation
The liveness probe is the sole mechanism Kubernetes uses to determine container health. A permanent probe failure causes Kubernetes to restart the container in a `CrashLoopBackOff`-equivalent loop, making the pinger service completely unavailable. Since the pinger submits Hedera network transactions on a ticker, this constitutes a denial-of-service against the monitoring/pinger function. The attack is self-sustaining across restarts if the attacker can re-create the symlink (e.g., via a shared volume).

### Likelihood Explanation
The precondition is write access to `/tmp` inside the container. This is achievable via: (a) a misconfigured Kubernetes pod sharing an `emptyDir` volume at `/tmp` between a compromised sidecar and the pinger container, or (b) any code-execution vulnerability in the pinger itself. The container runs as UID 1000 (non-root), so no privilege escalation is needed once write access to `/tmp` is obtained. The attack is trivially repeatable across restarts.

### Recommendation
1. **Use `os.Lstat` instead of `os.Stat`** in the healthcheck to get the symlink's own metadata (or explicitly reject symlinks):
   ```go
   fi, err := os.Lstat("/tmp/alive")
   if err != nil || fi.Mode()&os.ModeSymlink != 0 {
       fmt.Fprintln(os.Stderr, "invalid heartbeat file")
       os.Exit(1)
   }
   ```
2. **Handle write errors** in the pinger heartbeat goroutine — log or act on failure instead of discarding with `_`.
3. **Use `O_NOFOLLOW`** when opening `/tmp/alive` for writing to prevent symlink following at the OS level.
4. Consider writing the heartbeat to a path outside world-writable `/tmp`, or use file locking/atomic rename to prevent replacement.

### Proof of Concept
```bash
# Inside the container (or from a co-located container sharing /tmp):

# Step 1: Remove the legitimate heartbeat file
rm /tmp/alive

# Step 2: Create symlink to a read-only file with stale mtime
ln -s /proc/1/exe /tmp/alive

# Step 3: Observe pinger silently fails to update heartbeat (no log output)
# Wait for next pinger tick (up to 15s), then run healthcheck:
/healthcheck live
# Output: "heartbeat stale"
# Exit code: 1

# Kubernetes liveness probe now fails on every check.
# Container is restarted; re-create symlink after each restart to sustain the loop.
```