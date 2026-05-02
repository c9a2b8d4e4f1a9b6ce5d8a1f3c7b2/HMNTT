### Title
Liveness Probe Spoofing via Arbitrary File Type at `/tmp/alive` — No File-Type or Ownership Validation

### Summary
The `healthcheck` binary's `live` mode calls `os.Stat("/tmp/alive")` and checks only that the file exists and has a `ModTime()` within the last 2 minutes. It performs no check on file type, ownership, or content. Because `os.Stat()` succeeds on any filesystem object — including Unix domain sockets — any process running as the same UID as the pinger (UID 1000) can create a socket at `/tmp/alive` and periodically recreate it to keep its mtime fresh, causing the Kubernetes liveness probe to pass indefinitely even when the real pinger heartbeat goroutine is dead.

### Finding Description

**Exact code location:**

`pinger/cmd/healthcheck/main.go`, lines 27–39:
```go
fi, err := os.Stat("/tmp/alive")   // succeeds on socket, pipe, symlink target, etc.
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
```

**Root cause:** The probe trusts `os.Stat()` on an unvalidated path. It never asserts `fi.Mode().IsRegular()`, never checks `fi.Sys().(*syscall.Stat_t).Uid`, and never reads or validates file content.

**Silent write failure compounds the issue:** `pinger/main.go` line 36 writes the heartbeat with:
```go
_ = os.WriteFile("/tmp/alive", []byte(...), 0644)
```
`os.WriteFile` opens with `O_WRONLY|O_CREATE|O_TRUNC`. On a socket inode this returns `ENXIO`; the error is discarded (`_`). The socket therefore persists untouched, and the pinger's own heartbeat silently stops updating the file.

**Exploit flow:**
1. Attacker gains code execution in the container as UID 1000 (the only UID present per `USER 1000:1000` in the Dockerfile).
2. Attacker removes `/tmp/alive` (they own it — same UID) and binds a Unix domain socket there: `net.Listen("unix", "/tmp/alive")`.
3. Every ~90 seconds the attacker's goroutine removes and re-creates the socket to refresh its mtime.
4. The pinger's heartbeat goroutine silently fails every 15 s (error discarded).
5. Kubelet runs `/healthcheck live` → `os.Stat` succeeds, mtime < 2 min → exit 0 → liveness probe passes.
6. Kubernetes never restarts the container; the pinger's actual transfer loop may be hung or dead.

**Existing checks reviewed:**
- Only two checks exist: `err != nil` (file must be stat-able) and `age > 2*time.Minute` (mtime freshness). Neither is sufficient.
- No `fi.Mode().IsRegular()` guard.
- No UID/GID ownership assertion.
- No content read or HMAC/nonce verification.

### Impact Explanation
The liveness probe is the sole mechanism by which Kubernetes detects a hung or crashed pinger and triggers a pod restart. Spoofing it means a silently dead pinger — one that is no longer submitting Hedera transfers or monitoring the mirror node — will never be restarted automatically. This is a **availability / monitoring integrity** impact: the pinger appears healthy while performing no work, defeating the purpose of the component entirely.

### Likelihood Explanation
Precondition is code execution inside the container as UID 1000. This is achievable via a supply-chain compromise of a dependency, a deserialization/RCE bug in any future feature, or a misconfigured `kubectl exec` policy. The container is `FROM scratch` with no shell, which raises the bar slightly, but a compiled Go payload dropped via any write primitive suffices. Once inside, the exploit is trivially repeatable with a simple loop and requires no elevated privileges whatsoever.

### Recommendation
1. **Assert regular file type** immediately after `os.Stat`:
   ```go
   if !fi.Mode().IsRegular() {
       fmt.Fprintln(os.Stderr, "heartbeat file is not a regular file")
       os.Exit(1)
   }
   ```
2. **Assert ownership** via `fi.Sys().(*syscall.Stat_t).Uid == uint32(os.Getuid())`.
3. **Read and validate content** — the pinger already writes `time.RFC3339Nano`; parse it and compare to wall clock instead of relying solely on mtime.
4. **Do not discard the `os.WriteFile` error** in `pinger/main.go:36`; log it so silent heartbeat failures are observable.
5. Consider writing the heartbeat file to a path inside a directory owned and mode-restricted to UID 1000 (e.g., `/run/pinger/alive`) rather than world-writable `/tmp`.

### Proof of Concept
```go
// attacker.go — compile and drop into container, run as UID 1000
package main

import (
    "net"
    "os"
    "time"
)

func main() {
    for {
        os.Remove("/tmp/alive")
        l, _ := net.Listen("unix", "/tmp/alive")
        // mtime is now fresh; healthcheck will pass
        time.Sleep(90 * time.Second)
        l.Close()
        // loop: recreate before 2-minute window expires
    }
}
```
Run `/healthcheck live`; it exits 0 despite the pinger heartbeat goroutine being unable to write to the socket (error silently discarded at `pinger/main.go:36`).