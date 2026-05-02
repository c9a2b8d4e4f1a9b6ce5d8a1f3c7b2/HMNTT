The code at the cited location is confirmed. Let me verify the exact lines match the claim.

The actual file [1](#0-0)  matches the claim exactly: `os.Stat("/tmp/alive")` is called with no subsequent `fi.Mode().IsRegular()` or `fi.IsDir()` check. The only guards are the `err != nil` check and the 2-minute `ModTime()` age window.

The SECURITY.md [2](#0-1)  does not exclude this class of finding. It excludes "best practice recommendations" and "theoretical impacts without proof," but this report provides a concrete exploit flow with no elevated privileges required, making it neither purely theoretical nor merely a best-practice suggestion.

---

Audit Report

## Title
Liveness Check Bypassed via Directory Substitution at `/tmp/alive`

## Summary
The `live` mode health check in `pinger/cmd/healthcheck/main.go` uses `os.Stat("/tmp/alive")` and checks only `ModTime()`, without verifying the path is a regular file. Because `os.Stat` succeeds on directories and a directory's mtime is controllable, an attacker who can place a directory at `/tmp/alive` can keep the liveness check permanently passing even after the pinger process has stopped.

## Finding Description
**Location:** `pinger/cmd/healthcheck/main.go`, `main()`, lines 27–38.

```go
fi, err := os.Stat("/tmp/alive")   // succeeds for directories too
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}

age := time.Since(fi.ModTime())    // directories have controllable mtimes
if age > 2*time.Minute {
    fmt.Fprintln(os.Stderr, "heartbeat stale")
    os.Exit(1)
}
os.Exit(0)
```

**Root cause:** The code never calls `fi.Mode().IsRegular()` or `fi.IsDir()`. `os.Stat` returns a valid `FileInfo` for any filesystem object — file, directory, symlink target, etc. A directory's mtime is updated whenever an entry inside it is created or removed, giving an attacker full control over apparent "freshness."

## Impact Explanation
The liveness probe is the mechanism by which Kubernetes detects a dead pinger and triggers a pod restart. By maintaining a directory at `/tmp/alive` with a fresh mtime, an attacker prevents the orchestrator from ever observing a failed liveness check. A crashed or hung pinger continues to appear healthy indefinitely, silently dropping all pinger functionality (monitoring, alerting, heartbeat forwarding) without any operator notification or automatic remediation.

## Likelihood Explanation
The precondition — placing a directory at `/tmp/alive` — is achievable in several realistic scenarios without elevated privileges:

- **Same-UID attacker** (compromised sidecar or another process running as the same service account): can unlink the file and `mkdir` the directory at any time.
- **Startup race**: if an attacker can execute code before the pinger first creates `/tmp/alive`, they create the directory first; the pinger's subsequent `os.WriteFile("/tmp/alive", …)` will fail (cannot overwrite a directory with a file), leaving the directory in place permanently.
- **Container environments without sticky-bit `/tmp`**: some minimal base images mount `/tmp` as a plain `tmpfs` without the sticky bit, making the path world-writable and world-deletable.

## Recommendation
Add an explicit file-type check immediately after the `os.Stat` call:

```go
fi, err := os.Stat("/tmp/alive")
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
if !fi.Mode().IsRegular() {
    fmt.Fprintln(os.Stderr, "heartbeat path is not a regular file")
    os.Exit(1)
}
```

This ensures that only a genuine regular file written by the pinger process can satisfy the liveness check.

## Proof of Concept

```bash
# 1. Kill or wait for the pinger to stop updating /tmp/alive
kill <pinger_pid>

# 2. Remove the stale file (possible if same UID or /tmp lacks sticky bit)
rm /tmp/alive

# 3. Create a directory in its place
mkdir /tmp/alive

# 4. Keep the directory mtime fresh (runs in background)
while true; do
    touch /tmp/alive/x && rm /tmp/alive/x
    sleep 60
done &

# 5. Liveness check now exits 0 indefinitely despite pinger being dead
healthcheck live; echo $?   # prints 0
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

**File:** SECURITY.md (L1-16)
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
```
