### Title
Predictable World-Writable `/tmp/alive` Allows Liveness Probe Spoofing Before First Heartbeat Tick

### Summary
The liveness exec probe in `pinger/cmd/healthcheck/main.go` trusts only the mtime of the hardcoded path `/tmp/alive` to determine process health. Because `/tmp` is world-writable and the heartbeat goroutine in `pinger/main.go` does not write the file at startup (only after the first 15-second tick), any unprivileged local user can pre-create `/tmp/alive` with a fresh mtime before the pinger starts. If the pinger then crashes during initialization (before the first tick), the liveness probe still returns exit 0, masking the failure for up to 2 minutes.

### Finding Description

**Liveness probe — `pinger/cmd/healthcheck/main.go`, lines 27–39:** [1](#0-0) 

The probe calls `os.Stat("/tmp/alive")` and checks only `time.Since(fi.ModTime()) > 2*time.Minute`. There is no check that:
- the pinger process is actually running,
- the file is owned by the pinger's UID, or
- the file was written after the current process started.

**Heartbeat goroutine — `pinger/main.go`, lines 28–39:** [2](#0-1) 

`time.NewTicker(15 * time.Second)` fires its first tick 15 seconds after the goroutine starts. The file `/tmp/alive` is **never written at startup**; it is only written on subsequent ticks.

**Fatal startup paths before first tick — `pinger/main.go`, lines 19–44:** [3](#0-2) 

Both `loadConfig()` (line 21) and `newClient(cfg)` (line 43) call `log.Fatalf`, terminating the process before the 15-second tick ever fires. If `/tmp/alive` was pre-created by an attacker, the probe returns exit 0 despite the process being dead.

**Root cause:** The liveness check conflates "file exists with fresh mtime" with "process is healthy." Because `/tmp` has the sticky bit but is world-writable (any user may create new files), the mtime is fully attacker-controlled.

### Impact Explanation
A Kubernetes liveness probe returning exit 0 tells the kubelet the container is healthy; it will not restart the pod. A pinger that crashes at startup (bad config, unreachable network, SDK init failure) will go undetected for up to 2 minutes (the staleness window). During that window, no transactions are submitted, no alerts fire, and the operator has no indication the service is down. In a monitoring/pinger role this directly defeats the purpose of the liveness probe.

### Likelihood Explanation
The precondition is write access to `/tmp` on the same host or pod. This is satisfied in any of these realistic scenarios:
- A shared Kubernetes node where another pod or init-container shares the host's `/tmp` (e.g., `hostPath` volume).
- A pod with a sidecar container sharing an `emptyDir` mounted at `/tmp`.
- A non-containerized deployment on a multi-user Linux host.
- A compromised or malicious init-container that runs before the pinger container.

The attack requires no privileges, no special tools, and is a single `touch /tmp/alive` command. It is trivially repeatable.

### Recommendation
1. **Write the heartbeat file immediately at startup** (before the ticker loop) so the file's existence is tied to the current process invocation, not a pre-existing file.
2. **Use a process-owned path** instead of `/tmp`: write to a directory created with `os.MkdirTemp` or a path under `/run/pinger/` with restricted permissions (`0700`), so other users cannot create or modify the file.
3. **Embed a process-start nonce** (e.g., PID or a random token written to the file at startup) and verify it in the healthcheck, so a stale or attacker-created file is rejected.
4. **Check file ownership** in the healthcheck: `syscall.Stat_t.Uid` must match the running process's UID.

### Proof of Concept
```bash
# 1. As an unprivileged user, pre-create the liveness file with a fresh mtime
touch /tmp/alive

# 2. Start the pinger with a broken config so it crashes before the first tick
PINGER_OPERATOR_KEY=invalid ./pinger &   # exits immediately via log.Fatalf

# 3. Immediately invoke the liveness probe (pinger is already dead)
./healthcheck live
echo "exit code: $?"   # prints: exit code: 0  <-- probe reports healthy

# 4. Confirm the pinger process is not running
pgrep -x pinger || echo "pinger is NOT running"

# The probe continues returning 0 for up to 2 minutes after the touch,
# masking the startup failure from Kubernetes.
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

**File:** pinger/main.go (L19-44)
```go
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// heartbeat for liveness exec probe (touches /tmp/alive)
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

	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```
