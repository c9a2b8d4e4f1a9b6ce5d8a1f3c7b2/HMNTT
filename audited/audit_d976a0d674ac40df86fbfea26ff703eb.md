### Title
Heartbeat Goroutine Writes `/tmp/alive` Unconditionally, Masking Complete Network Partition from Liveness Probe

### Summary
The heartbeat goroutine in `pinger/main.go` writes `/tmp/alive` every 15 seconds on a timer that is entirely independent of whether `submitWithRetry()` succeeds or fails. When an attacker causes all consensus node responses to be delayed or dropped beyond the SDK's internal timeout, every transfer attempt silently fails (logged only), while the heartbeat continues refreshing `/tmp/alive`, causing the Kubernetes liveness probe to permanently report the pod as healthy and suppressing automated recovery.

### Finding Description
**Exact code path:**

In `pinger/main.go` lines 28–39, the heartbeat goroutine is launched as a standalone goroutine with its own `time.NewTicker(15 * time.Second)`. On every tick it unconditionally executes:
```go
_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
```
There is no check of any transfer result, no shared state, no channel, and no flag that could suppress this write.

In `pinger/main.go` lines 62–68, the transfer loop calls `submitWithRetry()` and on failure only logs:
```go
log.Printf("transfer failed: %v", err)
```
The process continues running; the heartbeat goroutine is never signaled.

In `pinger/transfer.go` lines 23–59, `submitWithRetry()` exhausts all `cfg.maxRetries + 1` attempts (default: 11) and returns `fmt.Errorf("all attempts failed: %w", lastErr)`. This error propagates back to `main()` where it is only logged.

In `pinger/cmd/healthcheck/main.go` lines 27–38, the liveness probe checks only:
1. Does `/tmp/alive` exist?
2. Is its `ModTime()` within the last 2 minutes?

It has no knowledge of transfer success or failure.

**Root cause:** The design assumes the heartbeat represents application health, but it is structurally decoupled from the only meaningful health signal — whether consensus node transactions are succeeding. The failed assumption is that a running process implies a functioning network path.

**Exploit flow:**
1. Attacker positions themselves to delay or drop all gRPC traffic to consensus nodes (e.g., BGP route injection, firewall rule insertion at a network boundary, or simply a real network partition).
2. Every call to `cryptoTransfer.Execute(client)` in `transfer.go` line 33 blocks until the SDK's internal per-node timeout fires, then fails.
3. All 11 attempts (1 + 10 retries with exponential backoff capped at 30s) fail; `submitWithRetry()` returns an error.
4. `main()` logs the error and loops back to wait for the next ticker tick.
5. Meanwhile, the heartbeat goroutine fires every 15 seconds and writes a fresh timestamp to `/tmp/alive`.
6. Kubernetes runs `/healthcheck live` every 10 seconds (per `values.yaml` line 42), finds `/tmp/alive` with a recent `ModTime`, and reports the pod as live.
7. The pod is never restarted. The network partition is invisible to the orchestration layer indefinitely.

### Impact Explanation
The pinger's entire purpose is to detect network-level failures between the mirror node deployment and the Hedera consensus network. When this masking occurs, the liveness probe — the only automated recovery mechanism — is permanently satisfied despite zero successful transactions. Operators receive no automated alert or pod restart. The failure is only visible in logs, which may not be actively monitored. This defeats the availability guarantee the pinger is designed to provide and can mask a sustained, complete network partition for an unbounded duration.

### Likelihood Explanation
No privileged access to the pod or cluster is required. Any attacker capable of causing a network partition between the pinger pod and consensus nodes — including BGP hijacking, upstream firewall misconfiguration, cloud security group changes, or a real infrastructure outage — triggers this condition. The condition is also reachable by an insider or misconfigured infrastructure without any malicious intent. It is fully repeatable: as long as the partition persists, the masking persists. The default retry configuration (10 retries, 2s base backoff, capped at 30s) means each tick can block the transfer goroutine for several minutes, but the heartbeat goroutine is unaffected throughout.

### Recommendation
Couple the heartbeat write to observed transfer health. Concrete options:

1. **Conditional heartbeat:** Only write `/tmp/alive` when `submitWithRetry()` succeeds. Move the `os.WriteFile` call into the success branch of the transfer loop, removing the independent goroutine entirely.

2. **Shared atomic flag:** Have `submitWithRetry()` set an `atomic.Bool` on success and clear it on failure. The heartbeat goroutine checks the flag before writing `/tmp/alive`.

3. **Deadline-based staleness:** Record the last successful transfer time atomically. The heartbeat goroutine writes `/tmp/alive` only if `time.Since(lastSuccess) < threshold`, where threshold is less than the 2-minute liveness window.

Option 1 is the simplest and eliminates the decoupling entirely:
```go
case <-ticker.C:
    if err := submitWithRetry(ctx, client, cfg); err != nil {
        if errors.Is(err, context.Canceled) { return }
        log.Printf("transfer failed: %v", err)
        // do NOT touch /tmp/alive
    } else {
        _ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
    }
```

### Proof of Concept
**Preconditions:** Pinger pod running with default config (`maxRetries=10`, `baseBackoff=2s`). Liveness probe configured as in `values.yaml` (`periodSeconds=10`, `failureThreshold=5`).

**Steps:**
1. Block all outbound gRPC traffic from the pinger pod to consensus node IPs/ports (e.g., via `iptables -A OUTPUT -p tcp --dport 50211 -j DROP` on the node, or a network policy change).
2. Observe logs: `transfer failed: all attempts failed: ...` appears on every ticker interval.
3. Simultaneously observe `/tmp/alive` inside the pod: `watch -n1 stat /tmp/alive` — the `ModTime` updates every 15 seconds.
4. Run `/healthcheck live` inside the pod — it exits 0 (healthy) on every invocation.
5. Observe Kubernetes pod status: pod remains `Running`, never enters `CrashLoopBackOff` or gets restarted.
6. The partition can persist indefinitely with the pod permanently reporting healthy.