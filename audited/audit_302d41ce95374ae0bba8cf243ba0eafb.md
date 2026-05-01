### Title
Unconditional Liveness Heartbeat Decoupled from Transfer Success Enables Silent Indefinite Failure

### Summary
The pinger's liveness heartbeat goroutine writes `/tmp/alive` unconditionally every 15 seconds regardless of whether transfers are succeeding or failing. When an attacker causes sustained transfer failures, the main loop logs errors indefinitely while the orchestrator's liveness probe continues to see the process as healthy, allowing a network partition to persist undetected for an unbounded duration with no automated remediation.

### Finding Description
**Code locations:**

- `pinger/main.go` lines 28–39: The heartbeat goroutine ticks every 15 seconds and writes `/tmp/alive` unconditionally — it has no awareness of transfer outcomes.
- `pinger/main.go` lines 62–68: On every `ticker.C` tick, `submitWithRetry` is called; if it returns a non-`context.Canceled` error, the only action is `log.Printf("transfer failed: %v", err)`. There is no failure counter, no circuit breaker, no threshold, and no process exit.
- `pinger/transfer.go` lines 14–59: `submitWithRetry` exhausts up to `maxRetries+1` attempts with exponential backoff capped at 30 s, then returns `"all attempts failed: %w"`. After that, control returns to the main loop which simply logs and loops again.

**Root cause:** The liveness signal (`/tmp/alive`) is structurally decoupled from the transfer health signal. The design assumption is that "process is running" ≡ "transfers are succeeding," which is false under sustained failure. There is no mechanism that ties consecutive transfer failures to any observable state change (file removal, counter, metric, exit code) that an orchestrator or alerting system could act on.

**Exploit flow:**
1. Attacker causes a network partition (blocks UDP/TCP to Hedera consensus nodes, poisons DNS, or causes the nodes to return errors) — no privileged access to the pinger host is required.
2. Every `cfg.interval` tick, `submitWithRetry` exhausts all retries and returns an error.
3. Main loop logs `"transfer failed: …"` and immediately waits for the next tick.
4. Heartbeat goroutine independently writes `/tmp/alive` every 15 s — the file is always fresh.
5. The readiness file `/tmp/ready` (written once at startup, line 47) is never removed.
6. The orchestrator's exec liveness probe sees a recently-updated `/tmp/alive` and does not restart the pod.
7. Steps 2–6 repeat indefinitely with no automated response.

**Why existing checks are insufficient:**
- `submitWithRetry` retries are per-tick only; they do not accumulate state across ticks.
- `errors.Is(err, context.Canceled)` (line 64) only exits on graceful shutdown, not on transfer failure.
- There is no consecutive-failure counter anywhere in the codebase.
- The heartbeat goroutine has no channel or shared variable connecting it to transfer results.

### Impact Explanation
The pinger exists specifically to detect network-level issues with the Hedera mirror node. If an attacker can silence the pinger's alerting path while keeping it appearing healthy to the orchestrator, the entire monitoring purpose of the component is defeated. A network partition can persist for hours or days without triggering a pod restart, a PagerDuty alert, or any automated remediation — the only detection path is a human manually reading logs.

### Likelihood Explanation
No privileged access to the pinger host or cluster is required. Any attacker with the ability to influence network reachability between the pinger and Hedera consensus nodes (BGP manipulation, DNS poisoning, firewall rule injection on a shared network path, or simply taking down the target nodes) satisfies the precondition. The attack is fully repeatable and requires no ongoing interaction once the partition is established.

### Recommendation
Tie the liveness signal to transfer health:

1. **Failure counter with liveness gate:** Maintain a consecutive-failure counter in the main loop. If it exceeds a configurable threshold (e.g., `cfg.maxConsecutiveFailures`), stop updating `/tmp/alive` (or delete it). The orchestrator's exec probe will then fail and restart the pod.
2. **Alternatively, exit on threshold:** Call `log.Fatalf` (or `os.Exit(1)`) after N consecutive failures, letting the orchestrator's restart policy handle recovery.
3. **Separate liveness from heartbeat:** Replace the time-based heartbeat with a success-gated write: only update `/tmp/alive` after a successful transfer, and configure the exec probe's `failureThreshold` × `periodSeconds` to match the acceptable outage window.

### Proof of Concept
```
# Precondition: pinger is running, targeting testnet/mainnet
# Step 1: Block outbound traffic to Hedera consensus node ports (50211/50212)
#         from the pinger's network namespace (no host privilege needed if
#         attacker controls an upstream firewall or shared network device).
iptables -I OUTPUT -p tcp --dport 50211 -j DROP   # example on a shared host

# Step 2: Observe pinger logs — errors appear every cfg.interval indefinitely:
#   transfer failed: all attempts failed: ...

# Step 3: Verify liveness file is still being updated (process appears healthy):
watch -n 5 'cat /tmp/alive'   # timestamp advances every 15 s despite all failures

# Step 4: Verify orchestrator does NOT restart the pod:
kubectl get pod <pinger-pod> --watch   # RESTARTS column stays at 0

# Result: Network partition is active, pinger logs errors, orchestrator is blind,
#         no alert fires, partition persists undetected indefinitely.
```