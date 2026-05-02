### Title
Heartbeat Decoupled from Transaction Success Enables Silent Liveness Probe Bypass Under Consensus Node Isolation

### Summary
The heartbeat goroutine in `pinger/main.go` writes `/tmp/alive` unconditionally every 15 seconds, completely independent of whether `submitWithRetry` is succeeding or failing. The liveness probe in `pinger/cmd/healthcheck/main.go` only checks the file's modification time, not transaction health. If an attacker makes the Hiero consensus node endpoints unreachable from the pinger (while leaving the Kubernetes node network intact), the pod reports itself as live indefinitely while silently failing to submit any transactions.

### Finding Description

**Heartbeat goroutine — `pinger/main.go` lines 28–39:**
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
The goroutine fires every 15 s and writes `/tmp/alive` regardless of transaction state. The only way it stops is `ctx.Done()`, which is only triggered by `SIGTERM`/`SIGINT`.

**Transfer failure path — `pinger/main.go` lines 62–68:**
```go
case <-ticker.C:
    if err := submitWithRetry(ctx, client, cfg); err != nil {
        if errors.Is(err, context.Canceled) {
            return
        }
        log.Printf("transfer failed: %v", err)
    }
```
A non-`context.Canceled` error (e.g., all retries exhausted because consensus nodes are unreachable) is only logged. The context is not cancelled, the heartbeat is not stopped, and `/tmp/alive` is not removed.

**Liveness check — `pinger/cmd/healthcheck/main.go` lines 26–39:**
```go
case "live":
    fi, err := os.Stat("/tmp/alive")
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
The check is purely temporal. As long as the process is alive and the ticker fires, `age` will always be ≤15 s, so `os.Exit(0)` is always reached — even when every single transaction has been failing for hours.

**Exploit flow:**
1. Attacker identifies the public gRPC endpoints of the Hiero consensus nodes (testnet/mainnet node IPs, port 50211). These are publicly documented.
2. Attacker floods those endpoints with traffic (volumetric DDoS, SYN flood, or UDP amplification targeting the node IPs) sufficient to make them unreachable from the pinger pod's egress path, while the Kubernetes kubelet/control-plane traffic (internal cluster CIDR) is unaffected.
3. `submitWithRetry` exhausts all retries (`maxRetries` default = 10) and returns an error on every tick.
4. The heartbeat goroutine continues writing `/tmp/alive` every 15 s.
5. Kubelet runs the liveness exec probe, gets `os.Exit(0)`, marks the pod `Running/Healthy`.
6. Kubernetes never restarts the pod. The pinger is silently non-functional for the entire duration of the attack.

### Impact Explanation
The pinger's entire purpose is to submit periodic transactions to verify end-to-end connectivity to the Hiero network. When it cannot do so, the liveness probe is supposed to trigger a pod restart (which may re-resolve DNS, pick a different node, or recover from a transient fault). Because the liveness signal is decoupled from transaction success, this recovery mechanism is completely bypassed. Any monitoring or alerting that relies on Kubernetes pod health status will show the service as healthy while it is entirely non-functional. The impact is silent, sustained loss of the pinger's monitoring function for the duration of the attack.

### Likelihood Explanation
The Hiero consensus node endpoints are publicly listed. Volumetric DDoS against specific IP:port targets requires no privileged access — it is a commodity attack available via booter services. The attacker does not need any credentials, cluster access, or knowledge of internal infrastructure. The attack is repeatable and can be sustained indefinitely. The only prerequisite is that the consensus node IPs are reachable from the public internet (which they are by design for a public ledger).

### Recommendation
The heartbeat write must be gated on recent transaction success. One concrete approach:

1. Maintain an atomic timestamp of the last successful `submitWithRetry` call.
2. In the heartbeat goroutine (or a separate goroutine), only write `/tmp/alive` if `time.Since(lastSuccess) < threshold` (e.g., `cfg.interval * (cfg.maxRetries + 2)`).
3. Alternatively, remove the separate heartbeat entirely and write `/tmp/alive` only inside the success branch of `submitWithRetry` (line 39 of `transfer.go`, after `return nil`).
4. The liveness threshold in `healthcheck/main.go` (`2*time.Minute`) must then be tuned to be greater than the maximum expected retry duration to avoid false negatives.

### Proof of Concept
```
# 1. Identify consensus node IPs for the configured network (e.g., testnet)
#    https://docs.hedera.com/hedera/networks/testnet/testnet-nodes

# 2. From an external host, flood the gRPC port of each consensus node
#    (no credentials required):
hping3 --flood --rand-source -S -p 50211 <consensus-node-ip>

# 3. While the flood is running, exec into the pinger pod and observe:
kubectl exec -n <ns> <pinger-pod> -- /bin/sh -c \
  'while true; do
     cat /tmp/alive
     /healthcheck live && echo "LIVENESS: PASS" || echo "LIVENESS: FAIL"
     sleep 10
   done'

# Expected output: /tmp/alive is refreshed every 15 s, liveness returns PASS,
# while pinger logs show continuous "transfer failed" errors.

# 4. Confirm Kubernetes never restarts the pod:
kubectl get pod <pinger-pod> -n <ns> -w
# RESTARTS column stays at 0 throughout the attack.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** pinger/main.go (L62-68)
```go
		case <-ticker.C:
			if err := submitWithRetry(ctx, client, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("transfer failed: %v", err)
			}
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
