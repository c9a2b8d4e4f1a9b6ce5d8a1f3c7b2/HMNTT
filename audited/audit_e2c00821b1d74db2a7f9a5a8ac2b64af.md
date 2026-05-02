### Title
Retry Loop Creates New Transaction IDs, Enabling Double-Spend via gRPC Response Delay

### Summary
In `submitWithRetry()`, `hiero.NewTransferTransaction()` is called **inside** the retry loop, generating a fresh transaction with a new unique transaction ID on every attempt. If an attacker delays the gRPC response long enough to trigger the SDK's internal timeout, `Execute(client)` returns an error while the original transaction may already have been received and queued by the consensus node. The retry then submits a second, independent transaction — both are confirmed on-chain, double-charging the operator.

### Finding Description
**Exact location:** `pinger/transfer.go`, `submitWithRetry()`, lines 29–33.

```go
// lines 29-33 — inside the for loop, every iteration
cryptoTransfer := hiero.NewTransferTransaction().
    AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
    AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

resp, err := cryptoTransfer.Execute(client)
```

**Root cause:** `hiero.NewTransferTransaction()` is called on every loop iteration. Each call produces a new transaction object with a new, unique transaction ID (Hedera transaction IDs embed account ID + wall-clock timestamp/nonce). There is no mechanism to reuse the same transaction ID across retries.

**Exploit flow:**
1. Iteration 1: a new `TransferTransaction` (ID = `T1`) is built and `Execute(client)` sends it over gRPC to a consensus node.
2. The consensus node receives `T1` and queues it for processing, but the attacker delays the gRPC response.
3. The SDK's internal gRPC deadline fires; `Execute` returns a timeout error to the caller.
4. The loop increments `i`, calls `hiero.NewTransferTransaction()` again, producing `T2` (different ID), and submits it.
5. The consensus network processes both `T1` and `T2` independently — they have different IDs so Hedera's deduplication does not apply.
6. Both transactions are confirmed; the operator is charged twice.

**Why existing checks are insufficient:**
- The `ctx.Err()` guard at line 24 only handles context cancellation; it does not detect whether a prior submission reached the network.
- There is no receipt/status pre-check before retrying to determine whether `T1` was already confirmed.
- There is no idempotency key or fixed transaction ID shared across retry iterations. [1](#0-0) [2](#0-1) 

### Impact Explanation
Each attacker-induced timeout can cause one extra transfer of `cfg.amountTinybar` tinybar from the operator account. With `maxRetries` defaulting to 10 and `interval` defaulting to 1 s, an attacker sustaining the delay can drain up to 10× the configured amount per tick cycle. The operator account (`cfg.operatorID`) bears the loss directly; the destination account (`cfg.toAccountID`) receives duplicate credits. [3](#0-2) 

### Likelihood Explanation
The attacker requires the ability to delay (not drop) gRPC packets on the path between the pinger pod and at least one Hedera consensus node — achievable via a MitM position (compromised cloud router, BGP prefix hijack, or malicious ISP segment). No Hedera account, private key, or application-layer credential is needed. The attack is repeatable on every ticker interval and is fully reversible (attacker can stop delaying at will). In containerised/cloud deployments where the pinger reaches public consensus node IPs over the open internet, this path is realistic. [4](#0-3) 

### Recommendation
Move `hiero.NewTransferTransaction()` **outside** the retry loop so that all retry attempts reuse the same transaction ID. Hedera's consensus layer deduplicates transactions by ID, so a second submission of the same signed transaction is a no-op if the first was already processed.

```go
// Build once, before the loop
cryptoTransfer := hiero.NewTransferTransaction().
    AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
    AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

for i := 1; i <= attempts; i++ {
    resp, err := cryptoTransfer.Execute(client)
    ...
}
```

Additionally, before each retry, query the mirror node or consensus node for the status of the previous transaction ID to confirm it was not already accepted before re-submitting.

### Proof of Concept
1. Deploy the pinger against a testnet with `maxRetries=2`, `amountTinybar=10000`.
2. Position a transparent TCP proxy (e.g., `tc netem delay`) on the path to the consensus node gRPC port (50211).
3. On the first `Execute` call, inject a delay exceeding the SDK's gRPC deadline (~10 s by default).
4. Observe that `Execute` returns a timeout error; the loop creates a second `NewTransferTransaction` and submits it.
5. Remove the delay; both `T1` and `T2` are confirmed on-chain.
6. Query the operator account balance — it has been debited `2 × amountTinybar` for a single intended transfer. [5](#0-4)

### Citations

**File:** pinger/transfer.go (L14-60)
```go
func submitWithRetry(ctx context.Context, client *hiero.Client, cfg config) error {
	toID, err := hiero.AccountIDFromString(cfg.toAccountID)
	if err != nil {
		return fmt.Errorf("invalid destination id: %w", err)
	}

	var lastErr error
	attempts := cfg.maxRetries + 1

	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := time.Now()
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
		if err == nil {
			receipt, rerr := resp.GetReceipt(client)
			if rerr == nil {
				log.Printf("transfer success: status=%s txID=%s elapsed=%s",
					receipt.Status.String(), resp.TransactionID.String(), time.Since(start))
				return nil
			}
			err = rerr
		}

		lastErr = err
		log.Printf("attempt %d/%d failed: %v", i, attempts, err)

		if i < attempts {
			sleep := backoff(cfg.baseBackoff, i)
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	return fmt.Errorf("all attempts failed: %w", lastErr)
}
```

**File:** pinger/config.go (L58-67)
```go
	retriesStr := envOr("HIERO_MIRROR_PINGER_MAX_RETRIES", "10")
	flag.Func("max-retries", "max retries per tick", func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		cfg.maxRetries = v
		return nil
	})
	_ = flag.CommandLine.Set("max-retries", retriesStr)
```

**File:** pinger/main.go (L54-68)
```go
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Shutting down")
			return
		case <-ticker.C:
			if err := submitWithRetry(ctx, client, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("transfer failed: %v", err)
			}
```
