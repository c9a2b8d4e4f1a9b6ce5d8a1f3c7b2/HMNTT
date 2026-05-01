### Title
Retry Loop Re-Executes New Transactions After Receipt Failure, Causing Multiple Unintended Transfers

### Summary
In `pinger/transfer.go`, `submitWithRetry()` constructs a brand-new `TransferTransaction` on every loop iteration. Because each new transaction object receives a fresh `TransactionID` at `Execute()` time, a failure of `GetReceipt()` after a successful `Execute()` causes the retry to submit a completely independent second transaction — both of which settle on-chain, draining `cfg.amountTinybar` per extra attempt.

### Finding Description
**Exact code path:** `pinger/transfer.go`, `submitWithRetry()`, lines 23–57.

```
// line 29-31: NEW transaction object created every iteration
cryptoTransfer := hiero.NewTransferTransaction().
    AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
    AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

resp, err := cryptoTransfer.Execute(client)   // line 33 — TX1 submitted, accepted on-chain
if err == nil {
    receipt, rerr := resp.GetReceipt(client)  // line 35 — times out / network error
    if rerr == nil { return nil }
    err = rerr                                // line 41 — falls through to retry
}
// ... backoff ...
// next iteration: NEW transaction TX2 created, Execute() called again
```

**Root cause:** The Hiero SDK assigns a `TransactionID` (payer account + current wall-clock nanosecond timestamp) when `Execute()` is called on a freshly constructed transaction. Because `hiero.NewTransferTransaction()` is called at the top of every loop iteration, each retry produces a distinct `TransactionID`. There is no call to `SetTransactionID()` to pin a reusable ID, and no pre-flight check to determine whether the previous transaction already reached consensus.

**Failed assumption:** The code assumes that a `GetReceipt()` error means the transfer did not execute. In reality, `GetReceipt()` can fail (timeout, transient gRPC error, network disruption) even when the underlying transaction has already been finalized on-chain.

**Exploit flow:**
1. Iteration 1: `Execute()` submits TX1 → consensus node accepts it, funds move.
2. `GetReceipt()` call times out or returns a transient error (e.g., `RECEIPT_NOT_FOUND` before the mirror propagates, or a network-level disruption).
3. `err = rerr` → loop continues.
4. Iteration 2: a new `TransferTransaction` is built with a new `TransactionID` → `Execute()` submits TX2 → funds move again.
5. Steps 2–4 repeat up to `cfg.maxRetries` (default **10**) times.

**No existing mitigations:** The `grep` search over the entire `pinger/` directory confirms zero uses of `SetTransactionID`, idempotency keys, or any pre-retry query to check whether the prior transaction succeeded. [1](#0-0) [2](#0-1) 

### Impact Explanation
Each failed receipt check that follows a successful `Execute()` causes one additional transfer of `cfg.amountTinybar` (default **10 000 tinybar**) from the operator account. With the default `maxRetries = 10`, a single "stuck" tick can drain up to **110 000 tinybar** instead of 10 000. The pinger runs on a ticker (default every 1 s), so repeated triggering compounds the loss. Although the per-tick amount is small in absolute terms, the operator key is a long-lived service credential and the loop runs indefinitely, making cumulative drain realistic. [3](#0-2) [4](#0-3) 

### Likelihood Explanation
The bug fires under **ordinary network conditions** without any attacker: a slow consensus node, a brief mirror-node lag, or a transient gRPC timeout on `GetReceipt()` is sufficient. An adversary who can influence network latency between the pinger pod and the Hedera network (e.g., cloud-provider network policy, BGP manipulation, or simply saturating the node's receipt endpoint) can reliably and repeatedly trigger the condition. No access to the operator key or the pinger process is required. [5](#0-4) 

### Recommendation
**Pin the transaction ID across retries.** Generate the `TransactionID` once before the loop and call `SetTransactionID()` on every reconstructed transaction:

```go
txID := hiero.TransactionIDGenerate(client.GetOperatorAccountID())

for i := 1; i <= attempts; i++ {
    cryptoTransfer := hiero.NewTransferTransaction().
        SetTransactionID(txID).                          // reuse same ID
        AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
        AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))
    ...
}
```

Because Hedera deduplicates transactions by `TransactionID`, re-submitting the same ID is a no-op if the transaction already reached consensus; `GetReceipt()` on the retry will then return the cached `SUCCESS` status. Additionally, before retrying after a receipt error, query the receipt directly (e.g., `TransactionReceiptQuery`) to confirm the prior transaction's status before submitting again.

### Proof of Concept
**Preconditions:**
- Pinger running with default config (`maxRetries=10`, `amountTinybar=10000`).
- Attacker (or natural condition) can cause `GetReceipt()` to return an error after `Execute()` succeeds.

**Steps:**
1. Start the pinger against testnet.
2. On the first tick, intercept/delay the receipt response (e.g., via `tc netem` on the pinger host, or by temporarily blocking port 50211 after the `Execute()` gRPC call completes).
3. Observe the log: `attempt 1/11 failed: <receipt error>`.
4. The loop continues; iteration 2 calls `Execute()` with a new transaction ID.
5. Query the operator account balance on the Hedera explorer: two separate `CRYPTOTRANSFER` transactions appear, each debiting 10 000 tinybar, for a total of 20 000 tinybar deducted in one tick.
6. Repeat the disruption on subsequent ticks to drain up to 110 000 tinybar per tick. [1](#0-0)

### Citations

**File:** pinger/transfer.go (L23-57)
```go
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
```

**File:** pinger/config.go (L44-53)
```go
	amountStr := envOr("HIERO_MIRROR_PINGER_AMOUNT_TINYBAR", "10000")
	flag.Func("amount-tinybar", "amount in tinybar (int64)", func(s string) error {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		cfg.amountTinybar = v
		return nil
	})
	_ = flag.CommandLine.Set("amount-tinybar", amountStr)
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

**File:** pinger/main.go (L57-69)
```go
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
		}
```
