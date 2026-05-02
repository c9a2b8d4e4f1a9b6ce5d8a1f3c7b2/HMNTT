### Title
Retry Loop Creates Fresh Transaction IDs, Enabling Double-Submission on Receipt-Query Failure

### Summary
In `pinger/transfer.go`, `submitWithRetry()` constructs a brand-new `TransferTransaction` (and therefore a new Hedera transaction ID) on every loop iteration. If `Execute(client)` succeeds—meaning the transaction is already accepted by the network—but `GetReceipt(client)` subsequently fails due to a network disruption, the function retries and submits a second, distinct transaction. Both transactions settle on-chain and appear in the mirror node history, producing two transaction IDs for what should be a single per-tick transfer event.

### Finding Description
**Exact code path:** `pinger/transfer.go`, `submitWithRetry()`, lines 23–59.

```
// line 29 — inside the retry loop
cryptoTransfer := hiero.NewTransferTransaction().
    AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
    AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

resp, err := cryptoTransfer.Execute(client)   // TX1 submitted & accepted
if err == nil {
    receipt, rerr := resp.GetReceipt(client)  // ← disruption here
    if rerr == nil { return nil }
    err = rerr                                // falls through to retry
}
// ... backoff, then loop again → NewTransferTransaction() → TX2
```

**Root cause:** `hiero.NewTransferTransaction()` is called on every iteration of the retry loop. Hedera transaction IDs embed a timestamp and operator account ID; each `NewTransferTransaction()` call produces a unique ID. Hedera's built-in deduplication only suppresses re-submissions of the *same* transaction ID. Because each retry generates a fresh ID, Hedera treats every retry as an independent, new transaction.

**Failed assumption:** The code assumes that a `GetReceipt` failure implies the transaction was not executed. In reality, `Execute` performs the gRPC `submitTransaction` call; once it returns `nil`, the transaction has been accepted into the network's mempool and will almost certainly be finalized. `GetReceipt` is only a *status query*—its failure says nothing about whether the underlying transaction settled.

**Exploit flow:**
1. The pinger's ticker fires (one logical tick).
2. `Execute(client)` returns `nil` → TX1 (e.g., `0.0.X@1746000000.000000001`) is submitted to Hedera and will settle.
3. An attacker (or natural disruption) drops/resets the TCP connection used by `GetReceipt`; `rerr != nil`.
4. The loop continues; `NewTransferTransaction()` creates TX2 with a new timestamp-based ID.
5. `Execute(client)` returns `nil` for TX2 → TX2 also settles on-chain.
6. Both TX1 and TX2 appear in the mirror node's transaction history for this tick interval.

**Why existing checks are insufficient:**
- The `ctx.Err()` guard (line 24) only aborts if the Go context is cancelled; it does not detect that a prior `Execute` already succeeded.
- There is no "already-submitted" flag or idempotency key carried across iterations.
- `maxRetries` (default 10, config line 58 of `config.go`) allows up to 11 total submissions per tick.

### Impact Explanation
- **Double (or multi) spend per tick:** The operator account is debited `amountTinybar` for each successful `Execute`, not just once per tick. With `maxRetries=10`, up to 11 transfers can be charged in a single tick.
- **Mirror node history corruption:** The mirror node records one transaction per `Execute` that settles. The expected invariant of exactly one transfer per tick interval is violated; auditors or downstream consumers of the mirror node API see multiple transaction IDs for a single logical event, breaking any tooling that relies on the one-per-tick assumption.
- **Severity:** Medium-High. Direct financial loss (repeated debits) plus integrity loss of the pinger's audit trail.

### Likelihood Explanation
Triggering `GetReceipt` failure while `Execute` has already succeeded requires disrupting the network path between the pinger and the Hedera consensus/mirror node *after* the `submitTransaction` gRPC call completes. Practical vectors:

- **Network-level attacker** on the same segment (cloud VPC, shared hosting): TCP RST injection timed to the receipt-query window.
- **BGP hijacking / route manipulation** against the Hedera node IPs.
- **Transient infrastructure failures** (cloud provider blip, DNS flap): no attacker needed; this fires naturally under normal operational stress.

No credentials, no privileged access to the pinger process, and no Hedera account are required. The default `maxRetries=10` and `baseBackoff=2s` mean the window for repeated exploitation within a single tick is wide. Repeatability is high because the pinger runs continuously on a ticker.

### Recommendation
Move `NewTransferTransaction()` **outside** the retry loop so the same transaction object (and therefore the same transaction ID) is reused on every retry attempt. Hedera will deduplicate re-submissions of an already-finalized transaction ID and return the existing receipt, making retries idempotent:

```go
// Build once, before the loop
cryptoTransfer := hiero.NewTransferTransaction().
    AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
    AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

for i := 1; i <= attempts; i++ {
    resp, err := cryptoTransfer.Execute(client)
    if err == nil {
        receipt, rerr := resp.GetReceipt(client)
        if rerr == nil { return nil }
        err = rerr
    }
    // backoff ...
}
```

Additionally, consider distinguishing "receipt query failed" from "transaction submission failed" and skipping further `Execute` calls if a prior `Execute` already returned `nil`.

### Proof of Concept
**Preconditions:**
- Pinger running with `maxRetries ≥ 1` (default 10).
- Attacker can inject TCP RST packets on the path between the pinger host and the Hedera node used for receipt queries (or simulate with `iptables -A OUTPUT -p tcp --dport 443 -m statistic --mode nth --every 1 --packet 1 -j REJECT` timed to fire after `Execute` returns).

**Steps:**
1. Start the pinger normally.
2. Wait for a ticker event; observe `Execute` completing (log line or packet capture).
3. Immediately drop the TCP connection used by `GetReceipt` (e.g., `tcpkill` or `iptables` rule active for ~2 s).
4. Observe the pinger log: `attempt 1/11 failed: <receipt error>` followed by a second `Execute` call.
5. Query the Hedera mirror node REST API for transactions from the operator account in the tick window:
   ```
   GET /api/v1/transactions?account.id=<operatorID>&order=asc&limit=20
   ```
6. Observe two distinct transaction IDs with the same transfer amounts within the same tick interval, confirming double submission. [1](#0-0) [2](#0-1) [3](#0-2)

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
