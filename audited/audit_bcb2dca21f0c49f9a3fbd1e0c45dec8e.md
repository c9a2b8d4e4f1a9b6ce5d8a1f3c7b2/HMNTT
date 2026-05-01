### Title
Duplicate `TransferTransaction` Execution via `GetReceipt()` Failure in `submitWithRetry()`

### Summary
`submitWithRetry()` in `pinger/transfer.go` constructs a **new** `TransferTransaction` on every retry iteration. If `Execute()` succeeds (transaction accepted and executed on-chain) but `GetReceipt()` subsequently fails due to a network-level delay or drop, the function treats the attempt as failed and retries with a fresh transaction carrying a new `TransactionID`. Because Hedera deduplicates only by `TransactionID`, each retry is treated as an independent transfer, causing the operator account to be debited once per retry.

### Finding Description

**Exact code path** — `pinger/transfer.go`, `submitWithRetry()`, lines 23–57: [1](#0-0) 

On every loop iteration, a new `TransferTransaction` is constructed at lines 29–31: [2](#0-1) 

`Execute(client)` at line 33 submits the transaction to the Hedera consensus network. A `nil` error from `Execute` means the transaction has been accepted and will be finalized on-chain — the debit has already occurred. [3](#0-2) 

`GetReceipt(client)` at line 35 is a separate, subsequent network call to a mirror/consensus node to retrieve the receipt. If this call fails (timeout, TCP reset, packet drop), `rerr` is non-nil: [4](#0-3) 

The error is assigned to `err` and the loop continues. On the next iteration, `hiero.NewTransferTransaction()` produces a transaction with a **new** `TransactionID` (new `validStart` timestamp auto-assigned by the SDK). Hedera's replay-protection deduplicates only within the same `TransactionID`; a new ID bypasses it entirely. The second `Execute(client)` call submits and executes a completely independent transfer.

**Root cause**: The failed assumption is that a `GetReceipt()` error implies the transaction did not execute. In reality, `Execute()` success and `GetReceipt()` success are two independent network round-trips. The code conflates receipt-query failure with transaction failure.

### Impact Explanation
Each successful `Execute()` followed by a dropped `GetReceipt()` response causes one additional debit of `cfg.amountTinybar` from the operator account. With `maxRetries = N`, up to `N+1` independent transfers can execute in a single pinger interval, multiplying the intended transfer amount by up to `N+1`. Since this is a monitoring/liveness tool that runs continuously on a ticker, an attacker who can sustain the interference across multiple intervals can drain the operator account progressively. Severity: **Critical** (direct, repeatable loss of funds from the operator account).

### Likelihood Explanation
The attacker must be able to delay or drop the `GetReceipt()` response without affecting the `Execute()` call. Realistic positions:

- **Network path attacker (MITM)**: If the pinger's egress path to the Hedera mirror/consensus node passes through attacker-controlled infrastructure (e.g., a cloud NAT gateway, a shared network segment, a BGP-hijacked route), the attacker can selectively drop TCP segments carrying the receipt response while allowing the submission to pass.
- **Malicious or compromised Hedera node**: The SDK may query a specific node for the receipt; a node operator who is malicious can return errors or time out on receipt queries while still processing submitted transactions.
- **Induced congestion / packet loss**: Even non-targeted packet loss (e.g., >5% loss on a flaky link) can cause `GetReceipt()` to time out while `Execute()` already succeeded, triggering unintentional duplicate debits without any active attacker.

No privileged access to the pinger process, its keys, or the Hedera network is required. The attacker only needs to influence the network path for the receipt query.

### Recommendation

1. **Reuse the same `TransactionID` across retries.** Generate the `TransactionID` once before the loop using `hiero.TransactionIDGenerate(operatorID)`, set it on the transaction with `SetTransactionID()`, and reuse it on every retry. Hedera will deduplicate subsequent submissions with the same ID.

2. **Query receipt before retrying submission.** After a `GetReceipt()` failure, re-query the receipt for the already-submitted `resp.TransactionID` before constructing and submitting a new transaction. Only submit a new transaction if the receipt query confirms the original transaction did not reach consensus (e.g., `UNKNOWN` or expired).

3. **Separate transient receipt errors from transaction errors.** Distinguish SDK errors that indicate the transaction was not found/expired from errors that indicate a local network failure on the receipt query, and handle them differently.

### Proof of Concept

**Preconditions:**
- Pinger is running with `maxRetries >= 1`.
- Attacker controls or can influence the network path between the pinger and the Hedera node used for receipt queries (not submission).

**Steps:**

1. Pinger ticker fires; `submitWithRetry()` is called.
2. `cryptoTransfer.Execute(client)` succeeds — transaction T1 with ID `(operatorID, t1)` is submitted and accepted by the network. The operator is debited `amountTinybar`.
3. Attacker drops/delays the TCP response to `resp.GetReceipt(client)`. The call returns a timeout/network error (`rerr != nil`).
4. `err = rerr`; the loop continues to iteration 2.
5. `hiero.NewTransferTransaction()` creates transaction T2 with a new ID `(operatorID, t2)` where `t2 != t1`.
6. `cryptoTransfer.Execute(client)` succeeds — T2 is submitted and accepted. The operator is debited `amountTinybar` a second time.
7. If the attacker again drops the `GetReceipt()` response, step 5–6 repeats for T3, T4, … up to `maxRetries + 1` total debits per pinger interval.
8. Both T1 and T2 (and further) appear as separate finalized `CRYPTOTRANSFER` transactions on-chain, each with a distinct `TransactionID`, confirming multiple debits.

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
