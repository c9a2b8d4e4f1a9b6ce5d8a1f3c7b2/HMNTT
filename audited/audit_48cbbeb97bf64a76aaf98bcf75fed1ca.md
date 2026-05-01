### Title
Unbounded sigPair Count in Fee Estimation Endpoint Allows Arbitrary Fee Inflation

### Summary
The `POST /api/v1/network/fees` endpoint in `NetworkController` accepts an unauthenticated protobuf `Transaction` and passes it directly to `FeeEstimationService.estimateFees()`. Inside `TransactionFeeContext`, `numTxnSignatures` is set to the raw `.sigPair().size()` of the submitted `SignatureMap` with no cap or validation. Because the fee calculator scales the estimate linearly with `numTxnSignatures`, any unauthenticated caller can submit a transaction containing an arbitrarily large number of fake `sigPair` entries to obtain an arbitrarily inflated fee estimate, misleading downstream callers about the true cost of the transaction.

### Finding Description
**Exact code path:**

`NetworkController.estimateFees()` (lines 113–124) accepts `@RequestBody @NotNull byte[] body` with no `@Size` constraint on the body, parses it as a `Transaction`, and calls `feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle)`.

`FeeEstimationService.estimateFees()` (lines 95–116) constructs a `TransactionFeeContext(transaction)`.

Inside `TransactionFeeContext` (lines 136–154), for the `signedTransactionBytes` path:
```java
this.numTxnSignatures = signedTransaction
        .sigMapOrElse(SignatureMap.DEFAULT)
        .sigPair()
        .size();   // ← raw, uncapped count from attacker-controlled input
```
And for the legacy `bodyBytes` path (lines 147–150):
```java
this.numTxnSignatures =
        transaction.sigMapOrElse(SignatureMap.DEFAULT).sigPair().size();
```

`numTxnSignatures()` (line 172–174) returns this value directly to `calculator.calculateTxFee()`.

**Root cause:** The design assumes the submitted transaction's `SignatureMap` reflects the real signing intent. There is no validation that sigPairs are cryptographically valid, no deduplication, and no upper bound on the count. The fee formula treats each entry as a billable signature.

**Confirmed by test:** `estimateFeesWithSignatures` (test lines 151–158) explicitly shows 0 sigPairs → 1,000,000 tinycents, 2 sigPairs → 2,000,000 tinycents — a linear 2× increase per 2 additional entries.

**Existing checks reviewed:** The `@RequestBody` parameter carries only `@NotNull` — no `@Size` limit. The `highVolumeThrottle` parameter has `@Min(0) @Max(10000)`, but no analogous constraint exists for the body size or sigPair count. `FeeEstimationFeeContext.numTxnSignatures()` (line 268–270) hard-codes `return 0` for the STATE-mode inner context, but `TransactionFeeContext.numTxnSignatures()` — used in both modes — returns the raw attacker-supplied count.

### Impact Explanation
A caller (wallet, SDK, dApp) that queries this endpoint to determine the `maxFee` to embed in a real transaction will receive an estimate that is a multiple of the true on-chain fee proportional to the number of injected fake sigPairs. While Hedera's `maxFee` is a cap (so the network charges the actual fee, not the estimate), the inflated estimate can: (1) cause automated systems to set an unnecessarily high `maxFee`, locking up excess HBAR; (2) cause users or systems to incorrectly conclude a transaction is unaffordable and abort it; (3) be used in phishing or social-engineering attacks to misrepresent network costs. Additionally, submitting a transaction with thousands of sigPairs forces the server to parse and iterate over all of them, creating a secondary CPU/memory amplification vector against the mirror node itself.

### Likelihood Explanation
The endpoint requires no authentication and is publicly reachable. The attack requires only the ability to craft a protobuf `Transaction` with an inflated `SignatureMap` — a trivial operation using any protobuf library. No special privileges, accounts, or on-chain state are needed. The attack is fully repeatable and stateless.

### Recommendation
1. **Cap sigPair count before use:** In `TransactionFeeContext`, clamp `numTxnSignatures` to a protocol-defined maximum (Hedera's current limit is 50 key-pairs per transaction):
   ```java
   this.numTxnSignatures = Math.min(
       signedTransaction.sigMapOrElse(SignatureMap.DEFAULT).sigPair().size(),
       MAX_SIGNATURES   // e.g., 50
   );
   ```
2. **Add a request body size limit:** Annotate the `body` parameter with a `@Size(max = MAX_TX_BYTES)` constraint (Hedera's current limit is 6 144 bytes) or enforce it via a Spring `CommonsRequestLoggingFilter` / Tomcat `maxPostSize`.
3. **Optionally deduplicate sigPairs** by `pubKeyPrefix` before counting, matching the behavior of the consensus node.

### Proof of Concept
```python
import requests
from hedera_sdk_python import ...  # or raw protobuf construction

# Build a SignedTransaction with 1000 fake sigPairs
sig_pairs = [
    SignaturePair(pub_key_prefix=bytes([i % 256]), ed25519=bytes(64))
    for i in range(1000)
]
sig_map = SignatureMap(sig_pair=sig_pairs)
body_bytes = TransactionBody(crypto_transfer=CryptoTransferTransactionBody()).SerializeToString()
signed_tx = SignedTransaction(body_bytes=body_bytes, sig_map=sig_map).SerializeToString()
tx = Transaction(signed_transaction_bytes=signed_tx).SerializeToString()

resp = requests.post(
    "https://<mirror-node>/api/v1/network/fees",
    data=tx,
    headers={"Content-Type": "application/protobuf"}
)
# Returns a fee estimate ~1000× higher than the true 1-signature fee
print(resp.json()["total"])  # e.g., ~500_000_000 instead of ~1_000_000
```

The test `estimateFeesWithSignatures` in `FeeEstimationServiceTest` (lines 151–158) already demonstrates the linear scaling: 2 sigPairs doubles the total from 1,000,000 to 2,000,000 tinycents, confirming the exploit is directly reproducible.