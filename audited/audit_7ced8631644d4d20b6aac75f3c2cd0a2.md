### Title
Nil Pointer Dereference in `AccountBalance()` via `AllAccountBalances()` with Missing `AccountIdentifier`

### Summary
`AllAccountBalances()` passes `request.AccountIdentifier` directly to `AccountBalance()` without a nil guard. `AccountBalance()` unconditionally dereferences `request.AccountIdentifier.Address` at line 45, causing a nil pointer dereference panic when `AccountIdentifier` is omitted. The Rosetta SDK asserter permits a nil `AccountIdentifier` in `AllAccountBalancesRequest` (it is optional per the Rosetta spec), so no upstream validation blocks this path.

### Finding Description

**Code path:**

`AllAccountBalances()` (lines 88–113) copies the incoming request fields verbatim into a new `AccountBalanceRequest`:

```go
singleAccountBalanceRequest := rTypes.AccountBalanceRequest{
    NetworkIdentifier: request.NetworkIdentifier,
    AccountIdentifier: request.AccountIdentifier,   // nil propagates here
    ...
}
response, err := a.AccountBalance(ctx, &singleAccountBalanceRequest)
``` [1](#0-0) 

`AccountBalance()` then immediately dereferences `AccountIdentifier` without any nil check:

```go
accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, ...)
``` [2](#0-1) 

**Root cause:** The code assumes `AccountIdentifier` is always non-nil, which holds for direct `/account/balance` calls (where the Rosetta SDK asserter enforces it as required), but not for the `/account/balance/all` path where `AccountIdentifier` is optional per the Rosetta API specification.

**Why existing checks fail:** The `rosettaAsserter.NewServer(...)` asserter registered in `main.go` validates `AccountBalanceRequest.AccountIdentifier` as required for the `/account/balance` endpoint, but `AllAccountBalancesRequest.AccountIdentifier` is defined as optional in the Rosetta spec. The asserter therefore allows a nil `AccountIdentifier` through to `AllAccountBalances()`. There is no nil guard anywhere in `AllAccountBalances()` before the delegated call, and no nil guard at the top of `AccountBalance()`. [3](#0-2) 

The test suite never exercises a nil `AccountIdentifier` for `AllAccountBalances`; all test helpers always supply a non-nil `AccountIdentifier`. [4](#0-3) 

### Impact Explanation
When triggered, the handler goroutine panics. Go's `net/http` server recovers per-handler panics, so the process itself does not exit, but the client receives a connection reset or 500 response. An attacker can repeat this indefinitely, causing continuous panic log entries, potential log-storage exhaustion, and degraded observability. On nodes where log-based alerting or rate-limiting is absent, this constitutes a reliable, low-cost availability degradation vector.

### Likelihood Explanation
The `/account/balance/all` endpoint is unauthenticated and publicly reachable. No credentials, tokens, or prior knowledge are required. The payload is a single well-formed JSON object with `account_identifier` omitted or set to `null`. Any external user can craft and replay this request in a tight loop with standard HTTP tooling.

### Recommendation
Add an explicit nil check at the top of `AccountBalance()` (or at the entry of `AllAccountBalances()` before delegation):

```go
if request.AccountIdentifier == nil {
    return nil, errors.ErrInvalidAccount
}
```

This mirrors the existing pattern used for `BlockIdentifier` (line 52) and ensures the function is safe regardless of which code path invokes it. [5](#0-4) 

### Proof of Concept

```bash
curl -s -X POST http://<rosetta-node>:<port>/account/balance/all \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {
      "blockchain": "Hedera",
      "network": "testnet"
    }
  }'
```

**Preconditions:** None. No authentication required.  
**Trigger:** `account_identifier` is absent (nil after JSON decode).  
**Result:** `AllAccountBalances()` passes nil `AccountIdentifier` to `AccountBalance()`, which panics at line 45 (`request.AccountIdentifier.Address`). The server logs a panic stack trace and returns a 500/connection-reset to the caller. Repeating the request reproduces the panic on every invocation.

### Citations

**File:** rosetta/app/services/account_service.go (L41-48)
```go
func (a *AccountAPIService) AccountBalance(
	ctx context.Context,
	request *rTypes.AccountBalanceRequest,
) (*rTypes.AccountBalanceResponse, *rTypes.Error) {
	accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
	if err != nil {
		return nil, errors.ErrInvalidAccount
	}
```

**File:** rosetta/app/services/account_service.go (L93-99)
```go
	singleAccountBalanceRequest := rTypes.AccountBalanceRequest{
		NetworkIdentifier: request.NetworkIdentifier,
		AccountIdentifier: request.AccountIdentifier,
		BlockIdentifier:   request.BlockIdentifier,
		Currencies:        request.Currencies,
	}
	response, err := a.AccountBalance(ctx, &singleAccountBalanceRequest)
```

**File:** rosetta/main.go (L185-195)
```go
	asserter, err := rosettaAsserter.NewServer(
		types.SupportedOperationTypes,
		true,
		[]*rTypes.NetworkIdentifier{network},
		nil,
		false,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}
```

**File:** rosetta/app/services/account_service_test.go (L45-52)
```go
func getAllAccountBalancesRequest(request *rTypes.AccountBalanceRequest) *rTypes.AllAccountBalancesRequest {
	return &rTypes.AllAccountBalancesRequest{
		NetworkIdentifier: request.NetworkIdentifier,
		AccountIdentifier: request.AccountIdentifier,
		BlockIdentifier:   request.BlockIdentifier,
		Currencies:        request.Currencies,
	}
}
```
