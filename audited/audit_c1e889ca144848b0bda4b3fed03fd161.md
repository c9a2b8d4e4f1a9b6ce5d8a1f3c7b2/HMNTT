### Title
Nil Pointer Dereference DoS via Missing `AccountIdentifier` Validation in `AllAccountBalances()`

### Summary
`AllAccountBalances()` blindly copies `request.AccountIdentifier` (which may be `nil` when omitted from the JSON body) into `singleAccountBalanceRequest` and passes it to `AccountBalance()`. `AccountBalance()` immediately dereferences `request.AccountIdentifier.Address` at line 45 without any nil guard, causing a panic. Any unauthenticated external caller can trigger this repeatedly, causing every such request to panic and return HTTP 500, effectively denying service on the `/account/balances` endpoint.

### Finding Description

**Exact code path:**

In `AllAccountBalances()` (lines 88–99), `request.AccountIdentifier` is copied verbatim with no nil check:

```go
singleAccountBalanceRequest := rTypes.AccountBalanceRequest{
    NetworkIdentifier: request.NetworkIdentifier,
    AccountIdentifier: request.AccountIdentifier,   // line 95 — nil propagated here
    BlockIdentifier:   request.BlockIdentifier,
    Currencies:        request.Currencies,
}
response, err := a.AccountBalance(ctx, &singleAccountBalanceRequest)
```

`AccountBalance()` then immediately dereferences the pointer at line 45:

```go
accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, ...)
//                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^
//                                              nil dereference if AccountIdentifier is nil
```

**Root cause:** The Rosetta spec defines `account_identifier` as **optional** in `AllAccountBalancesRequest`. When a client omits it from the JSON body, Go's JSON decoder leaves `AccountIdentifier` as `nil`. The Rosetta SDK asserter validates `AccountIdentifier` for `/account/balance` requests but does **not** enforce it as required for `/account/balances` (`AllAccountBalancesRequest`). No nil guard exists in either `AllAccountBalances()` or `AccountBalance()` for this field.

**Why existing checks fail:** The only input validation in `AccountBalance()` is the `err` check after `NewAccountIdFromString()` (line 46–48), but execution never reaches that line — the nil dereference at line 45 panics first. Go's `net/http` server recovers the panic per goroutine and returns HTTP 500, so the process stays up, but every such request panics and the endpoint is rendered non-functional for callers omitting `account_identifier`.

### Impact Explanation
Any unauthenticated caller can send a POST to `/account/balances` with a body omitting `account_identifier` (e.g., `{"network_identifier": {...}}`). Each such request causes a nil pointer dereference panic in the handler goroutine. While Go's `net/http` recovers the panic (preventing full process termination), the endpoint returns HTTP 500 for every such request. Legitimate balance checks — which are a prerequisite for fund transfers in Rosetta-based workflows — are denied. Severity: **High DoS** on a critical financial data endpoint.

### Likelihood Explanation
No authentication or rate limiting is required. The Rosetta API is a public HTTP interface. The trigger is a single malformed POST with a valid `network_identifier` but absent `account_identifier`. This is trivially repeatable, automatable, and requires zero privileges. Any attacker aware of the Rosetta spec (which is public) knows `account_identifier` is optional in `AllAccountBalancesRequest` and can craft this payload immediately.

### Recommendation
Add an explicit nil check for `request.AccountIdentifier` at the top of `AllAccountBalances()` before constructing `singleAccountBalanceRequest`:

```go
func (a *AccountAPIService) AllAccountBalances(
    ctx context.Context,
    request *rTypes.AllAccountBalancesRequest,
) (*rTypes.AllAccountBalancesResponse, *rTypes.Error) {
    if request.AccountIdentifier == nil {
        return nil, errors.ErrInvalidAccount
    }
    // ... rest of function
}
```

Alternatively, add the same guard at the top of `AccountBalance()` so all callers are protected:

```go
if request.AccountIdentifier == nil {
    return nil, errors.ErrInvalidAccount
}
```

### Proof of Concept

```bash
# Trigger nil pointer dereference panic on /account/balances
curl -X POST http://<rosetta-host>/account/balances \
  -H "Content-Type: application/json" \
  -d '{
    "network_identifier": {
      "blockchain": "Hedera",
      "network": "testnet"
    }
  }'
# Expected: HTTP 500 (panic recovered by net/http)
# Server logs will show: "runtime error: invalid memory address or nil pointer dereference"
# Repeat indefinitely to sustain DoS on the balance-check endpoint
``` [1](#0-0) [2](#0-1)

### Citations

**File:** rosetta/app/services/account_service.go (L44-48)
```go
) (*rTypes.AccountBalanceResponse, *rTypes.Error) {
	accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
	if err != nil {
		return nil, errors.ErrInvalidAccount
	}
```

**File:** rosetta/app/services/account_service.go (L88-99)
```go
func (a *AccountAPIService) AllAccountBalances(
	ctx context.Context,
	request *rTypes.AllAccountBalancesRequest,
) (*rTypes.AllAccountBalancesResponse, *rTypes.Error) {
	// There's no subaccounts, so always delegate to AccountBalance
	singleAccountBalanceRequest := rTypes.AccountBalanceRequest{
		NetworkIdentifier: request.NetworkIdentifier,
		AccountIdentifier: request.AccountIdentifier,
		BlockIdentifier:   request.BlockIdentifier,
		Currencies:        request.Currencies,
	}
	response, err := a.AccountBalance(ctx, &singleAccountBalanceRequest)
```
