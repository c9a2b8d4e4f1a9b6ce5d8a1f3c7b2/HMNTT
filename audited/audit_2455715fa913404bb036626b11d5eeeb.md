### Title
Unconditional `ErrNotImplemented` in `Mempool()` Enables Unauthenticated Circuit-Breaker Trip via HTTP 500 Flood

### Summary
The `Mempool()` handler in `rosetta/app/services/mempool_service.go` unconditionally returns `errors.ErrNotImplemented`, which the Coinbase Rosetta SDK server maps to an HTTP 500 response for every request. The Traefik ingress middleware for the Rosetta service applies a shared circuit breaker (`ResponseCodeRatio(500, 600, 0, 600) > 0.25`) across all Rosetta routes. An unprivileged attacker can flood `/rosetta/mempool` at the permitted rate, push the 5xx ratio above 25%, trip the circuit breaker, and deny service to all Rosetta endpoints — including `/rosetta/call` and `/rosetta/construction` used for smart-contract interactions.

### Finding Description

**Code path:**

`rosetta/app/services/mempool_service.go` lines 22–27 — `Mempool()` always returns `nil, errors.ErrNotImplemented`.

`rosetta/app/errors/errors.go` line 70 — `ErrNotImplemented = newError(NotImplemented, 111, false)` creates a `*types.Error` with Rosetta error code 111.

The Coinbase `rosetta-sdk-go` server package (used at `rosetta/main.go` lines 89–90 via `server.NewMempoolAPIController`) writes **HTTP 500** for every non-nil `*types.Error` returned by a handler — this is mandated by the Rosetta specification and is the SDK's fixed behavior.

`charts/hedera-mirror-rosetta/values.yaml` lines 149–166 — the Traefik middleware chain applied to the Rosetta ingress is:
```
circuitBreaker: expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
inFlightReq:    amount: 5  (per source IP, depth: 1)
rateLimit:      average: 10 (per requestHost)
retry:          attempts: 3
```

The circuit breaker is **shared across all Rosetta routes** (`/rosetta/account`, `/rosetta/block`, `/rosetta/call`, `/rosetta/construction`, `/rosetta/events`, `/rosetta/mempool`, `/rosetta/network`, `/rosetta/search`). Traefik's `ResponseCodeRatio(500, 600, 0, 600)` measures 5xx responses against the total response window. Because `/mempool` returns HTTP 500 on 100% of requests, every attacker-controlled `/mempool` request increments the 5xx numerator.

**Failed assumption:** The designers assumed the rate limiter (`average: 10` per `requestHost`) would prevent enough volume to trip the circuit breaker. However:
1. The rate limit is keyed on the HTTP `Host` header value, not the source IP. An attacker can rotate `Host` header values (while still matching the ingress hostname pattern) or simply operate from multiple IPs to multiply their effective rate.
2. Even at the nominal 10 req/s, if legitimate Rosetta traffic is below ~30 req/s, the attacker's 10 req/s of pure 500s pushes the ratio above 25% within the Traefik circuit-breaker observation window (default 10 s).
3. The `retry: attempts: 3` middleware, if it fires on 5xx (configurable), would triple the 500 count per original request.

### Impact Explanation
When the circuit breaker trips, Traefik returns HTTP 503 to **all** requests on the Rosetta service — including `/rosetta/call` (smart-contract read calls) and `/rosetta/construction` (transaction construction/submission for smart contracts). This is a complete denial-of-service for all Rosetta-mediated smart-contract operations. The outage persists for the circuit-breaker recovery window (Traefik default: 10 s recovering, then half-open), but the attacker can re-trip it immediately upon recovery with another burst, sustaining the outage indefinitely. No funds are directly at risk, but liveness of the smart-contract API layer is fully compromised.

### Likelihood Explanation
No authentication, API key, or privileged access is required. The `/mempool` endpoint is publicly reachable via the ingress (`/rosetta/mempool` is explicitly listed in the ingress paths). The attack requires only an HTTP client capable of sending POST requests at 10 req/s — trivially achievable from a single machine or a small botnet. The condition is deterministic: every `/mempool` request returns 500, so the attacker has a 100% reliable signal. The attack is repeatable and can be automated to sustain the circuit-breaker open state indefinitely.

### Recommendation
1. **Return HTTP 200 with an empty mempool** instead of an error. The Rosetta spec allows returning an empty `MempoolResponse` (`{"transaction_identifiers": []}`), which is semantically correct for a network with no mempool concept and produces HTTP 200, contributing zero 5xx counts to the circuit breaker.
2. **Alternatively, exclude `/rosetta/mempool` from the circuit-breaker middleware** by splitting it into a separate Traefik router with no circuit breaker, or by using a `PathPrefix` matcher that excludes the mempool path from the shared middleware chain.
3. **Tighten the rate limit** to be keyed on source IP (`ipStrategy`) rather than `requestHost`, and lower the `average` to a value that prevents reaching the 25% threshold even under sustained attack.
4. **Separate the circuit-breaker scope** so that errors on stub/unimplemented endpoints cannot affect the circuit-breaker state for functional endpoints.

### Proof of Concept
```bash
# Precondition: Rosetta ingress is reachable at $HOST
# Legitimate traffic is low (< 30 req/s)

# Step 1: Confirm /mempool always returns HTTP 500
curl -s -o /dev/null -w "%{http_code}" -X POST https://$HOST/rosetta/mempool \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
# Expected: 500

# Step 2: Flood /mempool at 10 req/s to trip the circuit breaker
for i in $(seq 1 200); do
  curl -s -o /dev/null -X POST https://$HOST/rosetta/mempool \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
  sleep 0.1
done

# Step 3: Observe circuit breaker tripped — all Rosetta routes now return 503
curl -s -o /dev/null -w "%{http_code}" -X POST https://$HOST/rosetta/network/list \
  -H "Content-Type: application/json" \
  -d '{}'
# Expected: 503 (circuit breaker open)

curl -s -o /dev/null -w "%{http_code}" -X POST https://$HOST/rosetta/call \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},...}'
# Expected: 503 (smart-contract call blocked)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rosetta/app/services/mempool_service.go (L22-27)
```go
func (m *mempoolAPIService) Mempool(
	_ context.Context,
	_ *types.NetworkRequest,
) (*types.MempoolResponse, *types.Error) {
	return nil, errors.ErrNotImplemented
}
```

**File:** rosetta/app/errors/errors.go (L70-70)
```go
	ErrNotImplemented                    = newError(NotImplemented, 111, false)
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

**File:** rosetta/main.go (L89-90)
```go
	mempoolAPIService := services.NewMempoolAPIService()
	mempoolAPIController := server.NewMempoolAPIController(mempoolAPIService, asserter)
```
