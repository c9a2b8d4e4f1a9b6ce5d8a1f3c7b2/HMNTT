### Title
Circuit Breaker DoS via Deterministic HTTP 500 on `/mempool/transaction` Endpoint

### Summary
`MempoolTransaction()` unconditionally returns `errors.ErrNotImplemented`, which the Rosetta SDK serializes as an HTTP 500 response for every request. The Traefik circuit breaker middleware is applied globally across all Rosetta paths and opens when `ResponseCodeRatio(500, 600, 0, 600) > 0.25`. An unprivileged attacker can flood `/mempool/transaction` to push the 5xx ratio above 25%, causing the circuit breaker to open and block all traffic to all Rosetta endpoints for all users.

### Finding Description

**Exact code path:**

`rosetta/app/services/mempool_service.go`, lines 30–34:
```go
func (m *mempoolAPIService) MempoolTransaction(
    _ context.Context,
    _ *types.MempoolTransactionRequest,
) (*types.MempoolTransactionResponse, *types.Error) {
    return nil, errors.ErrNotImplemented
}
``` [1](#0-0) 

`ErrNotImplemented` is defined as:
```go
ErrNotImplemented = newError(NotImplemented, 111, false)
``` [2](#0-1) 

Per the Rosetta API specification and the coinbase/rosetta-sdk-go server implementation, any non-nil `*types.Error` returned from a service handler is serialized as JSON and sent with **HTTP 500**. This means 100% of requests to `/mempool/transaction` produce HTTP 500 responses.

**Circuit breaker configuration** (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–151):
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
``` [3](#0-2) 

This middleware is applied as a **single chain** to the entire Rosetta ingress, covering all paths: `/rosetta/account`, `/rosetta/block`, `/rosetta/call`, `/rosetta/construction`, `/rosetta/events`, `/rosetta/mempool`, `/rosetta/network`, `/rosetta/search`. [4](#0-3) 

The circuit breaker is not scoped per-path. `ResponseCodeRatio(500, 600, 0, 600)` measures the ratio of 5xx responses to all responses across the entire service in a sliding window. If an attacker sends enough requests to `/mempool/transaction` (all returning 500) relative to legitimate traffic, the ratio exceeds 0.25 and the circuit breaker opens, blocking **all** Rosetta paths.

**Why existing checks are insufficient:**

The rate limit is `average: 10` per `requestHost`:
```yaml
- rateLimit:
    average: 10
    sourceCriterion:
      requestHost: true
``` [5](#0-4) 

- `requestHost` is the HTTP `Host` header value, not the source IP. An attacker can use multiple distinct `Host` header values or multiple IPs to multiply their effective request rate.
- Even a single attacker at 10 req/s produces 10 HTTP 500s per second. If legitimate traffic is low (e.g., 30 req/s), the ratio is 10/40 = 25%, right at the threshold. Any slight increase tips it over.

The `inFlightReq` limit of 5 per IP:
```yaml
- inFlightReq:
    amount: 5
    sourceCriterion:
      ipStrategy:
        depth: 1
``` [6](#0-5) 

This limits concurrent requests per IP but does not limit the sustained request rate. With 5 concurrent requests each completing quickly (the handler returns immediately with no I/O), an attacker can sustain a high throughput of 500 responses from a single IP.

The `retry` middleware (3 attempts) is inside the circuit breaker in the chain, so the circuit breaker sees one final 500 per original request — it does not reduce the attacker's ability to accumulate 5xx counts.

### Impact Explanation
When the circuit breaker opens, Traefik returns HTTP 503 to **all** requests to all Rosetta paths — not just `/mempool/transaction`. This means `/rosetta/network`, `/rosetta/block`, `/rosetta/account`, `/rosetta/construction`, and all other endpoints become unavailable to all users. Any application or exchange relying on the Rosetta API for balance queries, block data, or transaction construction is completely denied service for the duration the circuit breaker remains open. The circuit breaker has a recovery period before it re-closes, during which the attacker can re-trigger it with minimal effort.

### Likelihood Explanation
The attack requires no authentication, no special privileges, and no knowledge of the system beyond the public API. The `/mempool/transaction` endpoint is publicly accessible. The attacker needs only an HTTP client capable of sending POST requests. The deterministic 500 response means the attack is 100% reliable — every single request contributes to the 5xx ratio. The rate limit is trivially bypassed by rotating `Host` headers or using multiple IPs. The attack is repeatable indefinitely.

### Recommendation
1. **Scope the circuit breaker per-path or exclude permanently-failing endpoints**: Apply separate circuit breaker middleware instances per ingress path group, or exclude `/rosetta/mempool` from the circuit breaker expression.
2. **Return HTTP 501 instead of HTTP 500 for unimplemented endpoints**: The Rosetta SDK allows customizing the HTTP status code. Returning 501 (Not Implemented) instead of 500 would exclude these responses from the `ResponseCodeRatio(500, 600, 0, 600)` expression, since 501 falls in the 500–600 range — actually this would not help. A better fix is to return a 4xx (e.g., 404 or 405) for unimplemented endpoints so they do not count as server errors.
3. **Rate-limit by source IP, not Host header**: Change `sourceCriterion` in `rateLimit` to use `ipStrategy` instead of `requestHost` to prevent Host-header spoofing.
4. **Add a per-IP rate limit on the circuit-breaker-triggering path**: Apply a stricter per-IP rate limit specifically on `/rosetta/mempool`.

### Proof of Concept
```bash
# Attacker floods /mempool/transaction from multiple Host values
# Each request returns HTTP 500 deterministically

for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<rosetta-host>/rosetta/mempool/transaction \
    -H "Content-Type: application/json" \
    -H "Host: attacker-host-$i.example.com" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"transaction_identifier":{"hash":"0x1234"}}' &
done
wait

# After sufficient requests, all Rosetta endpoints return 503:
curl -X POST https://<rosetta-host>/rosetta/network/list \
  -H "Content-Type: application/json" \
  -d '{"metadata":{}}'
# Expected: HTTP 503 Service Unavailable (circuit breaker open)
```

### Citations

**File:** rosetta/app/services/mempool_service.go (L30-34)
```go
func (m *mempoolAPIService) MempoolTransaction(
	_ context.Context,
	_ *types.MempoolTransactionRequest,
) (*types.MempoolTransactionResponse, *types.Error) {
	return nil, errors.ErrNotImplemented
```

**File:** rosetta/app/errors/errors.go (L70-70)
```go
	ErrNotImplemented                    = newError(NotImplemented, 111, false)
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L119-133)
```yaml
ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rosetta.namespace" . }}-{{ include "hedera-mirror-rosetta.fullname" . }}@kubernetescrd'
  enabled: true
  hosts:
    - host: ""
      paths:
        - "/rosetta/account"
        - "/rosetta/block"
        - "/rosetta/call"
        - "/rosetta/construction"
        - "/rosetta/events"
        - "/rosetta/mempool"
        - "/rosetta/network"
        - "/rosetta/search"
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-151)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L152-156)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```
