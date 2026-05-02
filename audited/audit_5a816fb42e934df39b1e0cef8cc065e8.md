### Title
Unauthenticated CPU Exhaustion via Crafted Hex Payload at `/construction/submit`

### Summary
The `/construction/submit` endpoint accepts any hex-encoded payload from unauthenticated callers and unconditionally invokes `hiero.TransactionFromBytes()` (protobuf parsing) on the decoded bytes before any validation rejects the request. There is no application-level request body size limit and the Traefik rate-limiting middleware is disabled by default (`global.middleware: false`), allowing an unprivileged attacker to exhaust CPU by flooding the endpoint with large, valid-hex but invalid-protobuf payloads.

### Finding Description

**Exact code path:**

`ConstructionSubmit` (line 340) calls `unmarshallTransactionFromHexString(request.SignedTransaction)`:

```
rosetta/app/services/construction_service.go:658-674
func unmarshallTransactionFromHexString(transactionString string) (hiero.TransactionInterface, *rTypes.Error) {
    transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
    if err != nil {
        return nil, errors.ErrTransactionDecodeFailed   // ← attacker avoids this
    }
    transaction, err := hiero.TransactionFromBytes(transactionBytes)  // ← protobuf parse
    if err != nil {
        return nil, errors.ErrTransactionUnmarshallingFailed           // ← lands here
    }
    ...
}
```

**Root cause:** `hiero.TransactionFromBytes()` performs full protobuf deserialization on attacker-supplied bytes. There is no maximum body size enforced before this call. The `http.Server` in `main.go` (lines 220–227) sets only timeout values (`ReadTimeout`, `WriteTimeout`, etc.) — no `http.MaxBytesReader` or equivalent is applied to the request body. The rosetta-sdk-go `server.NewRouter` also imposes no body size cap.

**Why existing checks fail:**

The Traefik middleware stack (`inFlightReq: 5`, `rateLimit: average 10`) is defined in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166, but is gated behind `global.middleware: false` (line 95) — **disabled by default**. Even when enabled, the rate limit uses `sourceCriterion: requestHost` (line 160), which is trivially bypassed by rotating the `Host` header or connecting directly to the pod. The `inFlightReq` limit uses `ipStrategy.depth: 1` (lines 154–156) but only applies when the middleware chain is active.

### Impact Explanation
An attacker can send arbitrarily large hex strings (e.g., several megabytes of valid hex encoding random bytes). Each request causes: (1) full hex decode of the payload, (2) a full protobuf parse attempt by `hiero.TransactionFromBytes()`. At high concurrency with large payloads, this saturates CPU cores on the Rosetta pod. Because the HPA scales on CPU utilization ≥ 80% (values.yaml lines 103–109), sustained attack also drives up cloud infrastructure costs. The endpoint is publicly reachable with no authentication.

### Likelihood Explanation
No privileges, accounts, or prior knowledge are required. The attack requires only HTTP POST access to `/construction/submit` with a JSON body containing a `signed_transaction` field set to any long even-length hex string. This is trivially scriptable with `curl` or any HTTP load tool. Default deployments are unprotected because `global.middleware` defaults to `false`.

### Recommendation
1. **Enforce a request body size limit at the application layer** — wrap the HTTP handler with `http.MaxBytesReader` (e.g., 64 KB) before the rosetta router in `main.go`.
2. **Enable the Traefik middleware by default** — change `global.middleware` default to `true` in `values.yaml`, and switch `rateLimit.sourceCriterion` from `requestHost` to `ipStrategy` to prevent host-header bypass.
3. **Add an explicit hex-decoded byte length check** in `unmarshallTransactionFromHexString` before calling `hiero.TransactionFromBytes()`, rejecting payloads above a reasonable maximum (e.g., 10 KB for a Hiero transaction).

### Proof of Concept

```bash
# Generate a 1 MB valid-hex but invalid-protobuf payload
python3 -c "import os; print('0x' + os.urandom(512*1024).hex())" > payload.txt
PAYLOAD=$(cat payload.txt)

# Flood the endpoint (no authentication required)
for i in $(seq 1 500); do
  curl -s -X POST http://<rosetta-host>/construction/submit \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},\"signed_transaction\":\"$PAYLOAD\"}" &
done
wait
# Expected: ErrTransactionUnmarshallingFailed returned after CPU-intensive protobuf parse
# Observed: CPU saturation on the Rosetta pod
```

Each request passes `hex.DecodeString` (valid hex) and then triggers `hiero.TransactionFromBytes()` on 512 KB of random bytes, returning `ErrTransactionUnmarshallingFailed` only after the parse attempt completes.