### Title
Unbounded Memory Allocation via Oversized Hex Transaction in `unmarshallTransactionFromHexString()`

### Summary
The `unmarshallTransactionFromHexString()` function in `rosetta/app/services/construction_service.go` performs no size validation on the attacker-controlled hex string before calling `hex.DecodeString()` and `hiero.TransactionFromBytes()`. Any unauthenticated user can POST an arbitrarily large hex-encoded payload to four public endpoints, causing the server to allocate unbounded memory proportional to the input, exhausting process memory and crashing the Rosetta service.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, lines 658–674:

```go
func unmarshallTransactionFromHexString(transactionString string) (hiero.TransactionInterface, *rTypes.Error) {
    transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
    // ← no len(transactionString) check here
    if err != nil {
        return nil, errors.ErrTransactionDecodeFailed
    }
    transaction, err := hiero.TransactionFromBytes(transactionBytes)
    // ← protobuf parse of attacker-controlled byte slice
    ...
}
```

This function is called unconditionally from four public endpoints:
- `ConstructionCombine` (line 62) — `/construction/combine`
- `ConstructionHash` (line 121) — `/construction/hash`
- `ConstructionParse` (line 187) — `/construction/parse`
- `ConstructionSubmit` (line 340) — `/construction/submit`

**Root cause:** There is no call to `http.MaxBytesReader` anywhere in the Rosetta Go codebase (confirmed by grep), and no length check on `transactionString` before decoding. The only server-level constraint is `ReadTimeout` (default 5 seconds, `rosetta/main.go` lines 220–226). This is a time limit, not a byte limit. On a 1 Gbps link, an attacker can deliver ~625 MB within that window. Each request causes:
1. `hex.DecodeString` — allocates `len(input)/2` bytes on the heap.
2. `hiero.TransactionFromBytes` — protobuf unmarshalling allocates additional heap objects proportional to the byte slice.

With concurrent requests, memory exhaustion is additive. Go's runtime will OOM-panic individual goroutines, but the OS OOM-killer will terminate the process when system memory is exhausted, crashing the service entirely.

**Why existing checks fail:**
- `ReadTimeout` (5 s) is a time-based limit, not a byte-based limit; high-bandwidth attackers trivially saturate it.
- The Rosetta SDK's `server.NewRouter` uses a plain `json.NewDecoder(r.Body).Decode(...)` with no `MaxBytesReader` wrapping.
- No authentication or rate-limiting is applied to these endpoints.

### Impact Explanation
A successful attack crashes the Rosetta mirror-node process, making `/construction/submit` unavailable and preventing all new transaction submissions through the Rosetta API. This maps directly to the stated critical scope: "Network not being able to confirm new transactions (total network shutdown)" for any operator relying on this Rosetta endpoint. Recovery requires a process restart; the attack is repeatable immediately after restart.

### Likelihood Explanation
The endpoints are unauthenticated and publicly reachable (default port 5700). No special knowledge, credentials, or on-chain state is required. The attacker only needs a high-bandwidth connection or the ability to open many concurrent TCP connections. The attack is fully scriptable and repeatable. Commodity cloud VMs with 1–10 Gbps egress make this trivially feasible.

### Recommendation
1. **Enforce a request body size limit** at the HTTP layer before any decoding occurs. In `rosetta/main.go`, wrap the handler with `http.MaxBytesReader` in a middleware, e.g.:
   ```go
   const maxRequestBodyBytes = 1 << 20 // 1 MB
   func limitBody(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
           next.ServeHTTP(w, r)
       })
   }
   ```
   Apply this before `MetricsMiddleware` in the middleware chain.

2. **Add an explicit length check** inside `unmarshallTransactionFromHexString()` as a defense-in-depth measure:
   ```go
   const maxTransactionHexLen = 2 * 1024 * 1024 // 1 MB decoded
   if len(transactionString) > maxTransactionHexLen {
       return nil, errors.ErrTransactionDecodeFailed
   }
   ```

3. **Add rate limiting** per IP on construction endpoints.

### Proof of Concept
```bash
# Generate a 50 MB hex string of valid-looking bytes (all zeros)
python3 -c "print('0x' + '00' * 50_000_000)" > /tmp/big_hex.txt
BIG_HEX=$(cat /tmp/big_hex.txt)

# Send to /construction/hash (no auth required)
curl -s -X POST http://<rosetta-host>:5700/construction/hash \
  -H 'Content-Type: application/json' \
  -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},\"signed_transaction\":\"$BIG_HEX\"}"

# Repeat with 20+ concurrent connections:
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/construction/hash \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},\"signed_transaction\":\"$BIG_HEX\"}" &
done
wait
# Expected result: process OOM-killed; service unavailable
```