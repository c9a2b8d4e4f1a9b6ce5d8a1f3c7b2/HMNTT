### Title
Unbounded Signature Loop in `ConstructionCombine` Enables CPU-Exhaustion DoS

### Summary
The `ConstructionCombine` endpoint in `rosetta/app/services/construction_service.go` iterates over every entry in `request.Signatures` with no upper-bound check on the slice length. Because the only guard is a "not-empty" check, an unauthenticated attacker can submit a single request containing thousands of copies of one valid `{pubKey, signature}` pair, forcing thousands of expensive `ed25519.Verify` calls and `hiero.TransactionAddSignature` invocations per request, exhausting CPU and blocking the Rosetta server.

### Finding Description
**Exact code path** — `rosetta/app/services/construction_service.go`, function `ConstructionCombine`, lines 58–87:

```
58:  if len(request.Signatures) == 0 {
59:      return nil, errors.ErrNoSignature
60:  }
...
72:  for _, signature := range request.Signatures {
73:      if signature.SignatureType != rTypes.Ed25519 {
74:          return nil, errors.ErrInvalidSignatureType
75:      }
77:      pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
...
82:      if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
83:          return nil, errors.ErrInvalidSignatureVerification
84:      }
86:      _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
87:  }
```

**Root cause** — The only pre-loop guard is `len == 0` (line 58). There is no maximum-count check, no deduplication of `{pubKey, signature}` pairs before the loop, and no HTTP body-size limit anywhere in the server setup.

**Exploit flow:**
1. Attacker generates one valid Ed25519 key pair offline.
2. Attacker obtains a valid `UnsignedTransaction` hex string (freely available from `/construction/payloads` or by constructing a minimal frozen transaction).
3. Attacker calls `getFrozenTransactionBodyBytes` logic locally (or simply signs the known body bytes) to produce one valid `(pubKey, sig)` pair that passes `ed25519.Verify`.
4. Attacker builds a JSON `ConstructionCombineRequest` with `signatures` containing that same valid pair repeated N=10,000+ times.
5. Server reads the body (no `http.MaxBytesReader` is set — confirmed: `rosetta/main.go` lines 220–227 configure only `IdleTimeout`, `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, no body-size cap), then enters the loop and executes 10,000 `ed25519.Verify` + 10,000 `hiero.TransactionAddSignature` calls synchronously in the request goroutine.

**Why existing checks fail:**
- `len(request.Signatures) == 0` (line 58) only rejects empty slices; it does not cap large ones.
- `ed25519.Verify` at line 82 does **not** prevent duplicates — the same valid `(pubKey, sig)` passes every iteration.
- No rate-limiting middleware exists in `rosetta/app/middleware/` (only `metrics.go`, `trace.go`, `health.go`).
- No request body size limit is applied anywhere in `rosetta/main.go` or the middleware chain.
- The `Http` config struct (`rosetta/app/config/types.go` lines 64–69) exposes only timeout fields, no body-size field. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
`ed25519.Verify` is a non-trivial elliptic-curve operation (~50–100 µs per call on modern hardware). A single request with 50,000 duplicate signatures consumes ~2.5–5 seconds of a single CPU core. Concurrent requests from multiple connections can saturate all available cores, making the Rosetta server unresponsive. Because `ConstructionCombine` is an **offline** endpoint (no database access required), it is reachable even in offline mode and has no authentication gate. The resulting DoS prevents legitimate users from constructing and submitting transactions, directly blocking gossip of new transactions to the Hiero network.

### Likelihood Explanation
The endpoint is publicly reachable with zero authentication. The attacker needs only: (a) one valid Ed25519 key pair (trivially generated), and (b) any valid unsigned transaction hex (obtainable from `/construction/payloads` or by replaying a known transaction). The attack is fully repeatable, requires no special privileges, and can be scripted in a few lines. Concurrent flooding from a single host is sufficient to exhaust a typical deployment.

### Recommendation
1. **Add a maximum signature count guard** immediately after the empty check:
   ```go
   const maxSignatures = 20 // tune to expected multi-sig threshold
   if len(request.Signatures) > maxSignatures {
       return nil, errors.ErrTooManySignatures
   }
   ```
2. **Deduplicate signatures by public key** before the loop to prevent repeated processing of the same key.
3. **Apply an HTTP body-size limit** in `rosetta/main.go` using `http.MaxBytesReader` or a middleware wrapper (e.g., 64 KB is more than sufficient for any legitimate combine request).
4. **Add rate limiting** per IP on the `/construction/combine` endpoint. [4](#0-3) 

### Proof of Concept
```python
import json, requests, subprocess

# 1. Generate a valid Ed25519 key pair and sign the frozen body bytes
#    (use any Ed25519 library; here pseudocode)
priv, pub = ed25519_keygen()
unsigned_tx = "<hex from /construction/payloads>"
frozen_body_bytes = get_frozen_body_bytes(unsigned_tx)  # same logic as server
sig = ed25519_sign(priv, frozen_body_bytes)

# 2. Build one valid signature entry
valid_sig = {
    "signing_payload": {
        "account_identifier": {"address": "0.0.100"},
        "hex_bytes": frozen_body_bytes.hex(),
        "signature_type": "ed25519"
    },
    "public_key": {"hex_bytes": pub.hex(), "curve_type": "edwards25519"},
    "signature_type": "ed25519",
    "hex_bytes": sig.hex()
}

# 3. Repeat it 50,000 times
payload = {
    "network_identifier": {"blockchain": "Hiero", "network": "testnet"},
    "unsigned_transaction": unsigned_tx,
    "signatures": [valid_sig] * 50000   # <-- no server-side limit
}

# 4. Send — server will execute 50,000 ed25519.Verify + TransactionAddSignature calls
r = requests.post("http://<rosetta-host>/construction/combine",
                  json=payload, timeout=120)
# Repeat concurrently to exhaust all CPU cores
```

Each concurrent request ties up a goroutine for several seconds of CPU work, with no server-side defence to stop it.

### Citations

**File:** rosetta/app/services/construction_service.go (L54-97)
```go
func (c *constructionAPIService) ConstructionCombine(
	_ context.Context,
	request *rTypes.ConstructionCombineRequest,
) (*rTypes.ConstructionCombineResponse, *rTypes.Error) {
	if len(request.Signatures) == 0 {
		return nil, errors.ErrNoSignature
	}

	transaction, rErr := unmarshallTransactionFromHexString(request.UnsignedTransaction)
	if rErr != nil {
		return nil, rErr
	}

	frozenBodyBytes, rErr := getFrozenTransactionBodyBytes(transaction)
	if rErr != nil {
		return nil, rErr
	}

	for _, signature := range request.Signatures {
		if signature.SignatureType != rTypes.Ed25519 {
			return nil, errors.ErrInvalidSignatureType
		}

		pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
		if err != nil {
			return nil, errors.ErrInvalidPublicKey
		}

		if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
			return nil, errors.ErrInvalidSignatureVerification
		}

		_, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
	}

	transactionBytes, err := hiero.TransactionToBytes(transaction)
	if err != nil {
		return nil, errors.ErrTransactionMarshallingFailed
	}

	return &rTypes.ConstructionCombineResponse{
		SignedTransaction: tools.SafeAddHexPrefix(hex.EncodeToString(transactionBytes)),
	}, nil
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

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```
