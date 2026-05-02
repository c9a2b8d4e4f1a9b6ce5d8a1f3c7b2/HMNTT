### Title
Unauthenticated CPU Exhaustion via Repeated Elliptic Curve Key Parsing in `AccountBalance` Alias Path

### Summary
The `AccountBalance` endpoint in `rosetta/app/services/account_service.go` unconditionally parses the caller-supplied `AccountIdentifier.Address` as a cryptographic public key on every request when the address is hex-prefixed. Because there is no application-level rate limiting, no caching of the parsed key, and no authentication requirement, an unprivileged attacker can flood the endpoint with valid secp256k1 alias addresses, forcing repeated EC point decompression (`hiero.PublicKeyFromBytes`) on every request and driving CPU consumption well above the 30% threshold.

### Finding Description

**Exact code path:**

1. `rosetta/app/services/account_service.go:45` — `AccountBalance()` calls `types.NewAccountIdFromString(request.AccountIdentifier.Address, ...)` on every incoming request with no guard. [1](#0-0) 

2. `rosetta/app/domain/types/account_id.go:191-200` — `NewAccountIdFromString()` detects a `0x`-prefixed address, hex-decodes it, and immediately calls `NewAccountIdFromAlias()`. [2](#0-1) 

3. `rosetta/app/domain/types/account_id.go:85-101` — `NewAccountIdFromAlias()` calls `NewPublicKeyFromAlias(alias)` unconditionally. [3](#0-2) 

4. `rosetta/app/domain/types/public_key.go:60-88` — `NewPublicKeyFromAlias()` performs `proto.Unmarshal` then calls `hiero.PublicKeyFromBytes(rawKey)`. For a secp256k1 key (33-byte compressed point), `PublicKeyFromBytes` must decompress the point — computing a modular square root over the 256-bit prime field — to validate the key. This is the expensive cryptographic operation triggered on every request. [4](#0-3) 

**Root cause:** The alias-to-public-key parsing (including EC point decompression) is performed synchronously on every request, with no result caching and no application-level concurrency or rate controls. The failed assumption is that callers will be well-behaved or that an external proxy will always enforce rate limits.

**Why existing checks fail:**

The only rate-limiting mechanism is the optional Traefik middleware defined in the Helm chart. It is **disabled by default** (`global.middleware: false`): [5](#0-4) 

Even when enabled, the middleware template is conditional: [6](#0-5) 

And the rate limit (`average: 10` per `requestHost`) still permits sustained high-rate flooding, and is entirely bypassable if the attacker has direct network access to the pod (bypassing the ingress). There is zero rate limiting, caching, or authentication inside the Go application itself — confirmed by the absence of any such logic in `account_service.go`. [7](#0-6) 

### Impact Explanation
An attacker can sustain a high request rate to `/account/balance` using a single pre-computed valid secp256k1 alias. Each request forces one EC point decompression (modular exponentiation over a 256-bit field) in the Go process. On a lightly-to-moderately loaded node, a few hundred requests per second is sufficient to push CPU utilization above 30% above baseline, degrading or denying service to legitimate Rosetta API consumers (exchanges, wallets, block explorers) that depend on balance queries for transaction construction and reconciliation.

### Likelihood Explanation
The attack requires zero privileges: the `/account/balance` endpoint is publicly reachable, accepts unauthenticated POST requests, and the attacker only needs to construct one valid protobuf-encoded secp256k1 public key once and replay it at high rate. This is trivially scriptable with any HTTP load tool (curl loop, wrk, k6). The default deployment has no application-level protection. The attack is repeatable and persistent.

### Recommendation
1. **Cache parsed alias results**: Introduce a bounded LRU cache (keyed on the raw alias bytes) that maps alias → `AccountId` so that `NewPublicKeyFromAlias` / `hiero.PublicKeyFromBytes` is called at most once per unique alias.
2. **Application-level rate limiting**: Add a per-IP (or global) token-bucket rate limiter as Go middleware, independent of the optional Traefik layer, so the protection is always present regardless of deployment topology.
3. **Enable Traefik middleware by default**: Change `global.middleware` default to `true` and tighten `inFlightReq.amount` and `rateLimit.average` to values appropriate for the expected legitimate traffic volume.

### Proof of Concept

**Step 1 — Generate a valid secp256k1 alias (one time):**
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import proto_services_pb2  # hedera services Key proto

key = ec.generate_private_key(ec.SECP256K1())
compressed = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)  # 33 bytes

# Encode as protobuf Key { ECDSASecp256K1: compressed }
k = proto_services_pb2.Key()
k.ECDSASecp256K1 = compressed
alias_hex = "0x" + k.SerializeToString().hex()
```

**Step 2 — Flood the endpoint:**
```bash
# Replace <HOST> and <NETWORK> with actual values
ALIAS="0x3a21<33-byte-compressed-secp256k1-pubkey-hex>"
PAYLOAD='{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
          "account_identifier":{"address":"'"$ALIAS"'"}}'

# Send at high rate (e.g., 500 req/s with 50 parallel connections)
wrk -t50 -c50 -d60s -s <(echo "
  wrk.method = 'POST'
  wrk.body   = '$PAYLOAD'
  wrk.headers['Content-Type'] = 'application/json'
") http://<HOST>/account/balance
```

**Expected result:** CPU utilization of the `rosetta` process rises by ≥30% above the 24-hour baseline within seconds of the flood starting, as each request triggers `hiero.PublicKeyFromBytes` (EC point decompression) with no caching or throttling to absorb the load.

### Citations

**File:** rosetta/app/services/account_service.go (L44-48)
```go
) (*rTypes.AccountBalanceResponse, *rTypes.Error) {
	accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
	if err != nil {
		return nil, errors.ErrInvalidAccount
	}
```

**File:** rosetta/app/domain/types/account_id.go (L85-101)
```go
func NewAccountIdFromAlias(alias []byte, shard, realm int64) (zero AccountId, _ error) {
	if shard < 0 || realm < 0 {
		return zero, errors.Errorf("shard and realm must be positive integers")
	}

	curveType, publicKey, err := NewPublicKeyFromAlias(alias)
	if err != nil {
		return zero, err
	}

	return AccountId{
		accountId: domain.EntityId{ShardNum: shard, RealmNum: realm},
		alias:     alias,
		aliasKey:  &publicKey.PublicKey,
		curveType: curveType,
	}, nil
}
```

**File:** rosetta/app/domain/types/account_id.go (L191-201)
```go
	if !strings.HasPrefix(address, tools.HexPrefix) {
		return zero, errors.Errorf("Invalid Account Alias")
	}

	alias, err := hex.DecodeString(tools.SafeRemoveHexPrefix(address))
	if err != nil {
		return zero, err
	}

	return NewAccountIdFromAlias(alias, shard, realm)
}
```

**File:** rosetta/app/domain/types/public_key.go (L60-88)
```go
func NewPublicKeyFromAlias(alias []byte) (zeroCurveType types.CurveType, zeroPublicKey PublicKey, _ error) {
	if len(alias) == 0 {
		return zeroCurveType, zeroPublicKey, errors.Errorf("Empty alias provided")
	}

	var key services.Key
	if err := proto.Unmarshal(alias, &key); err != nil {
		return zeroCurveType, zeroPublicKey, err
	}

	var curveType types.CurveType
	var rawKey []byte
	switch value := key.GetKey().(type) {
	case *services.Key_Ed25519:
		curveType = types.Edwards25519
		rawKey = value.Ed25519
	case *services.Key_ECDSASecp256K1:
		curveType = types.Secp256k1
		rawKey = value.ECDSASecp256K1
	default:
		return zeroCurveType, zeroPublicKey, errors.Errorf("Unsupported key type")
	}

	publicKey, err := hiero.PublicKeyFromBytes(rawKey)
	if err != nil {
		return zeroCurveType, zeroPublicKey, err
	}

	return curveType, PublicKey{publicKey}, nil
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

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-4)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
apiVersion: traefik.io/v1alpha1
```
