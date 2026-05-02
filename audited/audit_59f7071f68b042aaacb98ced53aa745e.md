### Title
Unbounded Request Body Allows Memory/CPU Exhaustion via `/construction/parse` Endpoint

### Summary
The `/construction/parse` endpoint in the Rosetta API accepts an arbitrarily large hex-encoded transaction string with no application-level body size limit. An unauthenticated attacker can send a maximally large valid hex string, causing `hex.DecodeString` to allocate a proportionally large byte slice and `hiero.TransactionFromBytes` to attempt protobuf parsing of the full payload, exhausting server memory and CPU before returning `ErrTransactionUnmarshallingFailed`. No authentication or privilege is required.

### Finding Description

**Exact code path:**

`ConstructionParse` at [1](#0-0)  calls `unmarshallTransactionFromHexString` with the raw `request.Transaction` string, which has no prior size check.

`unmarshallTransactionFromHexString` at [2](#0-1)  performs two unbounded operations in sequence:
1. `hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))` — allocates a `[]byte` of `len(input)/2` bytes with no size guard.
2. `hiero.TransactionFromBytes(transactionBytes)` — performs full protobuf deserialization of the resulting byte slice.

**Root cause:** There is no `http.MaxBytesReader` or equivalent body-size cap anywhere in the Rosetta server stack. The grep for `MaxBytesReader`, `LimitReader`, `maxBodySize`, and `BodyLimit` across all `rosetta/**/*.go` files returns zero matches. [3](#0-2) 

**Why existing checks fail:**

1. **`ReadTimeout: 5s`** — limits how long the server spends *reading* the body, not how large the body can be. On a co-located or high-bandwidth connection (1 Gbps = ~625 MB in 5 s), an attacker can deliver hundreds of megabytes within the timeout window. After the body is fully read, the `hex.DecodeString` + `hiero.TransactionFromBytes` CPU/memory work proceeds with no further timeout. [4](#0-3) 

2. **Traefik middleware (rate limit / inFlightReq)** — the `rateLimit: average: 10` and `inFlightReq: amount: 5` controls are defined in the Helm chart but are gated behind `global.middleware: false` by default. [5](#0-4)  They are only activated in the production overlay. [6](#0-5)  Any deployment not using that overlay has no rate limiting at all.

3. **Rosetta asserter** — validates network identifier and operation structure, not the byte length of the `transaction` field.

### Impact Explanation
Each request with a large hex payload causes two memory allocations proportional to payload size (the hex string itself in the JSON body, plus the decoded `[]byte`), followed by CPU-intensive protobuf parsing. Concurrent requests from a single unauthenticated source can exhaust heap memory and saturate CPU, causing an OOM kill or sustained unresponsiveness of the Rosetta node. This affects both online and offline modes since `ConstructionParse` is available in both. [7](#0-6) 

### Likelihood Explanation
The endpoint is publicly reachable with no authentication. The attack requires only the ability to send HTTP POST requests — no credentials, no prior state, no cryptographic material. The exploit is trivially scriptable and repeatable. Deployments without the Traefik middleware overlay (the default) have no compensating control at any layer.

### Recommendation
1. Wrap the request body reader with `http.MaxBytesReader` in the HTTP handler or in a middleware, capping the body at a reasonable limit (e.g., 1 MB, well above any legitimate Hiero transaction size).
2. Add an explicit length check on `request.Transaction` before calling `unmarshallTransactionFromHexString`, rejecting strings exceeding a defined maximum (e.g., `len(tx) > 2*maxTransactionBytes`).
3. Enable the Traefik `inFlightReq` and `rateLimit` middleware by default, not only in the production overlay.

### Proof of Concept
```bash
# Generate a large valid hex string (e.g., 50 MB of 0x00 bytes = 100 MB hex)
python3 -c "print('00' * 50_000_000)" > /tmp/big_hex.txt
BIG_HEX=$(cat /tmp/big_hex.txt)

# Send to /construction/parse (repeat concurrently to amplify memory pressure)
for i in $(seq 1 10); do
  curl -s -X POST http://<rosetta-host>:5700/construction/parse \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hiero\",\"network\":\"testnet\"},\"signed\":false,\"transaction\":\"${BIG_HEX}\"}" &
done
wait
# Expected: server OOM or severe latency spike; response (if any) is ErrTransactionUnmarshallingFailed
```

### Citations

**File:** rosetta/app/services/construction_service.go (L183-190)
```go
func (c *constructionAPIService) ConstructionParse(
	ctx context.Context,
	request *rTypes.ConstructionParseRequest,
) (*rTypes.ConstructionParseResponse, *rTypes.Error) {
	transaction, err := unmarshallTransactionFromHexString(request.Transaction)
	if err != nil {
		return nil, err
	}
```

**File:** rosetta/app/services/construction_service.go (L658-667)
```go
func unmarshallTransactionFromHexString(transactionString string) (hiero.TransactionInterface, *rTypes.Error) {
	transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
	if err != nil {
		return nil, errors.ErrTransactionDecodeFailed
	}

	transaction, err := hiero.TransactionFromBytes(transactionBytes)
	if err != nil {
		return nil, errors.ErrTransactionUnmarshallingFailed
	}
```

**File:** rosetta/main.go (L133-152)
```go
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror/values-prod.yaml (L7-8)
```yaml
global:
  middleware: true
```
