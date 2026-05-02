### Title
Unauthenticated DB Flood via Unprotected `NetworkStatus()` Endpoint with Infrastructure Circuit Breaker Disabled by Default

### Summary
`NetworkStatus()` in `rosetta/app/services/network_service.go` issues at least two unconditional DB queries per request (`RetrieveLatest` and `Entries`) with no application-level rate limiting, throttling, or circuit breaker. The Traefik middleware chain that defines `circuitBreaker`, `inFlightReq`, and `rateLimit` protections is gated behind `global.middleware: false` in the Helm chart defaults, meaning it is **not deployed in a default installation**. Any unauthenticated external caller can sustain a high-concurrency flood against `/network/status`, keeping the DB under constant load.

### Finding Description

**Exact code path:**

`NetworkStatus()` at `rosetta/app/services/network_service.go` lines 59–88 executes three repository calls per invocation:

1. `n.RetrieveGenesis(ctx)` (line 67) → `base_service.go:97` → `blockRepo.RetrieveGenesis()` — cached after first call via `initGenesisRecordFile`, so effectively free after startup.
2. `n.RetrieveLatest(ctx)` (line 72) → `base_service.go:105` → `blockRepo.RetrieveLatest()` — **always** issues `db.Raw(selectLatestWithIndex).First(rb)` at `persistence/block.go:199`.
3. `n.addressBookEntryRepo.Entries(ctx)` (line 77) → `persistence/address_book_entry.go:57–75` — **always** issues up to two `db.Raw(latestNodeServiceEndpoints, ...)` queries (one for file_id 101, one for 102 if 101 returns empty). [1](#0-0) [2](#0-1) [3](#0-2) 

**Root cause — failed assumption:**

The design assumes that infrastructure-layer Traefik middleware (circuit breaker, per-IP in-flight cap, rate limiter) will be active. However, the Helm template at `charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3 conditions the entire Middleware CRD on `{{ if and .Values.global.middleware .Values.middleware }}`. The default value of `global.middleware` is `false` (`charts/hedera-mirror-rosetta/values.yaml` line 95), so **no Middleware CRD is created in a default deployment**. The ingress annotation still references the non-existent middleware name, which Traefik silently skips or ignores, leaving the route fully unprotected. [4](#0-3) [5](#0-4) [6](#0-5) 

There is zero application-level rate limiting, circuit breaking, or caching of the `RetrieveLatest` or `Entries` results anywhere in the Go service code. [7](#0-6) 

### Impact Explanation

Each concurrent request to `/network/status` consumes at least two DB connections and executes two to three SQL queries (one `selectLatestWithIndex` scan + one or two `latestNodeServiceEndpoints` aggregation queries involving joins across `address_book`, `address_book_entry`, `address_book_service_endpoint`, and `node` tables). A flood of concurrent requests exhausts the DB connection pool, starves legitimate queries from other Rosetta endpoints (block, account, construction), and can prevent the DB from recovering even during low-traffic periods because each new request immediately re-occupies freed connections. The impact is persistent service degradation for all users of the mirror node's Rosetta API. [8](#0-7) 

### Likelihood Explanation

**Preconditions:** None. The `/network/status` endpoint (`POST /network/status`) requires no authentication, no API key, and no special network position. It is publicly reachable wherever the Rosetta service is exposed.

**Feasibility:** A single attacker with a modest number of concurrent HTTP clients (e.g., 100–500 goroutines or `ab`/`wrk` threads) can saturate the DB connection pool. The `latestNodeServiceEndpoints` query is a multi-table join with aggregation — it is not a trivial point-lookup and will hold connections for measurable time under load.

**Repeatability:** Fully repeatable; no state is consumed or depleted by the attack. The attacker can sustain the flood indefinitely.

**Default deployment risk:** Because `global.middleware: false` is the shipped default, any operator who deploys the chart without explicitly overriding this value is exposed. [9](#0-8) 

### Recommendation

1. **Immediate (application level):** Add an in-process rate limiter (e.g., `golang.org/x/time/rate`) or a short-lived cache (TTL ~1–5 s) for the `RetrieveLatest` and `Entries` results inside `NetworkStatus()`. The data returned by this endpoint changes at block cadence (~2–3 s), so caching is semantically safe.

2. **Helm default fix:** Change `global.middleware` default to `true`, or unconditionally deploy the Middleware CRD when `middleware` values are non-empty, removing the `global.middleware` gate. The `inFlightReq: amount: 5` per-IP and `rateLimit: average: 10` per-host limits defined in `values.yaml` lines 152–160 are appropriate but currently dead code in default deployments.

3. **DB-level:** Apply a statement timeout on the DB connection used by the Rosetta service so that runaway queries are killed rather than held open indefinitely. [10](#0-9) 

### Proof of Concept

```bash
# 1. Deploy the Rosetta service with default Helm values (global.middleware=false)
# 2. Confirm no Traefik Middleware CRD exists:
kubectl get middleware -n <namespace> | grep rosetta   # returns nothing

# 3. Launch concurrent flood (requires no credentials):
wrk -t 50 -c 500 -d 60s \
  -s <(echo 'wrk.method="POST"; wrk.body="{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"}}"; wrk.headers["Content-Type"]="application/json"') \
  http://<rosetta-host>/network/status

# 4. Observe DB connection pool exhaustion:
#    - Other Rosetta endpoints (/block, /account/balance) begin returning 500s
#    - DB CPU and active connection count spike to maximum
#    - Degradation persists after flood stops until connection pool drains
```

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

**File:** rosetta/app/persistence/address_book_entry.go (L18-30)
```go
const latestNodeServiceEndpoints = `select
                                    abe.node_id,
                                    coalesce(n.account_id, abe.node_account_id) as node_account_id,
                                    string_agg(ip_address_v4 || ':' || port::text, ','
                                      order by ip_address_v4,port) endpoints
                                  from (
                                    select max(start_consensus_timestamp) from address_book where file_id = @file_id
                                  ) current
                                  join address_book_entry abe on abe.consensus_timestamp = current.max
                                  left join node n on n.node_id = abe.node_id
                                  left join address_book_service_endpoint abse
                                    on abse.consensus_timestamp = current.max and abse.node_id = abe.node_id
                                  group by abe.node_id, n.account_id, abe.node_account_id`
```

**File:** rosetta/app/persistence/address_book_entry.go (L57-75)
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
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-97)
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
  podAnnotations: {}
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

**File:** rosetta/app/services/base_service.go (L100-106)
```go
func (b *BaseService) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if !b.IsOnline() {
		return nil, errors.ErrInternalServerError
	}

	return b.blockRepo.RetrieveLatest(ctx)
}
```
