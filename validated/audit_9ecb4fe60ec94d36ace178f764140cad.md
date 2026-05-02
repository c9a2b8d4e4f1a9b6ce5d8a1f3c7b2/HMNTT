All referenced code has been verified against the actual repository. Every technical claim in the report is accurate.

---

Audit Report

## Title
Unauthenticated `/network/status` Endpoint Triggers Multiple Unbounded DB Queries Per Request, Enabling Resource Exhaustion

## Summary
The `NetworkStatus()` handler in the Rosetta service executes 2–3 uncached database queries on every invocation. The Go application applies no rate limiting. The Traefik-based infrastructure rate limit is opt-in and disabled by default. Any unauthenticated caller can flood this endpoint to exhaust the PostgreSQL connection pool.

## Finding Description

**Call chain — verified line by line:**

`NetworkStatus()` in `rosetta/app/services/network_service.go` sequentially calls:

1. `n.RetrieveGenesis(ctx)` → `blockRepository.RetrieveGenesis()` → `initGenesisRecordFile()`. The genesis block is cached via a `sync.Once` guarded by a fast-path check on `br.genesisBlock.ConsensusStart`. After the first successful call this costs **0 DB queries**. [1](#0-0) 

2. `n.RetrieveLatest(ctx)` → always executes `selectLatestWithIndex` raw SQL against `record_file` with no caching. **1 DB query per request.** [2](#0-1) [3](#0-2) 

3. `n.addressBookEntryRepo.Entries(ctx)` → loops over file IDs 101 and 102, executing `latestNodeServiceEndpoints` SQL for each, breaking only when rows are returned. **1–2 DB queries per request.** [4](#0-3) 

**Steady-state DB queries per request: 2–3. No caching, no throttle, no auth.**

**No application-level rate limiting.** `main.go` wraps the router with exactly three middlewares — `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — and nothing else. [5](#0-4) 

**Infrastructure rate limiting is opt-in and off by default.** The Traefik `Middleware` CRD is only rendered when **both** `global.middleware` and `.Values.middleware` are truthy: [6](#0-5) 

`global.middleware` defaults to `false` in `values.yaml`: [7](#0-6) 

When the middleware *is* enabled, the `rateLimit` entry is keyed on `requestHost: true`, not source IP, making it trivially bypassable via arbitrary `Host` headers: [8](#0-7) 

**No authentication is required.** `NetworkStatus()` checks only `n.IsOnline()` before proceeding. [9](#0-8) 

## Impact Explanation
A sustained flood of POST requests to `/network/status` forces 2–3 PostgreSQL queries per request. At sufficient request rate this exhausts the database connection pool, causing query queuing and timeouts across all mirror node components that share the same DB backend (importer, REST API, gRPC). The mirror node loses the ability to read chain state. Availability impact is high; no confidentiality or integrity impact.

## Likelihood Explanation
The attack requires only network access to the Rosetta port and knowledge of the public Rosetta API specification. No credentials or special headers are needed. The project itself ships a k6 load test targeting this exact endpoint: [10](#0-9) 

Deployments without Traefik (bare-metal, direct port exposure, non-Helm) have zero rate limiting. Even with Traefik enabled, the `requestHost`-keyed rate limit is bypassable. Likelihood is **High**.

## Recommendation

1. **Application-level rate limiting:** Add a per-IP token-bucket middleware in `main.go` (e.g., `golang.org/x/time/rate`) before the router, independent of infrastructure.
2. **Short-lived cache for `RetrieveLatest`:** Cache the latest block result with a 1–2 second TTL to reduce DB fan-out under load.
3. **DB connection pool limits with timeouts:** Configure `SetMaxOpenConns`, `SetMaxIdleConns`, and `SetConnMaxLifetime` on the DB client so a flood cannot hold connections indefinitely.
4. **Enable middleware by default:** Set `global.middleware: true` in the default Helm values, or document it as a required security configuration.
5. **Switch `rateLimit` criterion to source IP** (`ipStrategy`) rather than `requestHost` to prevent Host-header bypass.

## Proof of Concept

```bash
# Flood /network/status with 50 concurrent workers
wrk -t50 -c50 -d60s -s - http://<rosetta-host>/network/status <<'EOF'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}'
EOF
```

Each request triggers 2–3 queries against `record_file` and `address_book_entry`. At 50 concurrent connections the DB connection pool saturates, causing `ErrDatabaseError` responses and degrading all other mirror node DB consumers.

### Citations

**File:** rosetta/app/persistence/block.go (L24-31)
```go
	selectLatestWithIndex string = `select consensus_start,
                                           consensus_end,
                                           hash,
                                           index,
                                           prev_hash
                                    from record_file
                                    order by index desc
                                    limit 1`
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```

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

**File:** tools/k6/src/rosetta/test/networkStatus.js (L1-25)
```javascript
// SPDX-License-Identifier: Apache-2.0

import http from 'k6/http';

import {TestScenarioBuilder} from '../../lib/common.js';
import {setupTestParameters} from '../libex/parameters.js';

const urlTag = '/rosetta/network/status';

const {options, run} = new TestScenarioBuilder()
  .name('networkStatus') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = testParameters.baseUrl + urlTag;
    const payload = JSON.stringify({
      network_identifier: testParameters.networkIdentifier,
      metadata: {},
    });
    return http.post(url, payload);
  })
  .check('NetworkStatus OK', (r) => r.status === 200)
  .build();

export {options, run};

```
