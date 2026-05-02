### Title
Unauthenticated Repeated `AccountBalance` Requests Without `BlockIdentifier` Cause Unbounded Uncached DB Query Amplification

### Summary
The `AccountBalance()` handler in `rosetta/app/services/account_service.go` unconditionally calls `RetrieveLatest()` — which executes a raw SQL query against the database on every invocation with no caching — whenever a request omits `BlockIdentifier`. Combined with the multiple additional uncached DB queries in `RetrieveBalanceAtBlock()`, each unauthenticated request triggers 4+ database round-trips. No application-level rate limiting or result caching exists, and the Traefik middleware protection is disabled by default, allowing any unprivileged external user to sustain elevated DB I/O and CPU consumption well above the 30% threshold.

### Finding Description

**Code path:**

`rosetta/app/services/account_service.go`, lines 52–56:
```go
if request.BlockIdentifier != nil {
    block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
} else {
    block, rErr = a.RetrieveLatest(ctx)   // ← triggered on every request with no BlockIdentifier
}
``` [1](#0-0) 

`RetrieveLatest()` in `rosetta/app/services/base_service.go` lines 100–105 delegates directly to `blockRepo.RetrieveLatest()` with no caching layer: [2](#0-1) 

`blockRepository.RetrieveLatest()` in `rosetta/app/persistence/block.go` lines 190–208 executes a raw SQL query (`selectLatestWithIndex`: `SELECT … FROM record_file ORDER BY index DESC LIMIT 1`) on **every call** — the `sync.Once` on the struct only guards `initGenesisRecordFile`, not the latest-block query: [3](#0-2) [4](#0-3) 

After `RetrieveLatest()`, `RetrieveBalanceAtBlock()` in `rosetta/app/persistence/account.go` lines 161–223 issues at minimum 3 more uncached DB queries per request: `getCryptoEntity` (entity/entity_history lookup), `getLatestBalanceSnapshot` (account_balance + mirror_node_time_partitions), and `getBalanceChange` (crypto_transfer aggregation): [5](#0-4) 

**Root cause:** There is no in-process cache for the latest block result, no application-level request throttling, and no authentication requirement on the `/account/balance` endpoint. The `BlockIdentifier`-absent branch is the normal Rosetta API usage pattern, making it trivially reachable.

**Why existing checks fail:**

The only rate-limiting mechanism is the optional Traefik middleware defined in `charts/hedera-mirror-rosetta/values.yaml`. However:
- `global.middleware` defaults to `false` (line 95), so the middleware chain is **not deployed** in default installations: [6](#0-5) 
- Even when enabled, the `rateLimit` uses `sourceCriterion: requestHost: true` (keyed on the HTTP `Host` header, not source IP), which an attacker trivially bypasses by rotating the `Host` header value across requests: [7](#0-6) 
- The `inFlightReq: amount: 5` per-IP limit only caps concurrency, not sustained request rate.

### Impact Explanation
Each unauthenticated POST to `/account/balance` without `block_identifier` triggers 4+ sequential uncached database queries against `record_file`, `entity`/`entity_history`, `account_balance`, `mirror_node_time_partitions`, and `crypto_transfer`. At even modest flood rates (e.g., 50–100 req/s from a single host, or distributed across IPs), this produces hundreds of DB queries per second that are entirely absent from normal baseline traffic, easily exceeding a 30% increase in DB I/O and CPU on the mirror node's PostgreSQL instance. The mirror node's DB connection pool (`maxOpenConnections: 100` per config) can be saturated, degrading or blocking legitimate traffic. [8](#0-7) 

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a valid (or even invalid — the account lookup returns a zero balance rather than an error for unknown accounts) account identifier. The omission of `BlockIdentifier` is the standard Rosetta API call pattern documented in the Rosetta spec, so it cannot be blocked without breaking spec compliance. The attack is trivially scriptable, repeatable indefinitely, and distributable across multiple source IPs to defeat any per-IP controls.

### Recommendation
1. **Cache the latest block result** in `blockRepository.RetrieveLatest()` with a short TTL (e.g., 1–2 seconds), since the latest block changes only on new record file ingestion (every ~2–5 seconds on Hedera mainnet). A simple time-based in-memory cache with a mutex guard is sufficient.
2. **Add application-level rate limiting** in the Go HTTP middleware layer (e.g., using `golang.org/x/time/rate`) keyed on source IP, independent of the optional Traefik deployment.
3. **Enable the Traefik middleware by default** (`global.middleware: true`) and change the `rateLimit` `sourceCriterion` from `requestHost` to `ipStrategy` to prevent Host-header bypass.
4. **Set a DB query timeout** on `RetrieveLatest` and `RetrieveBalanceAtBlock` contexts to bound per-request DB resource consumption.

### Proof of Concept
```bash
# No authentication required. Omit block_identifier to trigger RetrieveLatest on every request.
# Replace ACCOUNT_ID with any valid (or even nonexistent) account, e.g. "0.0.98"

while true; do
  curl -s -o /dev/null -X POST https://<rosetta-host>/account/balance \
    -H "Content-Type: application/json" \
    -d '{
      "network_identifier": {"blockchain":"Hedera","network":"mainnet"},
      "account_identifier": {"address":"0.0.98"}
    }' &
done
# Run from multiple IPs or with varied Host headers to bypass per-IP/per-host controls.
# Monitor PostgreSQL pg_stat_activity and CPU: query count and CPU will rise proportionally
# to request rate, with no server-side throttle in a default deployment.
```

### Citations

**File:** rosetta/app/services/account_service.go (L52-56)
```go
	if request.BlockIdentifier != nil {
		block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
	} else {
		block, rErr = a.RetrieveLatest(ctx)
	}
```

**File:** rosetta/app/services/base_service.go (L100-105)
```go
func (b *BaseService) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if !b.IsOnline() {
		return nil, errors.ErrInternalServerError
	}

	return b.blockRepo.RetrieveLatest(ctx)
```

**File:** rosetta/app/persistence/block.go (L119-123)
```go
type blockRepository struct {
	dbClient         interfaces.DbClient
	genesisBlock     recordBlock
	once             sync.Once
	treasuryEntityId domain.EntityId
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

**File:** rosetta/app/persistence/account.go (L20-87)
```go
const (
	balanceChangeBetween = `select
                              coalesce((
                                select sum(amount) from crypto_transfer
                                where
                                  consensus_timestamp > @start and
                                  consensus_timestamp <= @end and
                                  entity_id = @account_id and
                                  (errata is null or errata <> 'DELETE')
                              ), 0) as value`
	latestBalanceBeforeConsensus = `select
                                      bt.consensus_timestamp,
                                      coalesce((
                                        select balance
                                        from account_balance as ab
                                        where account_id = @account_id and
                                          ab.consensus_timestamp <= bt.consensus_timestamp and
                                          ab.consensus_timestamp >= @lower_bound and
                                          ab.consensus_timestamp <= @timestamp
                                        order by ab.consensus_timestamp desc
                                        limit 1
                                      ), 0) as balance
                                    from (
                                      select consensus_timestamp
                                      from account_balance
                                      where account_id = @treasury_entity_id and
                                        consensus_timestamp >= @lower_bound and
                                        consensus_timestamp <= @timestamp
                                      order by consensus_timestamp desc
                                      limit 1
                                    ) as bt`
	selectCryptoEntityWithAliasById = "select alias, id from entity where id = @id"
	selectCryptoEntityByAlias       = `select id, deleted, key, timestamp_range
                                 from entity
                                 where alias = @alias and timestamp_range @> @consensus_end
                                 union all
                                 select id, deleted, key, timestamp_range
                                 from entity_history
                                 where alias = @alias and timestamp_range @> @consensus_end
                                 order by timestamp_range desc`
	selectCurrentCryptoEntityByAlias = `select id from entity
                                 where alias = @alias and (deleted is null or deleted is false)`
	selectCryptoEntityById = `select id, deleted, key, timestamp_range
                              from entity
                              where type in ('ACCOUNT', 'CONTRACT') and id = @id and
                                  timestamp_range @> @consensus_end
                              union all
                              select id, deleted, key, timestamp_range
                              from entity_history
                              where type in ('ACCOUNT', 'CONTRACT') and id = @id and
                                  timestamp_range @> @consensus_end
                              order by timestamp_range desc
                              limit 1`
	// select the lower bound of the second last partition whose lower bound is LTE @timestamp. It's possible that
	// @timestamp is in a partition for which the first account balance snapshot is yet to be filled, thus the need
	// to look back one more partition for account balance
	selectPreviousPartitionLowerBound = `with last_two as (
                                select *
                                from mirror_node_time_partitions
                                where parent = 'account_balance' and @timestamp >= from_timestamp
                                order by from_timestamp desc
                                limit 2
                              )
                              select from_timestamp
                              from last_two
                              order by from_timestamp
                              limit 1`
)
```

**File:** rosetta/app/persistence/account.go (L161-223)
```go
func (ar *accountRepository) RetrieveBalanceAtBlock(
	ctx context.Context,
	accountId types.AccountId,
	consensusEnd int64,
) (types.AmountSlice, string, []byte, *rTypes.Error) {
	var entityIdString string
	entity, err := ar.getCryptoEntity(ctx, accountId, consensusEnd)
	if err != nil {
		return nil, entityIdString, nil, err
	}

	if entity == nil && accountId.HasAlias() {
		return types.AmountSlice{&types.HbarAmount{}}, entityIdString, nil, nil
	}

	balanceChangeEndTimestamp := consensusEnd
	balanceSnapshotEndTimestamp := consensusEnd
	if entity != nil && entity.Deleted != nil && *entity.Deleted && entity.GetModifiedTimestamp() <= consensusEnd {
		// if an account / contract is deleted at t1, a balance snapshot at t1 (if exists) won't have info for the
		// entity, thus look for a balance snapshot at or before the deleted timestamp - 1
		// however, the balanceChangeEndTimestamp should be the deletion timestamp since the crypto delete transaction
		// may have a transfer which moves the remaining hbar balance to another account
		balanceChangeEndTimestamp = entity.GetModifiedTimestamp()
		balanceSnapshotEndTimestamp = balanceChangeEndTimestamp - 1
	}

	id := accountId.GetId()
	if accountId.HasAlias() {
		// entity can't be nil if accountId has alias
		id = entity.Id.EncodedId
	}
	snapshotTimestamp, hbarAmount, err := ar.getLatestBalanceSnapshot(
		ctx,
		id,
		balanceSnapshotEndTimestamp,
	)
	if err != nil {
		return nil, entityIdString, nil, err
	}

	hbarValue, err := ar.getBalanceChange(
		ctx,
		id,
		snapshotTimestamp,
		balanceChangeEndTimestamp,
	)
	if err != nil {
		return nil, entityIdString, nil, err
	}

	hbarAmount.Value += hbarValue

	amounts := make(types.AmountSlice, 0, 1)
	amounts = append(amounts, hbarAmount)

	var publicKey []byte
	if entity != nil {
		// return the entity id string in the format of 'shard.realm.num'
		entityIdString = entity.Id.String()
		publicKey = entity.Key
	}
	return amounts, entityIdString, publicKey, nil
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-161)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
```
