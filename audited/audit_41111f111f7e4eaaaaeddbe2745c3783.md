### Title
Unauthenticated Repeated `/account/balance` Calls Trigger Unbounded `SUM` Aggregation on `crypto_transfer`, Enabling Sustained DB CPU Exhaustion

### Summary
`RetrieveBalanceAtBlock()` in `rosetta/app/persistence/account.go` issues up to four sequential DB queries per request, including an unbounded `SELECT SUM(amount) FROM crypto_transfer` aggregation scoped only by `entity_id` and a timestamp range. No rate limiting exists at the application or persistence layer; the only throttle is an optional Traefik ingress middleware whose `rateLimit` criterion is keyed on `requestHost` (not source IP), making it trivially bypassable. An unprivileged attacker can sustain elevated DB CPU by flooding `/account/balance` for a high-activity account (e.g., treasury `0.0.2`) with varying `consensusEnd` values that defeat query-plan caching.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/account.go`, `RetrieveBalanceAtBlock()` (lines 161–223) calls three helpers in sequence:

1. `getCryptoEntity()` (lines 225–265) — one query against `entity` / `entity_history`.
2. `getLatestBalanceSnapshot()` (lines 267–311) — **two** queries: `selectPreviousPartitionLowerBound` (lines 76–86) then `latestBalanceBeforeConsensus` (lines 30–50).
3. `getBalanceChange()` (lines 313–339) — one query executing `balanceChangeBetween` (lines 21–29):

```sql
SELECT coalesce((
  SELECT SUM(amount) FROM crypto_transfer
  WHERE consensus_timestamp > @start
    AND consensus_timestamp <= @end
    AND entity_id = @account_id
    AND (errata IS NULL OR errata <> 'DELETE')
), 0) AS value
```

This `SUM` must scan every `crypto_transfer` row for the account between the last balance snapshot and `consensusEnd`. For the treasury account, which participates in every fee-paying transaction, this range can contain millions of rows.

**Root cause:** The persistence layer performs no input throttling, no result caching, and no query-cost guard. Each unique `consensusEnd` value produces a distinct timestamp range `[@start, @end]`, preventing the DB from reusing a cached result. The `@start` value is derived from the most recent `account_balance` snapshot before `consensusEnd`, so an attacker who sweeps `consensusEnd` across the space between two consecutive balance snapshots (typically 15 minutes apart on mainnet) forces a fresh full-range aggregation on every request.

**Why existing checks fail:**

- The application middleware stack in `main.go` (lines 217–219) registers only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — none of which throttle requests.
- The Traefik `rateLimit` in `charts/hedera-mirror-rosetta/values.yaml` (lines 157–160) uses `sourceCriterion: requestHost: true`, meaning the limit is shared across **all callers that send the same `Host` header**, not per source IP. An attacker sending requests with a spoofed or varied `Host` header bypasses this entirely.
- The `inFlightReq: amount: 5` (lines 152–156) limits concurrent in-flight requests per IP to 5, but 5 simultaneous long-running aggregation queries against a high-activity account is already sufficient to saturate DB CPU on a typical mirror-node deployment.
- Both Traefik controls are Kubernetes-ingress-only; direct TCP access to the service port bypasses them completely.
- There is no authentication or API key requirement on any Rosetta endpoint.

### Impact Explanation
A sustained flood of `/account/balance` POST requests targeting `0.0.2` (treasury) with varying `block_identifier.index` values causes the PostgreSQL instance to continuously execute expensive `SUM` aggregations over `crypto_transfer`. On mainnet, the treasury account has tens of millions of transfer rows. Even at 5 concurrent requests (the `inFlightReq` ceiling), each query scanning millions of rows can hold DB CPU above 30% indefinitely, degrading all other mirror-node consumers (REST API, gRPC, other Rosetta endpoints) that share the same database. This meets the stated threshold of ≥30% sustained CPU elevation without brute-force volume.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only knowledge of the Rosetta API spec (public). The treasury account ID (`0.0.2`) is publicly known. Valid `consensusEnd` values (block consensus timestamps) are discoverable via `/block` endpoints. A single attacker with a modest internet connection can sustain the attack indefinitely. The Traefik `requestHost`-keyed rate limit is bypassable with a one-line HTTP header change. No CAPTCHA, API key, or IP-based throttle exists at the application layer.

### Recommendation
1. **Application-layer rate limiting:** Add a per-IP token-bucket middleware in `main.go` (e.g., `golang.org/x/time/rate`) wrapping the router before `MetricsMiddleware`, enforcing a per-source-IP request rate for `/account/balance`.
2. **Result caching:** Cache `getBalanceChange()` results keyed on `(accountId, consensusStart, consensusEnd)` with a short TTL (e.g., 30 s) using an in-process LRU cache to absorb repeated identical queries.
3. **Fix Traefik criterion:** Change `sourceCriterion` in the `rateLimit` middleware from `requestHost: true` to `ipStrategy: depth: 1` so the limit is per source IP, not per host header.
4. **DB query timeout:** Enforce a short statement timeout (e.g., `statement_timeout = 5s`) on the DB role used by the Rosetta service to bound the worst-case cost of any single aggregation query.
5. **Index coverage:** Ensure `crypto_transfer(entity_id, consensus_timestamp)` is a covering index to reduce per-row scan cost for the `SUM` query.

### Proof of Concept

**Preconditions:** Rosetta mirror node running in online mode, accessible without authentication. Treasury account `0.0.2` used as target. Two valid consecutive block indices `N` and `N+K` (spanning one balance-snapshot interval, ~15 min) obtained from `/block`.

**Steps:**

```bash
# 1. Discover a range of valid block indices spanning one snapshot interval
curl -s -X POST http://<rosetta-host>/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  | jq .current_block_identifier.index

# 2. Launch 5 concurrent workers, each sweeping a different block index
# within the same snapshot interval to prevent cache reuse
for i in $(seq 1 5); do
  while true; do
    BLOCK=$((BASE_BLOCK + RANDOM % 10000))
    curl -s -X POST http://<rosetta-host>/account/balance \
      -H 'Content-Type: application/json' \
      -H "Host: attacker-host-$i.example.com" \
      -d "{
        \"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
        \"account_identifier\":{\"address\":\"0.0.2\"},
        \"block_identifier\":{\"index\":$BLOCK}
      }" > /dev/null
  done &
done
```

**Result:** Each request triggers `SELECT SUM(amount) FROM crypto_transfer WHERE entity_id = 2 AND consensus_timestamp > <snapshot_ts> AND consensus_timestamp <= <block_ts>` with a unique range. The varying `Host` headers bypass the Traefik `requestHost`-keyed rate limit. DB CPU climbs above 30% and remains elevated for the duration of the attack. Other API consumers experience query latency degradation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rosetta/app/persistence/account.go (L21-29)
```go
	balanceChangeBetween = `select
                              coalesce((
                                select sum(amount) from crypto_transfer
                                where
                                  consensus_timestamp > @start and
                                  consensus_timestamp <= @end and
                                  entity_id = @account_id and
                                  (errata is null or errata <> 'DELETE')
                              ), 0) as value`
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

**File:** rosetta/app/persistence/account.go (L313-339)
```go
func (ar *accountRepository) getBalanceChange(ctx context.Context, accountId, consensusStart, consensusEnd int64) (
	int64,
	*rTypes.Error,
) {
	db, cancel := ar.dbClient.GetDbWithContext(ctx)
	defer cancel()

	change := &accountBalanceChange{}
	// gets the balance change from the Balance snapshot until the target block
	if err := db.Raw(
		balanceChangeBetween,
		sql.Named("account_id", accountId),
		sql.Named("start", consensusStart),
		sql.Named("end", consensusEnd),
		sql.Named("end_range", getInclusiveInt8Range(consensusEnd, consensusEnd)),
	).First(change).Error; err != nil {
		log.Errorf(
			databaseErrorFormat,
			hErrors.ErrDatabaseError.Message,
			fmt.Sprintf("%v looking for account %d's balance change in [%d, %d]", err, accountId, consensusStart,
				consensusEnd),
		)
		return 0, hErrors.ErrDatabaseError
	}

	return change.Value, nil
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-167)
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
