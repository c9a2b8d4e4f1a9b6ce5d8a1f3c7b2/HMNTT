### Title
Missing Shard/Realm Validation in `AccountBalance()` Allows Unprivileged DB Griefing

### Summary
`AccountBalance()` in `rosetta/app/services/account_service.go` passes the caller-supplied address to `types.NewAccountIdFromString()`, which — by explicit design — ignores `systemShard`/`systemRealm` when the address is in `shard.realm.num` dot-notation. An unprivileged attacker can therefore supply any arbitrary shard/realm values (e.g., `99.99.1`), causing the service to issue real database queries against non-existent accounts on every request, with no early-rejection path.

### Finding Description
**Code path:**

`rosetta/app/services/account_service.go:45` calls:
```go
accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
```

`rosetta/app/domain/types/account_id.go:182-188` — the function's own comment states the root cause explicitly:
```go
// NewAccountIdFromString creates AccountId from the address string. If the address is in the shard.realm.num form,
// shard and realm are ignored.
func NewAccountIdFromString(address string, shard, realm int64) (zero AccountId, _ error) {
    if strings.Contains(address, ".") {
        entityId, err := domain.EntityIdFromString(address)  // parses attacker-supplied shard/realm
        if err != nil {
            return zero, err
        }
        return AccountId{accountId: entityId}, nil  // systemShard/systemRealm never consulted
    }
```

The `systemShard`/`systemRealm` parameters are silently discarded for dot-notation addresses. The returned `AccountId` carries the attacker-controlled shard and realm values.

This `accountId` is then passed directly to `accountRepo.RetrieveBalanceAtBlock()` at line 61, which calls `getCryptoEntity()` (`rosetta/app/persistence/account.go:225-264`) — a live DB query using the attacker-supplied encoded entity ID. When the entity is not found (`len(entities) == 0`), the code does **not** short-circuit for non-alias accounts; it proceeds to call `getLatestBalanceSnapshot()` with the same bogus ID, issuing a second DB query. Only then does it return an error (confirmed by `TestRetrieveBalanceAtBlockNoAccountBalance`).

**Why the existing error check is insufficient:**
The check at `account_service.go:46-48` only catches parse errors (malformed strings like `a.b.c`). A well-formed address like `99.99.1` passes `EntityIdFromString` successfully, so `ErrInvalidAccount` is never returned. The shard/realm mismatch is never detected.

### Impact Explanation
Every request with a mismatched shard/realm causes **two unnecessary database round-trips** (entity lookup + balance snapshot lookup) that will always miss. An attacker can sustain this to inflate DB CPU/IO load, degrade query latency for legitimate users, and exhaust DB connection pool slots — all with zero cost to the attacker and no economic damage to any on-chain user. This is a classic griefing/resource-exhaustion vector.

### Likelihood Explanation
No authentication or special privilege is required. The Rosetta `/account/balance` endpoint is publicly reachable. The Helm chart configures a rate limit of 10 req/s per host (`charts/hedera-mirror-rosetta/values.yaml:157-160`), but this is per-host and easily bypassed from multiple IPs or by rotating source addresses. The attack is trivially scriptable and fully repeatable.

### Recommendation
After `NewAccountIdFromString` returns successfully for a dot-notation address, add an explicit guard in `AccountBalance()` (or inside `NewAccountIdFromString` itself) that rejects addresses whose parsed shard/realm differ from `systemShard`/`systemRealm`:

```go
accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
if err != nil {
    return nil, errors.ErrInvalidAccount
}
// Add: reject cross-shard/realm dot-notation addresses
if !accountId.HasAlias() {
    if accountId.GetShardNum() != a.systemShard || accountId.GetRealmNum() != a.systemRealm {
        return nil, errors.ErrInvalidAccount
    }
}
```

This makes the rejection happen before any DB interaction, at zero cost.

### Proof of Concept
```
POST /account/balance
Content-Type: application/json

{
  "network_identifier": { "blockchain": "Hedera", "network": "mainnet" },
  "account_identifier": { "address": "99.99.1" }
}
```

1. `NewAccountIdFromString("99.99.1", 0, 0)` succeeds — returns `AccountId{shard:99, realm:99, num:1}`.
2. `RetrieveBalanceAtBlock` is called; `getCryptoEntity` issues a DB query for encoded ID of `99.99.1` → returns empty.
3. `getLatestBalanceSnapshot` issues a second DB query for the same ID → returns not-found error.
4. Response: error. Repeat at high frequency from multiple IPs to sustain DB load. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rosetta/app/services/account_service.go (L45-48)
```go
	accountId, err := types.NewAccountIdFromString(request.AccountIdentifier.Address, a.systemShard, a.systemRealm)
	if err != nil {
		return nil, errors.ErrInvalidAccount
	}
```

**File:** rosetta/app/domain/types/account_id.go (L180-188)
```go
// NewAccountIdFromString creates AccountId from the address string. If the address is in the shard.realm.num form,
// shard and realm are ignored. The only valid form of the alias address is the hex string of the raw public key bytes.
func NewAccountIdFromString(address string, shard, realm int64) (zero AccountId, _ error) {
	if strings.Contains(address, ".") {
		entityId, err := domain.EntityIdFromString(address)
		if err != nil {
			return zero, err
		}
		return AccountId{accountId: entityId}, nil
```

**File:** rosetta/app/persistence/account.go (L225-264)
```go
func (ar *accountRepository) getCryptoEntity(ctx context.Context, accountId types.AccountId, consensusEnd int64) (
	*domain.Entity,
	*rTypes.Error,
) {
	db, cancel := ar.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var query string
	var args []any
	consensusEndArg := sql.Named("consensus_end", getInclusiveInt8Range(consensusEnd, consensusEnd))
	if accountId.HasAlias() {
		query = selectCryptoEntityByAlias
		args = []any{
			sql.Named("alias", accountId.GetAlias()),
			consensusEndArg,
		}
	} else {
		query = selectCryptoEntityById
		args = []any{
			consensusEndArg,
			sql.Named("id", accountId.GetId()),
		}
	}

	entities := make([]domain.Entity, 0)
	if err := db.Raw(query, args...).Scan(&entities).Error; err != nil {
		log.Errorf(
			databaseErrorFormat,
			hErrors.ErrDatabaseError.Message,
			fmt.Sprintf("%v looking for entity %s", err, accountId),
		)
		return nil, hErrors.ErrDatabaseError
	}

	if len(entities) == 0 {
		return nil, nil
	}

	// if it's by alias, return the first match which is the current one owns the alias, even though it may be deleted
	return &entities[0], nil
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```
