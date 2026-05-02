### Title
Missing Entity Type Filter in `GetAccountId` Allows CONTRACT Entities to Be Resolved as Accounts

### Summary
The `selectCurrentCryptoEntityByAlias` SQL query used by `GetAccountId()` in `rosetta/app/persistence/account.go` does not filter on entity `type`, allowing a CONTRACT entity with a matching alias to be returned and treated as an account. Since CONTRACT entities legitimately carry aliases (confirmed by the importer's `EntityIdServiceImpl`), an unprivileged user can submit a contract's alias to the Rosetta API and cause downstream construction operations to treat the contract as a regular account.

### Finding Description

**Exact location:** `rosetta/app/persistence/account.go`, lines 60–61 (`selectCurrentCryptoEntityByAlias`) and lines 138–158 (`GetAccountId`).

The query is:
```sql
select id from entity
where alias = @alias and (deleted is null or deleted is false)
``` [1](#0-0) 

There is no `type in ('ACCOUNT')` predicate. The `GetAccountId` function executes this query and unconditionally returns `types.NewAccountIdFromEntityId(entity.Id)` for whatever entity matches: [2](#0-1) 

**Root cause / failed assumption:** The code assumes that only ACCOUNT entities will have aliases. This assumption is false. The importer's `EntityIdServiceImpl.notify()` explicitly caches CONTRACT entities under their alias: [3](#0-2) 

This means the `entity` table can contain rows with `type = 'CONTRACT'`, a non-null `alias`, and `deleted is null`, which the query will happily return.

**Contrast with the historical/balance query:** `selectCryptoEntityById` (used in `getCryptoEntity`) correctly restricts to `type in ('ACCOUNT', 'CONTRACT')`, but even that does not distinguish contracts from accounts. `selectCurrentCryptoEntityByAlias` has no type restriction at all. [4](#0-3) 

**Exploit flow:**
1. Attacker identifies a live CONTRACT entity in the mirror DB that has an alias set and `deleted is null`.
2. Attacker submits a Rosetta `/construction/preprocess` (or any endpoint that calls `GetAccountId`) with the contract's alias as the `AccountIdentifier.Address` (hex-encoded alias, prefixed with `0x`).
3. `GetAccountId` resolves the alias via `selectCurrentCryptoEntityByAlias`, gets the contract's `id`, and returns it wrapped as an `AccountId`.
4. The construction service uses this `AccountId` to build a transaction that designates the contract as a payer or participant, producing a malformed transaction body that references a smart contract where an account is expected. [5](#0-4) 

### Impact Explanation
The Rosetta construction pipeline will construct and potentially submit transactions that reference a smart contract entity as if it were a regular account. This produces unintended smart contract behavior at the network layer: the consensus node receives a `CryptoTransfer` (or similar) whose payer/sender is a contract ID, which is semantically invalid and may trigger unexpected contract execution paths or transaction failures. No direct fund loss occurs (the mirror node does not hold keys), but the integrity of the Rosetta construction flow is broken and the behavior of the target contract on-chain is unpredictable.

### Likelihood Explanation
The precondition — a CONTRACT entity with a non-null alias in the `entity` table — is a normal, expected state for any EVM-compatible contract deployed on Hedera (contracts created via `CREATE2` or with an explicit alias). No privileged access is required; the Rosetta API is public. The attacker only needs to know (or enumerate) a contract's alias, which is derivable from on-chain data. The attack is fully repeatable.

### Recommendation
Add a `type = 'ACCOUNT'` predicate to `selectCurrentCryptoEntityByAlias`:

```sql
select id from entity
where alias = @alias
  and type = 'ACCOUNT'
  and (deleted is null or deleted is false)
``` [1](#0-0) 

Additionally, after the DB lookup in `GetAccountId`, validate that the returned entity's `Type` field equals `domain.EntityTypeAccount` before returning its ID, providing defense-in-depth. [6](#0-5) 

### Proof of Concept
1. Identify a CONTRACT row in the `entity` table: `SELECT id, alias FROM entity WHERE type = 'CONTRACT' AND alias IS NOT NULL AND (deleted IS NULL OR deleted = false) LIMIT 1;`
2. Hex-encode the `alias` bytes and prefix with `0x`, e.g. `0x<hex_alias>`.
3. Send a Rosetta request:
```json
POST /construction/preprocess
{
  "network_identifier": { ... },
  "operations": [{
    "operation_identifier": {"index": 0},
    "type": "CRYPTO_TRANSFER",
    "account": { "address": "0x<hex_alias>" },
    "amount": { "value": "-1", "currency": { "symbol": "HBAR", "decimals": 8 } }
  }]
}
```
4. Observe that `GetAccountId` resolves the alias to the contract's numeric EntityId and the construction service proceeds to build a transaction treating the contract as the sending account, producing unintended smart contract behavior.

### Citations

**File:** rosetta/app/persistence/account.go (L60-61)
```go
	selectCurrentCryptoEntityByAlias = `select id from entity
                                 where alias = @alias and (deleted is null or deleted is false)`
```

**File:** rosetta/app/persistence/account.go (L62-72)
```go
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
```

**File:** rosetta/app/persistence/account.go (L149-158)
```go
	var entity domain.Entity
	if err := db.Raw(selectCurrentCryptoEntityByAlias, sql.Named("alias", accountId.GetAlias())).First(&entity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return zero, hErrors.ErrAccountNotFound
		}

		return zero, hErrors.ErrDatabaseError
	}

	return types.NewAccountIdFromEntityId(entity.Id), nil
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L159-161)
```java
            }
            case CONTRACT -> cache.put(alias, entityId);
            default -> Utility.handleRecoverableError("Invalid Entity: {} entity can't have alias", type);
```

**File:** rosetta/app/services/construction_service.go (L44-51)
```go
type constructionAPIService struct {
	BaseService
	accountRepo        interfaces.AccountRepository
	sdkClient          *hiero.Client
	systemShard        int64
	systemRealm        int64
	transactionHandler construction.TransactionConstructor
}
```

**File:** rosetta/app/persistence/domain/entity.go (L7-9)
```go
const (
	EntityTypeAccount = "ACCOUNT"

```
