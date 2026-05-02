### Title
Unbounded Repeated EC Crypto Work and Double DB Queries via ECDSA Alias Lookups in EntityIdServiceImpl

### Summary
In `EntityIdServiceImpl.lookup()`, when an `AccountID` carries a non-20-byte alias (e.g., a 35-byte ECDSA secp256k1 public key), the code first calls `cacheLookup → findByAlias` (DB query 1), then unconditionally chains `.or(() -> findByAliasEvmAddress(alias))`. The fallback `findByAliasEvmAddress` is never cached under the original alias key, so `aliasToEvmAddress()` — which performs protobuf parsing, EC point decompression, and Keccak-256 hashing — executes on **every** lookup of a non-existent ECDSA alias, even after the alias is cached as empty. For each unique alias, two DB queries are also triggered on first encounter (and again after cache eviction).

### Finding Description

**Exact code path:**

`EntityIdServiceImpl.java` lines 57–62:
```java
case ALIAS -> {
    byte[] alias = toBytes(accountId.getAlias());
    yield alias.length == EVM_ADDRESS_LENGTH
            ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
            : cacheLookup(accountId.getAlias(), () -> findByAlias(alias))
                    .or(() -> findByAliasEvmAddress(alias));   // ← NOT cached under alias key
}
``` [1](#0-0) 

`findByAliasEvmAddress` lines 185–201:
```java
private Optional<EntityId> findByAliasEvmAddress(byte[] alias) {
    var evmAddress = aliasToEvmAddress(alias);   // EC decompression + Keccak every call
    ...
    return cacheLookup(fromBytes(evmAddress), () -> findByEvmAddress(evmAddress));  // DB query 2
}
``` [2](#0-1) 

`aliasToEvmAddress` in `Utility.java` lines 64–92 performs `Key.parseFrom(alias)`, `EC_DOMAIN_PARAMETERS.getCurve().decodePoint(pubKeyBytes)`, and a full Keccak-256 digest: [3](#0-2) 

**Root cause:** `cacheLookup` at line 61 stores the result of `findByAlias` under `accountId.getAlias()`. When the alias is absent from the entity table, it caches `Optional.empty()`. On every subsequent call with the same alias, `cacheLookup` returns the cached empty — but `.or()` is evaluated unconditionally on an empty Optional, so `findByAliasEvmAddress` (and thus `aliasToEvmAddress`) is invoked again. The combined result of the two-step lookup is never stored under the original alias key.

**DB query behavior:**
- **First lookup of each unique alias**: 2 DB queries (`findByAlias` + `findByEvmAddress`)
- **Repeated lookups of the same alias**: 0 DB queries, but `aliasToEvmAddress` CPU work runs every time
- **After cache eviction** (cache is `maximumSize=100000,expireAfterAccess=30m`): 2 DB queries again per alias [4](#0-3) 

**Failed assumption:** The cache is assumed to prevent all repeated work for a previously-seen alias. It prevents repeated DB queries but not the EC crypto work in `aliasToEvmAddress`.

### Impact Explanation
Every CryptoTransfer transaction that references a non-existent account by a 35-byte ECDSA secp256k1 alias forces the importer to perform EC point decompression and Keccak-256 hashing on every processing pass. With many unique aliases, each also triggers two DB queries on first encounter. An attacker submitting a sustained stream of such transactions can amplify importer CPU and DB load proportional to the volume of alias-bearing transactions, degrading processing throughput for all legitimate transactions. The alias cache holds at most 100,000 entries; an attacker with more than 100,000 unique aliases causes continuous cache eviction and re-triggers the full two-DB-query path indefinitely.

### Likelihood Explanation
Any Hedera account holder (no special privileges required) can submit CryptoTransfer transactions referencing arbitrary aliases. Generating valid ECDSA secp256k1 public keys is computationally trivial. The primary cost to the attacker is HBAR transaction fees and the network's per-account TPS throttle. Failed transactions (referencing non-existent accounts) are still included in the consensus record stream and processed by the importer. The attack is repeatable and sustained as long as the attacker can afford fees.

### Recommendation
Cache the combined result of the two-step lookup under the original alias key. Specifically, wrap the entire `.or(() -> findByAliasEvmAddress(alias))` chain inside a single `cacheLookup` call so that a "not found" result for an ECDSA alias is stored and prevents re-execution of `aliasToEvmAddress` on subsequent lookups:

```java
cacheLookup(accountId.getAlias(), () ->
    findByAlias(alias).or(() -> findByAliasEvmAddress(alias))
)
```

This ensures `aliasToEvmAddress` is called at most once per unique alias per cache TTL window, eliminating the repeated EC crypto work.

### Proof of Concept
1. Generate N unique ECDSA secp256k1 key pairs (trivial with any crypto library).
2. Serialize each public key as a 35-byte Hedera `Key` protobuf (`0x3a21` prefix + 33-byte compressed key).
3. Submit CryptoTransfer transactions to the Hedera network, each referencing a different non-existent account by one of these aliases (the transactions will fail consensus-side but will be included in the record stream).
4. Observe the importer processing these records: for each transaction, `EntityIdServiceImpl.lookup()` is called, `findByAlias` returns empty (DB query 1), then `findByAliasEvmAddress` runs `aliasToEvmAddress` (EC decompression + Keccak) and `findByEvmAddress` (DB query 2).
5. For repeated transactions using the same alias: DB queries are avoided by cache, but `aliasToEvmAddress` still executes on every call.
6. For N > 100,000 unique aliases: cache eviction causes the full two-DB-query path to repeat continuously.
7. Monitor importer CPU and DB query rate; both increase proportionally to the volume of alias-bearing transactions submitted.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L57-62)
```java
            case ALIAS -> {
                byte[] alias = toBytes(accountId.getAlias());
                yield alias.length == EVM_ADDRESS_LENGTH
                        ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
                        : cacheLookup(accountId.getAlias(), () -> findByAlias(alias))
                                .or(() -> findByAliasEvmAddress(alias));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L185-201)
```java
    private Optional<EntityId> findByAliasEvmAddress(byte[] alias) {
        var evmAddress = aliasToEvmAddress(alias);
        if (evmAddress == null) {
            Utility.handleRecoverableError("Unable to find entity for alias {}", Hex.encodeHexString(alias));
            return Optional.empty();
        }

        if (log.isDebugEnabled()) {
            log.debug(
                    "Trying to find entity by evm address {} recovered from public key alias {}",
                    Hex.encodeHexString(evmAddress),
                    Hex.encodeHexString(alias));
        }

        // Check cache first in case the 20-byte evm address hasn't persisted to db
        return cacheLookup(fromBytes(evmAddress), () -> findByEvmAddress(evmAddress));
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L64-92)
```java
    public static byte[] aliasToEvmAddress(byte[] alias) {
        if (alias == null
                || alias.length != DomainUtils.EVM_ADDRESS_LENGTH
                        && alias.length < ECDSA_SECP256K1_COMPRESSED_KEY_LENGTH) {
            return null;
        }

        if (alias.length == DomainUtils.EVM_ADDRESS_LENGTH) {
            return alias;
        }

        byte[] evmAddress = null;
        try {
            var key = Key.parseFrom(alias);
            if (key.getKeyCase() == Key.KeyCase.ECDSA_SECP256K1
                    && key.getECDSASecp256K1().size() == ECDSA_SECP256K1_COMPRESSED_KEY_LENGTH) {
                byte[] rawCompressedKey = DomainUtils.toBytes(key.getECDSASecp256K1());
                evmAddress = recoverAddressFromPubKey(rawCompressedKey);
                if (evmAddress == null) {
                    log.warn("Unable to recover EVM address from {}", Hex.encodeHexString(rawCompressedKey));
                }
            }
        } catch (Exception e) {
            var aliasHex = Hex.encodeHexString(alias);
            handleRecoverableError("Unable to decode alias to EVM address: {}", aliasHex, e);
        }

        return evmAddress;
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/config/CacheProperties.java (L19-19)
```java
    private String alias = "maximumSize=100000,expireAfterAccess=30m,recordStats";
```
