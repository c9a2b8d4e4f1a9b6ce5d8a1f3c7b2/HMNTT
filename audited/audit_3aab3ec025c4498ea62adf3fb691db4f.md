### Title
Unbounded Double-DB-Query and Recoverable Error Log Per Unknown ECDSA secp256k1 Alias Lookup in `EntityIdServiceImpl`

### Summary
In `EntityIdServiceImpl.lookup(AccountID)`, when an `AccountID` carries a non-20-byte alias (e.g., a 35-byte ECDSA secp256k1 protobuf key), the fallback path `.or(() -> findByAliasEvmAddress(alias))` is invoked unconditionally outside the alias cache on every lookup that misses the entity table. This means that for every transaction referencing a non-existent ECDSA alias, the importer executes two sequential DB queries and emits a recoverable error log. An unprivileged attacker who submits transactions with valid-format but unregistered ECDSA secp256k1 aliases can amplify this overhead across the entire record stream, degrading importer throughput.

### Finding Description

**Exact code path:**

In `EntityIdServiceImpl.lookup(AccountID)`:

```java
// EntityIdServiceImpl.java lines 57-62
case ALIAS -> {
    byte[] alias = toBytes(accountId.getAlias());
    yield alias.length == EVM_ADDRESS_LENGTH
            ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
            : cacheLookup(accountId.getAlias(), () -> findByAlias(alias))
                    .or(() -> findByAliasEvmAddress(alias));   // ← always evaluated when empty
}
``` [1](#0-0) 

For a 35-byte ECDSA secp256k1 alias not in the DB:

1. **DB query 1**: `cacheLookup(accountId.getAlias(), () -> findByAlias(alias))` calls `entityRepository.findByAlias(alias)` → returns `Optional.empty()`. The empty result IS cached by Caffeine for the alias key. [2](#0-1) 

2. **Fallback always fires**: Because `.or(supplier)` on `Optional.empty()` always evaluates the supplier, `findByAliasEvmAddress(alias)` is called on **every** lookup of an unknown alias — even after the first miss is cached. [3](#0-2) 

3. Inside `findByAliasEvmAddress`: `aliasToEvmAddress(alias)` performs EC point decompression and a Keccak-256 hash (CPU-intensive). If the alias is a valid ECDSA key, it returns a 20-byte EVM address. [4](#0-3) 

4. **DB query 2**: `cacheLookup(fromBytes(evmAddress), () -> findByEvmAddress(evmAddress))` calls `entityRepository.findByEvmAddress(evmAddress)` → returns `Optional.empty()`. This result is also cached after the first miss. [5](#0-4) 

5. **Error log**: `handleRecoverableError("Entity not found for EVM address {}", ...)` is emitted (first encounter only, since the EVM address result is cached). [6](#0-5) 

**Root cause**: The `.or(() -> findByAliasEvmAddress(alias))` call is placed outside the cache boundary for the original alias key. The cache only prevents re-execution of `findByAlias` (DB query 1), but the entire `findByAliasEvmAddress` path — including EC point decompression, keccak hash, and a second DB query (first time per unique EVM address) — is re-executed on every lookup of any unknown alias.

**Per-call overhead summary**:
- First encounter of a unique alias: 2 DB queries + 1 error log + CPU crypto work
- Repeated lookups of the same alias: 0 DB queries + CPU crypto work (EC decompression + keccak) on every call
- With >100,000 unique aliases: cache eviction (`maximumSize=100000`) causes DB query 1 to repeat as well [7](#0-6) 

### Impact Explanation

The importer processes the full Hedera record stream sequentially, including failed transactions. Each failed transaction referencing a unique non-existent ECDSA secp256k1 alias causes 2 DB queries against the `entity` table plus CPU-intensive cryptographic computation. At scale (thousands of such transactions per record file), this creates measurable DB connection pressure and CPU saturation on the importer process. If `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR=true` (non-default), the first such miss throws a `ParserException` and halts the importer entirely. [8](#0-7) 

### Likelihood Explanation

Any Hedera account holder can submit `CryptoTransfer` or other transactions referencing an `AccountID` by alias. The Hedera network includes failed transactions in the record stream. An attacker generates valid ECDSA secp256k1 key pairs (trivial), computes their 35-byte protobuf aliases, and submits transactions referencing these non-existent aliases. Each transaction costs a small HBAR fee, but the importer-side cost (2 DB queries + crypto work) is disproportionately higher. The Hedera mainnet throttle (~10,000 TPS) bounds the rate, but sustained low-cost spam is feasible. The attack requires no privileged access — only a funded Hedera account.

### Recommendation

Wrap the entire two-step resolution (alias lookup + EVM address fallback) in a single cache entry keyed on the original alias `ByteString`. If the combined result is empty, cache the empty result so that subsequent lookups for the same alias skip both DB queries and the `aliasToEvmAddress` computation entirely:

```java
case ALIAS -> {
    byte[] alias = toBytes(accountId.getAlias());
    yield alias.length == EVM_ADDRESS_LENGTH
            ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
            : cacheLookup(accountId.getAlias(), () ->
                    findByAlias(alias).or(() -> findByAliasEvmAddress(alias)));
}
```

This moves `findByAliasEvmAddress` inside the `cacheLookup` loader so the combined result (including the empty case) is cached under the original alias key, eliminating repeated crypto work and DB queries for the same unknown alias.

### Proof of Concept

1. Generate N unique ECDSA secp256k1 key pairs (e.g., N = 50,000).
2. For each key pair, serialize the public key as a Hedera `Key` protobuf (`ECDSASecp256K1` field, 33 bytes) → 35-byte alias.
3. Submit a `CryptoTransfer` transaction to Hedera mainnet/testnet with the transfer `AccountID` set to `alias = <35-byte-alias>` for a non-existent account. The transaction fails at consensus with `INVALID_ACCOUNT_ID` but is included in the record stream.
4. Observe the mirror node importer: for each such transaction, `EntityIdServiceImpl.lookup` fires `findByAlias` (DB query 1, miss), then `findByAliasEvmAddress` → `aliasToEvmAddress` (EC decompression + keccak) → `findByEvmAddress` (DB query 2, miss) → `handleRecoverableError` log.
5. With 50,000 unique aliases, the importer executes 100,000 extra DB queries and 50,000 error log entries while processing those record files, measurably increasing per-file processing latency. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L55-69)
```java
        return switch (accountId.getAccountCase()) {
            case ACCOUNTNUM -> Optional.ofNullable(EntityId.of(accountId));
            case ALIAS -> {
                byte[] alias = toBytes(accountId.getAlias());
                yield alias.length == EVM_ADDRESS_LENGTH
                        ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
                        : cacheLookup(accountId.getAlias(), () -> findByAlias(alias))
                                .or(() -> findByAliasEvmAddress(alias));
            }
            default -> {
                Utility.handleRecoverableError(
                        "Invalid Account Case for AccountID {}: {}", accountId, accountId.getAccountCase());
                yield Optional.empty();
            }
        };
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L169-178)
```java
    private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
        var id = Optional.ofNullable(DomainUtils.fromEvmAddress(evmAddress))
                .or(() -> entityRepository.findByEvmAddress(evmAddress).map(EntityId::of));

        if (id.isEmpty() && throwRecoverableError) {
            Utility.handleRecoverableError("Entity not found for EVM address {}", Hex.encodeHexString(evmAddress));
        }

        return id;
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L180-182)
```java
    private Optional<EntityId> findByAlias(byte[] alias) {
        return entityRepository.findByAlias(alias).map(EntityId::of);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L184-201)
```java
    // Try to fall back to the 20-byte evm address recovered from the ECDSA secp256k1 alias
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

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L220-231)
```java
    public static void handleRecoverableError(String message, Object... args) {
        var haltOnError = Boolean.parseBoolean(System.getProperty(HALT_ON_ERROR_PROPERTY));

        if (haltOnError) {
            var formattingTuple = MessageFormatter.arrayFormat(message, args);
            var throwable = formattingTuple.getThrowable();
            var formattedMessage = formattingTuple.getMessage();
            throw new ParserException(formattedMessage, throwable);
        } else {
            log.error(RECOVERABLE_ERROR + message, args);
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L233-251)
```java
    // This method is copied from consensus node's EthTxSigs::recoverAddressFromPubKey and should be kept in sync
    @SuppressWarnings("java:S1168")
    private static byte[] recoverAddressFromPubKey(byte[] pubKeyBytes) {
        final var point = EC_DOMAIN_PARAMETERS.getCurve().decodePoint(pubKeyBytes);

        if (!point.isValid()) {
            throw new IllegalArgumentException("Invalid public key: point is not on the secp256k1 curve");
        }

        final var uncompressed = point.normalize().getEncoded(false);
        final var raw64 = Arrays.copyOfRange(uncompressed, 1, 65);

        final var digest = new KeccakDigest(256);
        digest.update(raw64, 0, raw64.length);

        final var hash = new byte[32];
        digest.doFinal(hash, 0);

        return Arrays.copyOfRange(hash, 12, 32);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/config/CacheProperties.java (L19-19)
```java
    private String alias = "maximumSize=100000,expireAfterAccess=30m,recordStats";
```
