### Title
Missing Long-Zero EVM Address Optimization in `rest-java` `EntityServiceImpl` Causes Unnecessary DB Queries

### Summary
The `rest-java` `EntityServiceImpl.lookup()` unconditionally calls `findByEvmAddress()` for any `EntityIdEvmAddressParameter`, including long-zero format addresses that encode a valid `shard.realm.num`. Unlike the `graphql` module's `EntityServiceImpl`, which detects long-zero addresses and routes to the cheaper `findById()` primary-key lookup, the REST Java service always issues a secondary index query against the `entity.evm_address` column. Because entities do not store their long-zero address in the `evm_address` column, these queries always return empty, making every such request a wasted DB round-trip that any unauthenticated caller can trigger at will.

### Finding Description

**Parsing path — why long-zero addresses become `EntityIdEvmAddressParameter`:**

`EntityIdParameter.valueOf()` tries three parsers in order: [1](#0-0) 

`EntityIdNumParameter` uses regex `^((\\d{1,4})\\.)?((\\d{1,5})\\.)?(\\d{1,12})$` — the `num` group accepts at most 12 decimal digits. [2](#0-1) 

A long-zero EVM address such as `0000000000000000000000000000000000000001` is 40 characters — far exceeding the 12-digit limit — so it **never** matches `EntityIdNumParameter`. It then matches `EntityIdEvmAddressParameter` via its 40-hex-char regex: [3](#0-2) 

No long-zero detection is performed here; the raw bytes are stored as-is.

**Service layer — missing branch:**

`EntityServiceImpl.lookup()` dispatches on the parameter type: [4](#0-3) 

For `EntityIdEvmAddressParameter` it always calls `findByEvmAddress()`: [5](#0-4) 

**Contrast with the `graphql` module**, which correctly detects long-zero format (first 4 bytes shard = 0, next 8 bytes realm = 0) and routes to `findById()`: [6](#0-5) 

**Why `findByEvmAddress()` always misses for long-zero addresses:**

The `entity.evm_address` column stores the *actual* EVM address assigned to an entity (e.g., from an ECDSA alias). Entities that only have a numeric ID never have their long-zero address written into `evm_address`; that column is `NULL` for them. The index is a partial index on non-null values: [7](#0-6) 

So `SELECT id FROM entity WHERE evm_address = <long-zero-bytes> AND deleted <> true` will always return zero rows, confirmed by the `lookupNotFound` integration test: [8](#0-7) 

Every such request wastes one index-scan DB round-trip and returns HTTP 404.

**Root cause:** `EntityIdEvmAddressParameter.valueOfNullable()` does not call `DomainUtils.isLongZeroAddress()` / `DomainUtils.fromEvmAddress()` to detect and convert long-zero addresses into `EntityIdNumParameter`, and `EntityServiceImpl.lookup()` has no compensating check. [9](#0-8) 

### Impact Explanation
Every GET `/api/v1/accounts/<long-zero-evm-address>` request causes one unnecessary partial-index scan on the `entity` table that always returns empty. A `findById()` primary-key lookup would be cheaper and would actually find the entity. At sustained high request rates from one or more unauthenticated callers, the cumulative DB load from these wasted index scans can degrade mirror-node query throughput. Because the endpoint is public and requires no credentials, the attacker surface is the entire internet.

### Likelihood Explanation
No authentication, API key, or privileged access is required. Long-zero EVM addresses are well-known (they are the canonical on-chain representation of any `shard.realm.num` account) and trivially enumerable. An attacker can generate valid-looking long-zero addresses for any account number and flood the endpoint. The exploit is deterministic and repeatable with standard HTTP tooling.

### Recommendation
In `EntityIdEvmAddressParameter.valueOfNullable()` (or in `EntityServiceImpl.lookup()`), call `DomainUtils.isLongZeroAddress()` on the decoded bytes. If it returns `true`, extract the entity num via `DomainUtils.fromEvmAddress()` and return an `EntityIdNumParameter` instead, mirroring the logic already present in the `graphql` `EntityServiceImpl`:

```java
// In EntityIdEvmAddressParameter.valueOfNullable() or EntityServiceImpl.lookup():
var entityId = DomainUtils.fromEvmAddress(evmAddress);
if (entityId != null) {
    return new EntityIdNumParameter(entityId); // routes to findById()
}
```

Alternatively, add the check directly in `EntityServiceImpl.lookup()`:

```java
case EntityIdEvmAddressParameter p -> {
    var entityId = DomainUtils.fromEvmAddress(p.evmAddress());
    yield entityId != null
        ? Optional.of(entityId)
        : entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
}
```

### Proof of Concept

1. Pick any valid account number, e.g. `1000` (decimal = `0x3E8`).
2. Construct its long-zero EVM address: 12 zero bytes + 8-byte big-endian num = `00000000000000000000000000000000000003e8` (40 hex chars).
3. Send: `GET /api/v1/accounts/0x00000000000000000000000000000000000003e8`
4. Observe: the server issues `SELECT id FROM entity WHERE evm_address = '\x00000000000000000000000000000000000003e8' AND deleted <> true` — returns empty — responds HTTP 404, even though account `0.0.1000` exists.
5. A direct numeric lookup `GET /api/v1/accounts/0.0.1000` would use `findById(1000)` (primary key) and succeed.
6. Repeat step 3 in a tight loop (e.g., `ab -n 100000 -c 100`) with varying account numbers to generate sustained unnecessary index-scan load on the DB.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdParameter.java (L17-25)
```java
        if ((entityId = EntityIdNumParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else if ((entityId = EntityIdEvmAddressParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else if ((entityId = EntityIdAliasParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else {
            throw new IllegalArgumentException("Unsupported ID format");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdNumParameter.java (L12-13)
```java
    private static final String ENTITY_ID_REGEX = "^((\\d{1,4})\\.)?((\\d{1,5})\\.)?(\\d{1,12})$";
    private static final Pattern ENTITY_ID_PATTERN = Pattern.compile(ENTITY_ID_REGEX);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdEvmAddressParameter.java (L15-39)
```java
    public static final String EVM_ADDRESS_REGEX = "^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$";
    public static final Pattern EVM_ADDRESS_PATTERN = Pattern.compile(EVM_ADDRESS_REGEX);

    @SneakyThrows(DecoderException.class)
    static @Nullable EntityIdEvmAddressParameter valueOfNullable(String id) {
        var evmMatcher = EVM_ADDRESS_PATTERN.matcher(id);

        if (!evmMatcher.matches()) {
            return null;
        }

        var properties = CommonProperties.getInstance();
        long shard = properties.getShard();
        long realm = properties.getRealm();
        String realmString;

        if ((realmString = evmMatcher.group(5)) != null) {
            realm = Long.parseLong(realmString);
            shard = Long.parseLong(evmMatcher.group(3));
        } else if ((realmString = evmMatcher.group(3)) != null) {
            realm = Long.parseLong(realmString);
        }

        var evmAddress = Hex.decodeHex(evmMatcher.group(6));
        return new EntityIdEvmAddressParameter(shard, realm, evmAddress);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql (L112-112)
```sql
create index if not exists entity__evm_address on entity (evm_address) where evm_address is not null;
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/service/EntityServiceTest.java (L54-63)
```java
    @ParameterizedTest
    @ValueSource(
            strings = {
                "0.0.000000000000000000000000000000000186Fb1b",
                "0.0.HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA",
            })
    void lookupNotFound(String id) {
        var entityIdParameter = EntityIdParameter.valueOf(id);
        assertThatThrownBy(() -> service.lookup(entityIdParameter)).isInstanceOf(EntityNotFoundException.class);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java (L285-297)
```java
    public static EntityId fromEvmAddress(byte[] evmAddress) {
        final var commonProperties = CommonProperties.getInstance();

        try {
            if (isLongZeroAddress(evmAddress)) {
                final var num = Longs.fromByteArray(Arrays.copyOfRange(evmAddress, 12, 20));
                return EntityId.of(commonProperties.getShard(), commonProperties.getRealm(), num);
            }
        } catch (InvalidEntityException ex) {
            log.debug("Failed to parse long zero evm address into EntityId", ex);
        }
        return null;
    }
```
