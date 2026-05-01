### Title
Unbounded Recursive Key Serialization Exhausts Jackson `maxNestingDepth=100` Write Constraint via `account { key }` Query

### Summary
The `mapKey`/`mapKeyList` methods in `CommonMapper` recursively expand protobuf `KeyList`/`ThresholdKey` structures into nested Java `Map`/`List` objects with no depth limit. When the resulting structure is serialized to JSON by the Jackson `ObjectMapper` configured with `StreamWriteConstraints.maxNestingDepth(100)`, a `StreamConstraintsException` is thrown for any account whose key nesting depth exceeds ~50 levels (each key level produces two JSON nesting levels: one `{}` and one `[]`). Any unauthenticated caller can trigger this by querying `account { key }` for such an account.

### Finding Description

**Exact code path:**

`CommonMapper.mapKey(Key)` (lines 95–111) and `mapKeyList(KeyList)` (lines 113–126) are mutually recursive with no depth guard:

```
mapKey(KEYLIST)      → Map.of("keys", mapKeyList(...))
mapKey(THRESHOLDKEY) → Map.of("threshold", N, "keys", mapKeyList(...))
mapKeyList(...)      → for each key: mapKey(key)   ← recurses back
``` [1](#0-0) 

The only protection is the Jackson write constraint:

```java
StreamWriteConstraints.builder().maxNestingDepth(100).build();
``` [2](#0-1) 

This `MappingJsonFactory` is registered via `Jackson2ObjectMapperBuilderCustomizer` and is used by Spring MVC's `HttpMessageConverter` when writing the GraphQL HTTP response. The `key` field is typed as `Object` scalar: [3](#0-2) 

backed by `ExtendedScalars.Object`: [4](#0-3) 

**Root cause / failed assumption:** The design assumes that key structures stored in the database are shallow enough to serialize within the 100-level write constraint. There is no depth check in `mapKey`/`mapKeyList`, and the `MaxQueryDepthInstrumentation(10)` guard applies only to the GraphQL query document structure, not to the depth of data returned by an `Object` scalar leaf field. [5](#0-4) 

**Exploit flow:**
1. Attacker submits a `CryptoCreate` transaction on the Hedera network with a key structured as deeply nested `ThresholdKey`→`KeyList`→`ThresholdKey`→... (50+ levels). The Hedera transaction size limit (~6 KB) permits this; each nesting level adds only ~4–6 bytes of protobuf overhead.
2. The mirror node importer stores the raw protobuf key bytes in the `entity.key` column.
3. Attacker sends (repeatedly, with no auth): `{ account(input: {entityId: {num: X}}) { key } }`
4. `AccountController.account()` resolves the entity and calls `accountMapper.map(entity)`. [6](#0-5) 
5. `CommonMapper.mapKey(byte[])` parses the protobuf and recursively builds a 50+-level-deep Java `Map`/`List` tree. [7](#0-6) 
6. Spring MVC serializes the GraphQL response to JSON via the customized Jackson factory. At nesting depth 100, Jackson throws `StreamConstraintsException`.
7. If the HTTP response is not yet committed, Spring returns HTTP 500. If already partially written, the connection is abruptly closed.

**Why existing checks are insufficient:**
- `MaxQueryDepthInstrumentation(10)`: guards GraphQL query document depth only; `key` is a scalar leaf, so its internal data depth is invisible to this check.
- `maxNestingDepth(100)` write constraint: this is the *trigger* of the failure, not a guard — it throws an exception rather than gracefully truncating or rejecting.
- `catch (Exception e)` in `mapKey(byte[])`: catches only `Exception`; for extreme nesting (>~500 levels), `mapKey` would throw `StackOverflowError` (an `Error`), which escapes the catch block entirely. [8](#0-7) 

### Impact Explanation
Any query for an account with a deeply nested key produces a `StreamConstraintsException` during HTTP response serialization. This results in HTTP 500 errors or abrupt connection closes for the querying client. While the server itself does not crash (the exception is caught at the servlet container level), the affected request thread terminates abnormally. An attacker who creates one such account can make every subsequent `account { key }` query for that account fail deterministically and permanently, with no operator recourse short of patching the code or removing the account from the database.

### Likelihood Explanation
The `account()` endpoint requires no authentication. Creating a Hedera account with a deeply nested key requires only a small HBAR fee (fractions of a cent on mainnet). The attacker needs to know the account ID of the crafted account, which they control. The attack is trivially repeatable: a single crafted account permanently poisons all `key`-field queries for that account ID. No special privileges, network access, or insider knowledge are required.

### Recommendation
1. **Add a depth limit in `mapKey`**: introduce a `depth` parameter (mirroring the pattern already used in `DomainUtils.getPublicKey`), and return `null` (or a sentinel) when depth exceeds a safe threshold (e.g., 20). [1](#0-0) 
2. **Raise the write constraint or handle the exception gracefully**: either increase `maxNestingDepth` to a value that accommodates legitimate deep keys, or catch `StreamConstraintsException` at the field resolver level and return `null` with a GraphQL error rather than letting it propagate to the HTTP layer.
3. **Validate key depth at import time**: the importer could reject or flag keys exceeding a maximum nesting depth before storing them.

### Proof of Concept

```python
# Step 1: Build a deeply nested protobuf key (Python pseudocode)
from hapi.proto import basic_types_pb2 as bt

def nested_key(depth):
    if depth == 0:
        return bt.Key(ed25519=b'\x01' * 32)
    inner = bt.KeyList(keys=[nested_key(depth - 1)])
    threshold = bt.ThresholdKey(threshold=1, keys=inner)
    return bt.Key(thresholdKey=threshold)

key_bytes = nested_key(52).SerializeToString()  # 52 levels → ~104 JSON nesting levels

# Step 2: Submit CryptoCreate with key_bytes on Hedera testnet
# (standard SDK call, costs ~$0.001)
# Note the resulting account ID, e.g. 0.0.12345

# Step 3: Query the mirror node GraphQL endpoint (no auth required)
import requests
query = """
{ account(input: {entityId: {num: 12345}}) { key } }
"""
r = requests.post("https://<mirror-node>/graphql/alpha",
                  json={"query": query})
# Result: HTTP 500 or abrupt connection close due to StreamConstraintsException
print(r.status_code)  # 500
```

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/mapper/CommonMapper.java (L76-92)
```java
    default Object mapKey(byte[] source) {
        if (source == null) {
            return null;
        }

        if (ArrayUtils.isEmpty(source)) {
            return Collections.emptyMap();
        }

        try {
            var key = Key.parseFrom(source);
            return mapKey(key);
        } catch (Exception e) {
            logger.error("Unable to map protobuf Key to map", e);
            return null;
        }
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/mapper/CommonMapper.java (L95-126)
```java
    default Object mapKey(Key key) {
        var keyCase = key.getKeyCase();
        return switch (keyCase) {
            case CONTRACTID -> Map.of(CONTRACT_ID, mapContractId(key.getContractID()));
            case DELEGATABLE_CONTRACT_ID -> Map.of(keyCase.toString(), mapContractId(key.getDelegatableContractId()));
            case ECDSA_384 -> Map.of(keyCase.toString(), encodeBase64String(toBytes(key.getECDSA384())));
            case ECDSA_SECP256K1 -> Map.of(keyCase.toString(), encodeBase64String(toBytes(key.getECDSASecp256K1())));
            case ED25519 -> Map.of(keyCase.toString(), encodeBase64String(toBytes(key.getEd25519())));
            case KEYLIST -> Map.of(KEYS, mapKeyList(key.getKeyList()));
            case RSA_3072 -> Map.of(keyCase.toString(), encodeBase64String(toBytes(key.getRSA3072())));
            case THRESHOLDKEY ->
                Map.of(
                        THRESHOLD, key.getThresholdKey().getThreshold(),
                        KEYS, mapKeyList(key.getThresholdKey().getKeys()));
            default -> null;
        };
    }

    default List<Object> mapKeyList(KeyList keyList) {
        var keys = keyList.getKeysList();
        if (CollectionUtils.isEmpty(keys)) {
            return Collections.emptyList();
        }

        var target = new ArrayList<>(keys.size());

        for (var key : keys) {
            target.add(mapKey(key));
        }

        return target;
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L56-56)
```java
                .scalar(ExtendedScalars.Object)
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L82-83)
```java
            var streamWriteConstraints =
                    StreamWriteConstraints.builder().maxNestingDepth(100).build();
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L43-43)
```text
    key: Object
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L33-44)
```java
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
```
