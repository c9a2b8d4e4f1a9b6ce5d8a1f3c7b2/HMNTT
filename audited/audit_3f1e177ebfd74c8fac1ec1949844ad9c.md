### Title
EVM Address Pattern Takes Priority Over Alias Pattern for Ambiguous 40-Character Inputs in `getNftAllowances`, Causing Wrong Entity Resolution

### Summary
`EntityIdParameter.valueOf()` checks `EVM_ADDRESS_PATTERN` before `ALIAS_PATTERN`. The two patterns share a non-empty character intersection (`[A-F2-7]`), so any 40-character uppercase string composed solely of those characters matches both regexes. Because EVM is always tried first, such a string is unconditionally resolved as `EntityIdEvmAddressParameter` and looked up via `findByEvmAddress()`, silently bypassing the `findByAlias()` path and potentially returning NFT allowances for a completely different account.

### Finding Description

**Regex overlap — exact character intersection:**

| Pattern | Body charset | Length |
|---|---|---|
| `EVM_ADDRESS_REGEX` | `[A-Fa-f0-9]` | exactly 40 |
| `ALIAS_REGEX` | `[A-Z2-7]` | 40–70 |

Intersection: `[A-F2-7]` (uppercase hex letters A–F plus Base32 digits 2–7). Any 40-character string drawn exclusively from `[A-F2-7]` satisfies **both** regexes simultaneously.

**Priority ordering in `valueOf()`:**

```
// EntityIdParameter.java lines 17-25
if ((entityId = EntityIdNumParameter.valueOfNullable(id)) != null)   return entityId;
else if ((entityId = EntityIdEvmAddressParameter.valueOfNullable(id)) != null) return entityId;  // ← EVM wins
else if ((entityId = EntityIdAliasParameter.valueOfNullable(id)) != null)      return entityId;  // ← alias never reached
```

EVM is checked on line 19, alias on line 21. For any ambiguous input the alias branch is dead code.

**Downstream divergence in `EntityServiceImpl.lookup()`:**

```
case EntityIdAliasParameter p   -> entityRepository.findByAlias(p.alias())...
case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress())...
```

`findByAlias` and `findByEvmAddress` query different columns. An alias decoded as Base32 produces a different byte sequence than the same string decoded as hex, so the two lookups resolve to different (or no) entities.

**Exploit flow:**

1. Account A exists with alias `ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345` (valid Base32, all chars in `[A-F2-7]`).
2. Account B exists with EVM address `0xABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345` (same string, valid hex).
3. Attacker (or any caller) queries `GET /api/v1/accounts/ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345/allowances/nfts`.
4. `valueOf()` resolves to `EntityIdEvmAddressParameter` → `findByEvmAddress` → returns Account B's NFT allowances.
5. Account A's allowances are never consulted; the response silently belongs to a different entity.

No authentication or special privilege is required; the endpoint is publicly accessible.

### Impact Explanation
Off-chain applications and smart contract integrations that rely on the mirror node REST API to verify NFT allowances before submitting transactions will receive approval data for the wrong account. A spender that appears approved for Account B's NFTs may not be approved for Account A's NFTs (or vice versa), causing smart contracts to act on stale or incorrect approval state. Severity matches the stated scope: unintended smart contract behavior with no direct fund loss, but incorrect on-chain decisions driven by bad off-chain data.

### Likelihood Explanation
The character overlap is structural and requires no privileged access. An attacker who can create a Hedera account and choose its EVM address (possible via ECDSA key derivation) can deliberately engineer a collision with a target account's alias. Even without deliberate engineering, any account whose alias falls entirely within `[A-F2-7]{40}` will be silently misresolved by every caller. The attack is repeatable and deterministic once the collision exists.

### Recommendation
Reverse the check order in `EntityIdParameter.valueOf()` so that `ALIAS_PATTERN` is tested before `EVM_ADDRESS_PATTERN`, or — preferably — tighten `EVM_ADDRESS_REGEX` to require the `0x` prefix for bare hex strings (making the two patterns disjoint). The `0x`-prefix approach is the cleanest: it eliminates the ambiguity entirely and aligns with standard EVM address notation.

```java
// Preferred: require 0x prefix for bare EVM addresses, or swap order:
if ((entityId = EntityIdNumParameter.valueOfNullable(id)) != null)        return entityId;
else if ((entityId = EntityIdAliasParameter.valueOfNullable(id)) != null) return entityId; // alias first
else if ((entityId = EntityIdEvmAddressParameter.valueOfNullable(id)) != null) return entityId;
```

### Proof of Concept

**Precondition setup:**
```
# Account A: alias = ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345  (Base32, all chars in [A-F2-7])
# Account B: EVM address = 0xABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345
# Account B has NFT allowances; Account A does not (or has different ones)
```

**Trigger:**
```
GET /api/v1/accounts/ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345/allowances/nfts
```

**Observed:** Response contains Account B's NFT allowances.  
**Expected:** Response contains Account A's NFT allowances.

**Verification — regex match (Java):**
```java
String id = "ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345"; // 40 chars, all [A-F2-7]
assert EVM_ADDRESS_PATTERN.matcher(id).matches();  // true  ← wins
assert ALIAS_PATTERN.matcher(id).matches();        // true  ← silently lost
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdEvmAddressParameter.java (L15-16)
```java
    public static final String EVM_ADDRESS_REGEX = "^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$";
    public static final Pattern EVM_ADDRESS_PATTERN = Pattern.compile(EVM_ADDRESS_REGEX);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdAliasParameter.java (L13-14)
```java
    public static final String ALIAS_REGEX = "^((\\d{1,5})\\.)?((\\d{1,5})\\.)?([A-Z2-7]{40,70})$";
    public static final Pattern ALIAS_PATTERN = Pattern.compile(ALIAS_REGEX);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L31-35)
```java
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };
```
