All the referenced code is confirmed. Let me verify the regex overlap precisely before rendering a verdict.

**EVM_ADDRESS_REGEX** (line 15, `EntityIdEvmAddressParameter.java`): `[A-Fa-f0-9]{40}` — accepts uppercase A–F, lowercase a–f, digits 0–9.

**ALIAS_REGEX** (line 13, `EntityIdAliasParameter.java`): `[A-Z2-7]{40,70}` — accepts uppercase A–Z, digits 2–7.

Character intersection: `{A,B,C,D,E,F} ∪ {2,3,4,5,6,7}` = `[A-F2-7]`. Any 40-character string drawn exclusively from this set satisfies **both** regexes simultaneously.

Priority in `valueOf()` (lines 17–22, `EntityIdParameter.java`): EVM is tried on line 19, alias on line 21. For any ambiguous input the alias branch is unreachable.

Downstream divergence in `EntityServiceImpl.lookup()` (lines 33–34): `findByAlias()` vs `findByEvmAddress()` query different columns and decode the same byte string differently (Base32 vs hex), producing different entity lookups.

---

Audit Report

## Title
EVM Address Pattern Takes Priority Over Alias Pattern for Ambiguous 40-Character Inputs in `valueOf()`, Causing Wrong Entity Resolution

## Summary
`EntityIdParameter.valueOf()` checks `EVM_ADDRESS_PATTERN` before `ALIAS_PATTERN`. The two patterns share a non-empty character intersection (`[A-F2-7]`), so any 40-character uppercase string composed solely of those characters matches both regexes. Because EVM is always tried first, such a string is unconditionally resolved as `EntityIdEvmAddressParameter` and looked up via `findByEvmAddress()`, silently bypassing the `findByAlias()` path and potentially returning data for a completely different account.

## Finding Description

**Regex overlap — exact character intersection:**

| Pattern | Body charset | Length |
|---|---|---|
| `EVM_ADDRESS_REGEX` | `[A-Fa-f0-9]` | exactly 40 |
| `ALIAS_REGEX` | `[A-Z2-7]` | 40–70 |

Intersection: `[A-F2-7]`. Any 40-character string drawn exclusively from this set satisfies both regexes simultaneously.

**Root cause — priority ordering in `valueOf()`:**

In `EntityIdParameter.java` lines 17–22: [1](#0-0) 

EVM is checked on line 19, alias on line 21. For any ambiguous 40-character input from `[A-F2-7]`, the alias branch is dead code.

**Downstream divergence in `EntityServiceImpl.lookup()`:** [2](#0-1) 

`findByAlias()` decodes the input as Base32 and queries the `alias` column; `findByEvmAddress()` decodes the same string as hex and queries the `evm_address` column. The two decodings of the same 40-character string produce different byte sequences, resolving to different (or no) entities.

**Regex definitions confirmed:** [3](#0-2) [4](#0-3) 

## Impact Explanation
Off-chain applications and smart contract integrations that rely on the mirror node REST API to verify NFT allowances (or any account-scoped data) before submitting transactions will receive data for the wrong account. A spender that appears approved for Account B's NFTs may not be approved for Account A's NFTs (or vice versa), causing smart contracts to act on stale or incorrect approval state. The mirror node is a read-only data source, so there is no direct fund loss, but incorrect on-chain decisions driven by bad off-chain data are a realistic consequence.

## Likelihood Explanation
The character overlap is structural and requires no privileged access. An attacker who can influence account creation (possible via ECDSA key derivation, which deterministically maps a private key to an EVM address) can engineer a collision with a target account's alias. Any account whose alias falls entirely within `[A-F2-7]{40}` will be silently misresolved by every caller querying by that alias string. The attack is repeatable and deterministic once the collision exists.

## Recommendation
Disambiguate the two patterns so they have no overlap at exactly 40 characters. The simplest approach is to require the alias path to be explicitly prefixed (e.g., require a shard/realm prefix for alias inputs that are exactly 40 characters), or to check alias before EVM address in `valueOf()` and rely on the fact that valid EVM addresses can always be prefixed with `0x` to force unambiguous resolution. Alternatively, tighten `ALIAS_REGEX` to reject lengths that are also valid EVM address lengths (i.e., require `{41,70}` or `{52,70}` to match only realistic key-derived alias lengths), or tighten `EVM_ADDRESS_REGEX` to require the `0x` prefix for bare 40-character inputs.

## Proof of Concept

1. Account A is created on Hedera with alias `ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345` (40 chars, all from `[A-F2-7]`, valid Base32).
2. Account B is created with EVM address `0xABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345` (same string, valid hex).
3. Caller queries `GET /api/v1/accounts/ABCDEF2345ABCDEF2345ABCDEF2345ABCDEF2345/allowances/nfts` intending to look up Account A.
4. `EntityIdParameter.valueOf()` calls `EntityIdEvmAddressParameter.valueOfNullable()` first (line 19); the string matches `EVM_ADDRESS_REGEX`; returns `EntityIdEvmAddressParameter`.
5. `EntityServiceImpl.lookup()` dispatches to `findByEvmAddress()` (line 34), returning Account B's entity ID.
6. Account A's NFT allowances are never consulted; the response silently belongs to Account B.

No authentication or special privilege is required; the endpoint is publicly accessible. [5](#0-4) [6](#0-5)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L31-35)
```java
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };
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
