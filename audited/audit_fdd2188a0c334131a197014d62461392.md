I have now read all the relevant code. Let me synthesize the findings.

**Key code paths examined:**

- `OpcodeServiceImpl.getEntityAddress()` (lines 236–244): priority evmAddress > alias > entityId
- `OpcodeServiceImpl.getSenderAddress()` (lines 177–180): calls `commonEntityAccessor.evmAddressFromId(..., Optional.empty())`
- `OpcodeServiceImpl.getReceiverAddress()` (lines 182–205): calls `commonEntityAccessor.get(address, Optional.empty())` then `getEntityAddress(entity)` for long-zero addresses
- `CommonEntityAccessor.evmAddressFromId()` (lines 86–107): same priority, uses current DB state when timestamp is `Optional.empty()`

The `Optional.empty()` in both `getSenderAddress()` and `getReceiverAddress()` means **current entity state** is used, not the historical state at the time of the original transaction. The `consensusTimestamp` is available in `buildCallServiceParameters()` but is never passed to these address-resolution calls.

---

### Title
Stale Entity State in `getEntityAddress()` Causes Replay `msg.sender` to Diverge from Original Transaction

### Summary
`OpcodeServiceImpl.getSenderAddress()` and `getReceiverAddress()` resolve entity addresses using the **current** database state (`Optional.empty()` timestamp) rather than the entity state at the original transaction's `consensusTimestamp`. Because `getEntityAddress()` applies the priority `evmAddress > alias > entityId`, if a sender entity had only a 20-byte alias at the time of the original transaction but later had an explicit `evmAddress` added, the replay sets a different `msg.sender` than the original execution, producing a divergent opcode trace visible to any unprivileged caller.

### Finding Description
**Exact code path:**

`OpcodeServiceImpl.getSenderAddress()` (line 178):
```java
final var address = commonEntityAccessor.evmAddressFromId(
    contractResult.getSenderId(), Optional.empty());   // ← no timestamp
``` [1](#0-0) 

`CommonEntityAccessor.evmAddressFromId()` with `Optional.empty()` falls through to `findByIdAndDeletedIsFalse()` (current state) and then applies:
```java
if (entity.getEvmAddress() != null) {          // priority 1
    return Address.wrap(...entity.getEvmAddress()...);
}
if (entity.getAlias() != null && entity.getAlias().length == EVM_ADDRESS_LENGTH) {  // priority 2
    return Address.wrap(...entity.getAlias()...);
}
return toAddress(entityId);                    // priority 3
``` [2](#0-1) 

`getReceiverAddress()` has the same flaw for long-zero `toAddress` values:
```java
final var entity = commonEntityAccessor.get(address, Optional.empty()).orElse(null);
if (entity != null) {
    return getEntityAddress(entity);   // uses current evmAddress, not historical
}
``` [3](#0-2) 

**Root cause / failed assumption:** The code assumes an entity's `evmAddress` and `alias` are immutable after creation. In practice, Hedera allows an `evmAddress` to be set on an account after creation (e.g., via `CryptoUpdate` or first Ethereum transaction from that account). The `consensusTimestamp` is already a local variable in `buildCallServiceParameters()` but is never forwarded to address-resolution helpers. [4](#0-3) 

**Exploit flow:**
1. Account `0.0.5000` is created with a 20-byte ECDSA alias `0xAAAA…` and no explicit `evmAddress`. A Hedera `ContractCall` transaction T1 is executed; the EVM sets `msg.sender = 0xAAAA…` (alias path). The contract stores `owner = msg.sender`.
2. Later, account `0.0.5000` receives an explicit `evmAddress = 0xBBBB…` (different bytes).
3. Any unprivileged user calls `GET /api/v1/contracts/results/T1/opcodes`.
4. `getSenderAddress()` fetches the entity's **current** state, finds `evmAddress = 0xBBBB…`, and returns `0xBBBB…` as the sender.
5. The replay EVM sees `msg.sender = 0xBBBB…`. If the contract has `require(msg.sender == owner)`, the replay reverts — the original succeeded. The opcode trace shown is fabricated relative to the real execution.

### Impact Explanation
The opcodes endpoint is the authoritative debugging and audit surface for historical EVM execution. A divergent replay can:
- Show a transaction as **failed** when it originally **succeeded** (or vice versa), misleading security auditors and incident responders.
- Produce a completely different opcode sequence and storage-change trace, making forensic analysis of exploits unreliable.
- Be triggered deterministically and repeatably by any unauthenticated caller once the precondition (entity evmAddress added post-transaction) exists on-chain.

The impact is classified as "reorganizing visible execution history without direct fund theft."

### Likelihood Explanation
- No authentication or privilege is required; the endpoint is public.
- The precondition (entity gaining an `evmAddress` after a historical contract call) is a normal Hedera lifecycle event (e.g., account first sends an Ethereum transaction, triggering lazy creation of `evmAddress`).
- The attacker needs only a valid transaction ID or hash, which is public on-chain data.
- The condition is permanent once it exists; the divergence is reproducible on every call.

### Recommendation
Pass the historical `consensusTimestamp` to both address-resolution helpers instead of `Optional.empty()`:

```java
// getSenderAddress — add timestamp parameter
private Address getSenderAddress(ContractResult contractResult, long consensusTimestamp) {
    return commonEntityAccessor.evmAddressFromId(
        contractResult.getSenderId(), Optional.of(consensusTimestamp));
}

// getReceiverAddress — same change for the entity lookup
final var entity = commonEntityAccessor.get(address, Optional.of(consensusTimestamp)).orElse(null);
```

`EntityRepository.findActiveByIdAndTimestamp()` and `findActiveByEvmAddressAndTimestamp()` already exist and are used elsewhere for exactly this purpose. [5](#0-4) 

### Proof of Concept
1. Create account A with ECDSA key; alias = `0xAAAA…`, no `evmAddress`. Deploy contract C that stores `owner = msg.sender` in constructor.
2. Call contract C from account A via a Hedera `ContractCall` (not Ethereum). Record transaction ID `T1`. Confirm `owner == 0xAAAA…` on-chain.
3. Send one Ethereum transaction from account A, causing Hedera to set `evmAddress = 0xBBBB…` on account A (lazy EVM address assignment).
4. `GET /api/v1/contracts/results/T1/opcodes` (with `Accept-Encoding: gzip`).
5. Observe: the replay uses `msg.sender = 0xBBBB…`. Any `require(msg.sender == owner)` in the contract causes the replay to revert, while the original transaction succeeded. The returned opcode trace diverges from the real historical execution.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L152-175)
```java
    private ContractDebugParameters buildCallServiceParameters(
            Long consensusTimestamp, Transaction transaction, EthereumTransaction ethTransaction) {
        final var contractResult = contractResultRepository
                .findById(consensusTimestamp)
                .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));

        final var blockType = recordFileService
                .findByTimestamp(consensusTimestamp)
                .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
                .orElse(BlockType.LATEST);

        final var transactionType = transaction != null ? transaction.getType() : TransactionType.UNKNOWN.getProtoId();

        return ContractDebugParameters.builder()
                .block(blockType)
                .callData(getCallDataBytes(ethTransaction, contractResult))
                .ethereumData(getEthereumDataBytes(ethTransaction))
                .consensusTimestamp(consensusTimestamp)
                .gas(getGasLimit(ethTransaction, contractResult))
                .receiver(getReceiverAddress(ethTransaction, contractResult, transactionType))
                .sender(getSenderAddress(contractResult))
                .value(getValue(ethTransaction, contractResult).longValue())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L177-180)
```java
    private Address getSenderAddress(ContractResult contractResult) {
        final var address = commonEntityAccessor.evmAddressFromId(contractResult.getSenderId(), Optional.empty());
        return address != null ? address : EMPTY_ADDRESS;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L190-195)
```java
                final var entity =
                        commonEntityAccessor.get(address, Optional.empty()).orElse(null);
                if (entity != null) {
                    return getEntityAddress(entity);
                }
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L96-107)
```java
        }

        if (entity.getEvmAddress() != null) {
            return Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(entity.getEvmAddress()));
        }

        if (entity.getAlias() != null && entity.getAlias().length == EVM_ADDRESS_LENGTH) {
            return Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(entity.getAlias()));
        }

        return toAddress(entityId);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L59-85)
```java
    @Query(value = """
            with entity_cte as (
                select id
                from entity
                where evm_address = ?1 and created_timestamp <= ?2
                order by created_timestamp desc
                limit 1
            )
            (
                select *
                from entity e
                where e.deleted is not true
                and e.id = (select id from entity_cte)
            )
            union all
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
            )
            order by timestamp_range desc
            limit 1
            """, nativeQuery = true)
    Optional<Entity> findActiveByEvmAddressAndTimestamp(byte[] evmAddress, long blockTimestamp);
```
