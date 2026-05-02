All technical claims have been verified against the actual source code. Here is my assessment:

---

Audit Report

## Title
O(N²) CPU Amplification via Crafted Batch of ContractCall Siblings in `parsePossiblyHookContractRelatedParent()`

## Summary
`parsePossiblyHookContractRelatedParent()` in `RecordItem.java` performs an unbounded backwards walk of the `previous` linked list for every sibling transaction that has a non-null `ContractFunctionResult` whose `contractNum` is not `HOOK_CONTRACT_NUM` (365). A batch of N such siblings causes the i-th sibling to walk i−1 steps, yielding O(N²) total CPU work while the attacker pays only O(N) fees.

## Finding Description

The method `parsePossiblyHookContractRelatedParent()` is called unconditionally from `build()` for every `RecordItem`: [1](#0-0) 

The method body: [2](#0-1) 

The loop at line 359 walks backwards through `candidateRecord.previous` until it either finds a `HOOK_CONTRACT_NUM` match, encounters a null contract result, or reaches `parent`. There is no depth cap or iteration counter.

The `previous` field is set to the immediately preceding stream item by all record-file readers: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

This forms a singly-linked list through every item in the record file in stream order. For a batch of N sibling `ContractCall` transactions each targeting a contract with `contractNum ≠ 365`:

- The null-contract-result break (line 361) is never triggered — all siblings have non-null `ContractFunctionResult`.
- The `HOOK_CONTRACT_NUM` match (line 365) is never triggered — no sibling has `contractNum == 365`.
- The only termination is `candidateRecord == parent` (line 359), reached after walking through all preceding siblings.

Sibling 1: 0 iterations. Sibling 2: 1. … Sibling N: N−1. Total: N(N−1)/2 = **O(N²)**.

`HOOK_CONTRACT_NUM` is defined as: [7](#0-6) 

## Impact Explanation
The mirror node importer processes the record stream in near-real-time. An O(N²) per-file CPU spike causes the importer to fall behind the live stream, delaying all downstream consumers (REST API, gRPC, web3 API). With large N (feasible under HIP-551 batch transactions), the importer's processing thread is saturated. Because the mirror node is the primary off-chain data source for wallets, exchanges, and dApps on Hedera, sustained processing delays constitute a non-network DoS against the entire ecosystem that depends on it.

## Likelihood Explanation
Any account holder on Hedera can submit batch transactions (HIP-551). No special privileges, keys, or access are required. The attacker pays O(N) transaction fees but inflicts O(N²) CPU work on every mirror-node operator. The attack is repeatable every few seconds. The only cost barrier is the per-transaction fee on Hedera mainnet, which is low relative to the CPU cost imposed on mirror nodes.

## Recommendation
Add a depth cap to the backwards walk in `parsePossiblyHookContractRelatedParent()`. Since the method is only looking for the first hook child item among siblings, a small constant bound (e.g., 10–20 steps) is sufficient for any legitimate use case:

```java
private RecordItem parsePossiblyHookContractRelatedParent() {
    final var currentTxnRecordContractResult = getContractResult();
    final int MAX_SIBLING_WALK = 20; // add a depth cap

    if (transactionRecord.hasParentConsensusTimestamp()
            && currentTxnRecordContractResult != null
            && currentTxnRecordContractResult.getContractID().getContractNum() != HOOK_CONTRACT_NUM
            && previous != null) {
        var candidateRecord = previous;
        int steps = 0;

        while (candidateRecord != null && candidateRecord != parent && steps < MAX_SIBLING_WALK) {
            var candidateTxnRecordContractResult = candidateRecord.getContractResult();
            if (candidateTxnRecordContractResult == null) {
                break;
            }
            if (candidateTxnRecordContractResult.getContractID().getContractNum() == HOOK_CONTRACT_NUM) {
                return candidateRecord;
            }
            candidateRecord = candidateRecord.previous;
            steps++;
        }
    }
    return null;
}
```

Alternatively, the hook child item could be tracked directly on the parent `RecordItem` during construction, eliminating the need for any backwards walk entirely.

## Proof of Concept

1. Deploy any contract at `0.0.1000` (contractNum = 1000, which is ≠ 365).
2. Submit a HIP-551 batch transaction containing N `ContractCall` inner transactions, each calling `0.0.1000`.
3. The Hedera network writes N child records to the record stream, each with `parentConsensusTimestamp` set and a `ContractFunctionResult` with `contractNum = 1000`.
4. The mirror-node importer reads the record file. For each child item, `build()` → `parsePossiblyHookContractRelatedParent()` is called.
5. Conditions at lines 353–356 are all satisfied for every child. The loop walks backwards through all previous siblings before reaching `parent`.
6. Child 1: 0 iterations. Child 2: 1. … Child N: N−1. Total: N(N−1)/2 iterations of pure pointer-chasing CPU work.
7. Repeat with a new batch every few seconds to sustain importer saturation. [2](#0-1)

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java (L57-57)
```java
    public static final int HOOK_CONTRACT_NUM = 365;
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java (L306-307)
```java
            this.parent = parseParent();
            this.hookParent = parsePossiblyHookContractRelatedParent();
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java (L350-375)
```java
        private RecordItem parsePossiblyHookContractRelatedParent() {
            final var currentTxnRecordContractResult = getContractResult();

            if (transactionRecord.hasParentConsensusTimestamp()
                    && currentTxnRecordContractResult != null
                    && currentTxnRecordContractResult.getContractID().getContractNum() != HOOK_CONTRACT_NUM
                    && previous != null) {
                var candidateRecord = previous;

                while (candidateRecord != null && candidateRecord != parent) {
                    var candidateTxnRecordContractResult = candidateRecord.getContractResult();
                    if (candidateTxnRecordContractResult == null) {
                        break;
                    }

                    if (candidateTxnRecordContractResult.getContractID().getContractNum() == HOOK_CONTRACT_NUM) {
                        // we found the first hook child item, which has a ContractResult and is executed via a hook
                        return candidateRecord;
                    }

                    candidateRecord = candidateRecord.previous;
                }
            }

            return null;
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/record/ProtoRecordFileReader.java (L184-192)
```java
            var recordItem = RecordItem.builder()
                    .hapiVersion(hapiVersion)
                    .previous(previousItem)
                    .transactionRecord(recordStreamItem.getRecord())
                    .transaction(recordStreamItem.getTransaction())
                    .transactionIndex(items.size())
                    .build();
            items.add(recordItem);
            previousItem = recordItem;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/record/RecordFileReaderImplV5.java (L102-108)
```java
            var recordItem = RecordItem.builder()
                    .hapiVersion(recordFile.getHapiVersion())
                    .previous(lastRecordItem)
                    .transactionRecord(TransactionRecord.parseFrom(recordStreamObject.recordBytes))
                    .transactionIndex(count)
                    .transaction(Transaction.parseFrom(recordStreamObject.transactionBytes))
                    .build();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/record/AbstractPreV5RecordFileReader.java (L108-114)
```java
            RecordItem recordItem = RecordItem.builder()
                    .hapiVersion(recordFile.getHapiVersion())
                    .previous(lastRecordItem)
                    .transactionRecord(TransactionRecord.parseFrom(recordBytes))
                    .transactionIndex(count)
                    .transaction(Transaction.parseFrom(transactionBytes))
                    .build();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockFileTransformer.java (L103-110)
```java
        final var recordItems = new ArrayList<RecordItem>(blockTransactions.size());
        RecordItem previousItem = null;
        for (int index = builders.size() - 1; index >= 0; index--) {
            var builder = builders.get(index);
            var recordItem = builder.previous(previousItem).build();
            recordItems.add(recordItem);
            previousItem = recordItem;
        }
```
