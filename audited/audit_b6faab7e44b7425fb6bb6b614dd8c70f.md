### Title
O(N²) CPU Amplification via Crafted Batch of ContractCall Siblings in `parsePossiblyHookContractRelatedParent()`

### Summary
`parsePossiblyHookContractRelatedParent()` in `RecordItem.java` performs an unbounded backwards walk of the `previous` linked list for every sibling transaction that has a non-null `ContractFunctionResult` whose `contractNum` is not `HOOK_CONTRACT_NUM` (365). Because `previous` is set to the immediately preceding stream item by all record-file readers, and the loop only terminates when it reaches `parent` or a null contract result, a batch of N such siblings causes the i-th sibling to walk i−1 steps, yielding O(N²) total CPU work across the batch while the attacker pays only O(N) fees.

### Finding Description
**Exact code path:**
`common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java`, `RecordItemBuilder.parsePossiblyHookContractRelatedParent()`, lines 350–375.

```java
// line 350
private RecordItem parsePossiblyHookContractRelatedParent() {
    final var currentTxnRecordContractResult = getContractResult();

    if (transactionRecord.hasParentConsensusTimestamp()          // (A)
            && currentTxnRecordContractResult != null             // (B)
            && currentTxnRecordContractResult.getContractID()
                   .getContractNum() != HOOK_CONTRACT_NUM         // (C)
            && previous != null) {
        var candidateRecord = previous;

        while (candidateRecord != null && candidateRecord != parent) {  // (D)
            var candidateTxnRecordContractResult =
                    candidateRecord.getContractResult();
            if (candidateTxnRecordContractResult == null) {       // (E)
                break;
            }
            if (candidateTxnRecordContractResult.getContractID()
                    .getContractNum() == HOOK_CONTRACT_NUM) {
                return candidateRecord;
            }
            candidateRecord = candidateRecord.previous;           // (F)
        }
    }
    return null;
}
```

**How `previous` is wired:** Every record-file reader sets `previous` to the immediately preceding stream item:
- `ProtoRecordFileReader.java` line 186: `previous(previousItem)`
- `RecordFileReaderImplV5.java` line 104: `previous(lastRecordItem)`
- `AbstractPreV5RecordFileReader.java` line 110: `previous(lastRecordItem)`
- `BlockFileTransformer.java` line 107: `builder.previous(previousItem).build()`

This means `previous` forms a singly-linked list through every item in the record file in stream order.

**Root cause:** The loop at (D)–(F) walks backwards through all preceding siblings until it either finds a `HOOK_CONTRACT_NUM` match, hits a null contract result (E), or reaches `parent`. There is no depth cap. For a batch of N sibling ContractCall transactions whose `ContractFunctionResult.contractNum` is never 365, the break condition (E) is never triggered, and the loop for the i-th sibling walks exactly i−1 steps. Total iterations = 0+1+2+…+(N−1) = N(N−1)/2 = **O(N²)**.

**Failed assumption:** The code assumes that the number of preceding siblings with non-null contract results is small (i.e., that hook-related batches are short). There is no guard enforcing this.

**Exploit flow:**
1. Attacker submits a batch transaction (HIP-551) containing N `ContractCall` inner transactions, each targeting any contract with `contractNum ≠ 365` (e.g., a deployed ERC-20 at `0.0.1000`).
2. The Hedera network executes the batch and writes N child records to the record stream, each with `parentConsensusTimestamp` set and a `ContractFunctionResult` whose `contractNum` is 1000.
3. The mirror-node importer reads the record file. For each child item, `build()` is called, which calls `parsePossiblyHookContractRelatedParent()`.
4. Conditions (A), (B), (C) are all satisfied for every child. The loop walks backwards through all previous siblings before reaching `parent`.
5. Child 1: 0 iterations. Child 2: 1. … Child N: N−1. Total: N(N−1)/2 iterations.

**Why existing checks are insufficient:**
- Condition (E) (`candidateTxnRecordContractResult == null`) only breaks the loop for non-contract transactions. All crafted siblings are ContractCalls, so they all have non-null results.
- Condition (D) (`candidateRecord != parent`) terminates at the parent, but only after walking through every sibling.
- There is no iteration counter, depth limit, or early-exit heuristic.

### Impact Explanation
The mirror node's importer processes the record stream in near-real-time. An O(N²) per-file CPU spike causes the importer to fall behind the live stream, delaying all downstream consumers (REST API, gRPC, web3 API). With N=200 siblings per batch (feasible under HIP-551 if inner transactions are compact) and repeated across multiple record files, the importer's processing thread is saturated. Because the mirror node is the primary off-chain data source for wallets, exchanges, and dApps on Hedera, sustained processing delays constitute a non-network DoS against the entire ecosystem that depends on it.

### Likelihood Explanation
Any account holder on Hedera can submit batch transactions. No special privileges, keys, or access are required. The attacker pays O(N) transaction fees (one fee per inner ContractCall) but inflicts O(N²) CPU work on every mirror-node operator. The attack is repeatable: the attacker can submit a new batch every few seconds. The only cost barrier is the per-transaction fee on Hedera mainnet, which is low relative to the CPU cost imposed on mirror nodes.

### Recommendation
Add a depth cap to the backwards walk. A simple fix:

```java
private RecordItem parsePossiblyHookContractRelatedParent() {
    final var currentTxnRecordContractResult = getContractResult();
    if (transactionRecord.hasParentConsensusTimestamp()
            && currentTxnRecordContractResult != null
            && currentTxnRecordContractResult.getContractID().getContractNum() != HOOK_CONTRACT_NUM
            && previous != null) {
        var candidateRecord = previous;
        int maxDepth = 64; // or a configurable constant
        while (candidateRecord != null && candidateRecord != parent && maxDepth-- > 0) {
            var result = candidateRecord.getContractResult();
            if (result == null) break;
            if (result.getContractID().getContractNum() == HOOK_CONTRACT_NUM) {
                return candidateRecord;
            }
            candidateRecord = candidateRecord.previous;
        }
    }
    return null;
}
```

Alternatively, maintain a direct reference to the hook-sibling during batch construction rather than searching backwards at build time.

### Proof of Concept
1. Deploy a simple contract at `0.0.1000` on Hedera testnet.
2. Construct a HIP-551 batch transaction containing N=200 `ContractCall` inner transactions, each calling `0.0.1000`.
3. Submit the batch. The network produces 200 child records, each with `parentConsensusTimestamp` set and `ContractFunctionResult.contractID.contractNum = 1000`.
4. Observe the mirror-node importer: `parsePossiblyHookContractRelatedParent()` is called 200 times. The total loop iterations are 200×199/2 = 19,900.
5. Repeat the batch submission at the maximum allowed rate. CPU usage in the importer's parsing thread grows quadratically with batch size and linearly with submission rate, eventually causing the importer to lag behind the live record stream. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordItem.java (L299-312)
```java
        public RecordItem build() {
            if (transactionRecordBuilder != null) {
                transactionRecord = transactionRecordBuilder.build();
            }

            parseTransaction();
            this.consensusTimestamp = DomainUtils.timestampInNanosMax(transactionRecord.getConsensusTimestamp());
            this.parent = parseParent();
            this.hookParent = parsePossiblyHookContractRelatedParent();
            this.payerAccountId = EntityId.of(transactionBody.getTransactionID().getAccountID());
            this.successful = parseSuccess();
            this.transactionType = parseTransactionType(transactionBody);
            return buildInternal();
        }
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

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/record/ProtoRecordFileReader.java (L182-193)
```java
        RecordItem previousItem = null;
        for (var recordStreamItem : recordStreamFile.getRecordStreamItemsList()) {
            var recordItem = RecordItem.builder()
                    .hapiVersion(hapiVersion)
                    .previous(previousItem)
                    .transactionRecord(recordStreamItem.getRecord())
                    .transaction(recordStreamItem.getTransaction())
                    .transactionIndex(items.size())
                    .build();
            items.add(recordItem);
            previousItem = recordItem;
        }
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
