The critical clue is in the `INVALID_CHUNK_TRANSACTION_ID` constant comment:

> *"The entire initialTransactionID should match the transactionID of the first chunk, **but this is not checked or enforced by Hedera except when the chunk number is 1**."*

This confirms the vulnerability is real and exploitable.

---

### Title
Mirror Node Stores Orphaned Final Chunk Due to Partial Network Enforcement of `initialTransactionID`

### Summary
The Hedera consensus network only enforces that the payer account in `initialTransactionID` matches the transaction payer for non-first chunks; it does not verify the full `initialTransactionID` matches the first chunk's transaction ID. The mirror node's `doUpdateTransaction()` blindly persists whatever `initialTransactionID` is present in each chunk without any cross-chunk consistency check. An unprivileged user can therefore submit a final chunk (`number == total`) with a fabricated `initialTransactionID` that differs from chunk 1's, causing the mirror node to permanently store an orphaned final chunk that cannot be reassembled with its corresponding first chunk.

### Finding Description
**Code location:** `importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/ConsensusSubmitMessageTransactionHandler.java`, `doUpdateTransaction()`, lines 76–84.

```java
if (transactionBody.hasChunkInfo()) {
    ConsensusMessageChunkInfo chunkInfo = transactionBody.getChunkInfo();
    topicMessage.setChunkNum(chunkInfo.getNumber());
    topicMessage.setChunkTotal(chunkInfo.getTotal());

    if (chunkInfo.hasInitialTransactionID()) {
        topicMessage.setInitialTransactionId(
                chunkInfo.getInitialTransactionID().toByteArray());  // blindly stored
    }
}
```

**Root cause / failed assumption:** The handler assumes the network has fully validated `initialTransactionID` consistency across all chunks. In reality, as documented in `HederaResponseCodes.sol` line 145:

> *"The entire initialTransactionID should match the transactionID of the first chunk, but this is not checked or enforced by Hedera except when the chunk number is 1."*

For chunks 2 through N, the network only checks that the payer account embedded in `initialTransactionID` matches the transaction's payer. The full ID is not verified. The mirror node's only guard is `recordItem.isSuccessful()` (line 53), which merely confirms the network accepted the transaction — it provides no cross-chunk ID consistency guarantee.

**Exploit flow:**
1. Attacker controls account `0.0.X`.
2. Attacker submits chunk 1 with `chunkInfo.number=1, chunkInfo.total=2, initialTransactionID=TX_A` (TX_A is the actual transaction ID of this first chunk). Network enforces this for chunk 1 → accepted.
3. Attacker submits chunk 2 with `chunkInfo.number=2, chunkInfo.total=2, initialTransactionID=TX_B` where TX_B has the same payer account `0.0.X` but a completely different `transactionValidStart`. Network only checks payer account for non-first chunks → accepted with `SUCCESS`.
4. Mirror node processes both as successful, stores chunk 1 with `initial_transaction_id = TX_A` and chunk 2 with `initial_transaction_id = TX_B`.
5. Any consumer (gRPC subscriber, REST API client) grouping chunks by `initialTransactionID` to reassemble the logical message will never match chunk 2 to chunk 1.

### Impact Explanation
Fragmented topic message reassembly is permanently broken for the targeted logical message. The `topic_message` table will contain an orphaned final chunk with a mismatched `initial_transaction_id` that no consumer can correctly associate with its first chunk. The gRPC `ConsensusController` and REST API both surface `chunk_info.initial_transaction_id` directly to clients; clients following the HCS spec to reassemble multi-chunk messages will silently produce incomplete or corrupted application-layer messages. This is a data-integrity violation affecting all downstream consumers of the affected topic.

### Likelihood Explanation
Any account holder on the Hedera network (no special privileges required) can submit `ConsensusSubmitMessage` transactions to any open topic. The attack requires only two transactions and standard HAPI access. It is repeatable at will and costs only normal transaction fees. The partial enforcement gap is explicitly documented in the protocol constants, making it discoverable by any attacker reading the SDK or protobuf definitions.

### Recommendation
In `doUpdateTransaction()`, add a cross-chunk consistency check: when `chunkInfo.getNumber() > 1`, verify that the `initialTransactionID` in the incoming chunk matches the `initialTransactionId` already stored for the first chunk of the same logical message (identified by topic + `initialTransactionID` of chunk 1). If they do not match, treat the record as corrupt and skip persistence (or log a recoverable error). Alternatively, enforce at ingestion time that only chunk 1 is authoritative for `initialTransactionID` and derive/validate subsequent chunks against it.

### Proof of Concept
1. Create or use an open Hedera topic (no `submitKey`).
2. Submit chunk 1:
   ```
   ConsensusSubmitMessage {
     topicID: <target topic>
     message: <part 1>
     chunkInfo: { number: 1, total: 2, initialTransactionID: <this tx's own ID> }
   }
   ```
   → Network returns `SUCCESS`. Mirror node stores `chunk_num=1, initial_transaction_id=TX_A`.
3. Submit chunk 2 with a **different** `initialTransactionID` (same payer account, different `transactionValidStart`):
   ```
   ConsensusSubmitMessage {
     topicID: <target topic>
     message: <part 2>
     chunkInfo: { number: 2, total: 2, initialTransactionID: <fabricated ID with same payer> }
   }
   ```
   → Network returns `SUCCESS` (only payer account is checked). Mirror node stores `chunk_num=2, initial_transaction_id=TX_B`.
4. Query the mirror node REST API or gRPC for the topic messages. Observe that chunk 1 has `chunk_info.initial_transaction_id = TX_A` and chunk 2 has `chunk_info.initial_transaction_id = TX_B`. No client following the HCS reassembly spec can match them into a single logical message.