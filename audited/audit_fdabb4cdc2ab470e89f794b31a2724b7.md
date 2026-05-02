### Title
Missing `return` After Block Number Mismatch Allows Malicious Block Node to Abort Block Processing via `onEndOfBlock()`

### Summary
In `BlockAssembler.onEndOfBlock()` inside `BlockNode.java`, when `EndOfBlock.blockNumber` differs from `BlockHeader.number`, `Utility.handleRecoverableError()` is called but execution is **not halted with a `return`** (unlike the `pending.isEmpty()` branch above it). When `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR=true`, this causes a `ParserException` to propagate up and abort the entire streaming session without processing the block. Even in the default configuration, the fall-through causes the block to be assembled with the attacker-controlled `blockNumber` as the filename, which is then caught by `BlockStreamVerifier.verifyBlockNumber()` and also aborts the session. In both paths, all transactions in the block are silently dropped for that streaming cycle.

### Finding Description

**Exact code location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, inner class `BlockAssembler`, method `onEndOfBlock()`, lines 239–272.

```
void onEndOfBlock(final BlockEnd blockEnd) {
    final long blockNumber = blockEnd.getBlockNumber();   // ← attacker-controlled
    if (pending.isEmpty()) {
        Utility.handleRecoverableError(...);
        return;                                           // ← return present here
    }

    final var blockHeader = pending.getFirst().getFirst().getBlockHeader();
    if (blockHeader.getNumber() != blockNumber) {
        Utility.handleRecoverableError(                   // ← throws or logs
                "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
                blockHeader.getNumber(),
                blockNumber);
        // ← NO return here — falls through in both branches
    }

    // ... assembles block ...
    final var filename = BlockFile.getFilename(blockNumber, false);  // ← uses attacker's number
    blockStreamConsumer.accept(new BlockStream(block, null, filename, loadStart));
}
```

**Root cause:** The `pending.isEmpty()` guard (line 244) correctly returns after calling `handleRecoverableError`. The block-number mismatch guard (lines 248–253) does not. This is an asymmetric omission.

**Path A — `HALT_ON_ERROR_PROPERTY=true` (the "throws" case):**
`handleRecoverableError` (Utility.java lines 220–227) throws `ParserException`. This is not a `BlockStreamException`, so it is caught by the generic `catch (Exception ex)` in `streamBlocks()` (BlockNode.java lines 162–164), which calls `onError()` and re-throws as `BlockStreamException`. The block is never assembled or delivered to `blockStreamConsumer`. All transactions in the block are lost for this cycle.

**Path B — `HALT_ON_ERROR_PROPERTY=false` (default):**
`handleRecoverableError` logs and returns normally. Execution falls through. The block is assembled and `blockStreamConsumer.accept()` is called with a `BlockStream` whose `filename` is derived from the attacker-controlled `blockNumber` (line 270), while the actual `BlockFile.getIndex()` is set from `BlockHeader.number` by `BlockStreamReader`. `BlockStreamVerifier.verifyBlockNumber()` (lines 169–179) then parses the block number from the filename and compares it to the content index — they differ — and throws `InvalidStreamFileException`. This also propagates up through `streamBlocks`, calls `onError()`, and terminates the session.

**Existing checks reviewed and shown insufficient:**
- The mismatch check at line 248 exists but is not a hard stop — it is advisory only in the default config.
- `BlockStreamVerifier.verifyBlockNumber()` catches the downstream consequence in Path B, but only after the block has been fully assembled and the session is already in a broken state.
- `onError()` / `maxSubscribeAttempts` / `readmitDelay` only throttle reconnection; they do not prevent the attacker from repeating the attack on every new session.
- `CompositeBlockSource.SourceHealth` falls back to cloud storage only after 3 consecutive errors — the attacker can trigger exactly 3 per cycle to keep the node in a degraded state without triggering full fallback.

### Impact Explanation
Every time the attacker sends a mismatched `EndOfBlock.blockNumber`, the streaming session is aborted and the block's transactions are not recorded in the mirror node for that cycle. If the attacker controls the only configured block node, or all configured block nodes, and cloud storage fallback is disabled or unavailable, the mirror node stalls indefinitely at the targeted block number. Downstream consumers (REST API, gRPC API, event streaming) receive no data for that block or any subsequent block. This is a targeted, repeatable denial-of-service against block ingestion.

### Likelihood Explanation
The precondition — controlling a block node — is realistic. Block nodes are external infrastructure components that operators register with the mirror node via configuration or discovery. A malicious operator running their own block node, or an attacker who has compromised a legitimate block node's host, satisfies this precondition without any privileged access to the mirror node itself. The attack requires only crafting a single protobuf field (`EndOfBlock.blockNumber`) to a value that differs from the `BlockHeader.number` already present in the stream. It is trivially repeatable on every new streaming session. No cryptographic material or consensus participation is required.

### Recommendation
Add an explicit `return` immediately after the `handleRecoverableError` call in the block-number mismatch branch, mirroring the pattern already used in the `pending.isEmpty()` branch:

```java
if (blockHeader.getNumber() != blockNumber) {
    Utility.handleRecoverableError(
            "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
            blockHeader.getNumber(),
            blockNumber);
    return;   // ← add this
}
```

This ensures that in the default configuration the block is silently skipped (consistent with the "recoverable" intent) rather than assembled with a poisoned filename that causes a downstream verification failure and session abort. In the `HALT_ON_ERROR_PROPERTY=true` configuration the `ParserException` still propagates, which is the intended strict behavior. Additionally, consider whether a block-number mismatch from an external node should be treated as a hard error (throw `BlockStreamException` directly) rather than a recoverable one, since it indicates the block node is actively lying about block identity.

### Proof of Concept

**Preconditions:**
- Mirror node is configured with a single block node endpoint pointing to an attacker-controlled gRPC server.
- `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR=true` for Path A, or default (`false`) for Path B.

**Steps:**

1. Attacker's gRPC server implements `BlockStreamSubscribeService.subscribeBlockStream`.
2. On receiving a `SubscribeStreamRequest` for block N, the server sends:
   - A valid `BLOCK_ITEMS` response containing a `BlockHeader` with `number = N` and any valid transaction items.
   - An `END_OF_BLOCK` response with `BlockEnd.blockNumber = N + 9999` (any value ≠ N).
3. Mirror node calls `assembler.onEndOfBlock(response.getEndOfBlock())`.
4. **Path A:** `handleRecoverableError` throws `ParserException` → caught by `catch (Exception ex)` in `streamBlocks` → `onError()` → `BlockStreamException` thrown → block N not processed.
5. **Path B:** `handleRecoverableError` logs → execution falls through → `BlockFile.getFilename(N+9999, false)` used as filename → `verifyBlockNumber` detects `actual(N+9999) != index(N)` → `InvalidStreamFileException` → same abort path.
6. Repeat on every reconnection attempt. The mirror node never advances past block N.