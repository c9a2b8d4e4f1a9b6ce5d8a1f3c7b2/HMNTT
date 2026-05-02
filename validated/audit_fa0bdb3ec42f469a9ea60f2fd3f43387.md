All code claims were verified against the actual source. Here is the result:

---

Audit Report

## Title
Missing `return` After Block Number Mismatch in `BlockAssembler.onEndOfBlock()` Allows Malicious Block Node to Abort Block Ingestion

## Summary
In `BlockNode.java`, the inner class `BlockAssembler.onEndOfBlock()` calls `Utility.handleRecoverableError()` when `EndOfBlock.blockNumber` differs from `BlockHeader.number`, but unlike the `pending.isEmpty()` guard directly above it, does **not** `return` afterward. This asymmetric omission causes two distinct abort paths depending on configuration, both of which terminate the streaming session and drop all transactions in the affected block.

## Finding Description

**Exact location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, inner class `BlockAssembler`, method `onEndOfBlock()`.

The `pending.isEmpty()` guard correctly returns after the error call: [1](#0-0) 

The block-number mismatch guard does **not**: [2](#0-1) 

Execution falls through to line 270, where the filename is constructed from the attacker-controlled `blockNumber` (from `blockEnd.getBlockNumber()`), not from `BlockHeader.number`: [3](#0-2) 

**Path A — `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR=true`:**
`Utility.handleRecoverableError()` throws `ParserException`: [4](#0-3) 

`ParserException` is not a `BlockStreamException`, so it is caught by the generic `catch (Exception ex)` block in `streamBlocks()`, which calls `onError()` and re-throws as `BlockStreamException`: [5](#0-4) 

The block is never assembled. All transactions are dropped for that cycle.

**Path B — default (`HALT_ON_ERROR=false`):**
`handleRecoverableError()` logs and returns. Execution falls through. The block is assembled with a filename derived from the attacker-supplied `blockNumber`. `BlockStreamVerifier.verifyBlockNumber()` then parses the block number from the filename and compares it to `blockFile.getIndex()` (set from `BlockHeader.number` by the reader). They differ, so `InvalidStreamFileException` is thrown: [6](#0-5) 

This also propagates through `streamBlocks()`, calls `onError()`, and terminates the session.

## Impact Explanation
Every crafted `EndOfBlock` message with a mismatched `blockNumber` aborts the streaming session. All transactions in the targeted block are silently dropped for that cycle. If the attacker controls the only configured block node and cloud storage fallback is disabled or unavailable, the mirror node stalls indefinitely at the targeted block number. Downstream consumers (REST API, gRPC API, event streaming) receive no data for that block or any subsequent block. The `onError()` / `maxSubscribeAttempts` / `readmitDelay` mechanism only throttles reconnection; it does not prevent the attacker from repeating the attack on every new session. [7](#0-6) 

## Likelihood Explanation
The precondition is controlling a block node — an external infrastructure component registered with the mirror node via configuration. A malicious operator or an attacker who has compromised a legitimate block node host satisfies this precondition without any privileged access to the mirror node itself. The attack requires crafting a single protobuf field (`EndOfBlock.blockNumber`) to a value differing from `BlockHeader.number`. No cryptographic material or consensus participation is required. It is trivially repeatable on every new streaming session.

## Recommendation
Add a `return` statement immediately after `Utility.handleRecoverableError()` in the block-number mismatch branch of `onEndOfBlock()`, mirroring the existing pattern in the `pending.isEmpty()` branch:

```java
// In BlockNode.java, BlockAssembler.onEndOfBlock(), after line 252:
if (blockHeader.getNumber() != blockNumber) {
    Utility.handleRecoverableError(
            "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
            blockHeader.getNumber(),
            blockNumber);
    return;  // ← add this
}
```

This ensures that regardless of the `HALT_ON_ERROR` setting, a mismatched `EndOfBlock` message is discarded and the pending block state is preserved (or cleared), rather than allowing fall-through assembly with an attacker-controlled filename. [8](#0-7) 

## Proof of Concept
1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. Configure the mirror node to use this server as its sole block node.
3. For a block with `BlockHeader.number = N`, send all `BlockItemSet` messages normally, then send `EndOfBlock` with `blockNumber = N + 1` (any value ≠ N).
4. **Path A** (`HALT_ON_ERROR=true`): `handleRecoverableError` throws `ParserException`; `streamBlocks()` catches it, calls `onError()`, re-throws as `BlockStreamException`. Block N is never delivered to `blockStreamConsumer`. Mirror node stalls at block N.
5. **Path B** (default): `handleRecoverableError` logs and returns; `onEndOfBlock` assembles the block with filename `000000000000000{N+1}.blk`; `BlockStreamVerifier.verifyBlockNumber()` compares filename-parsed number (`N+1`) against content index (`N`), throws `InvalidStreamFileException`; `streamBlocks()` catches it, calls `onError()`, re-throws. Mirror node stalls at block N.
6. Repeat on every reconnect to keep the mirror node stalled indefinitely.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L162-164)
```java
        } catch (Exception ex) {
            onError();
            throw new BlockStreamException(ex);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L196-207)
```java
    private void onError() {
        errorsMetric.increment();
        if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
            active = false;
            errors.set(0);
            readmitTime.set(Instant.now().plus(streamProperties.getReadmitDelay()));
            log.warn(
                    "Marking connection to {} as inactive after {} attempts",
                    this,
                    streamProperties.getMaxSubscribeAttempts());
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L239-272)
```java
        void onEndOfBlock(final BlockEnd blockEnd) {
            final long blockNumber = blockEnd.getBlockNumber();
            if (pending.isEmpty()) {
                Utility.handleRecoverableError(
                        "Received end-of-block message for block {} while there's no pending block items", blockNumber);
                return;
            }

            final var blockHeader = pending.getFirst().getFirst().getBlockHeader();
            if (blockHeader.getNumber() != blockNumber) {
                Utility.handleRecoverableError(
                        "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
                        blockHeader.getNumber(),
                        blockNumber);
            }

            final List<BlockItem> block;
            if (pending.size() == 1) {
                block = pending.getFirst();
            } else {
                // assemble when there are more than one BlockItemSet
                block = new ArrayList<>();
                for (final var items : pending) {
                    block.addAll(items);
                }
            }

            pending.clear();
            pendingCount = 0;
            stopwatch.reset();

            final var filename = BlockFile.getFilename(blockNumber, false);
            blockStreamConsumer.accept(new BlockStream(block, null, filename, loadStart));
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockStreamVerifier.java (L169-179)
```java
        try {
            final var filename = blockFile.getName();
            final int endIndex = filename.indexOf(FilenameUtils.EXTENSION_SEPARATOR);
            final long actual = Long.parseLong(endIndex != -1 ? filename.substring(0, endIndex) : filename);
            if (actual != blockNumber) {
                throw new InvalidStreamFileException(String.format(
                        "Block number mismatch, from filename = %d, from content = %d", actual, blockNumber));
            }
        } catch (final NumberFormatException _) {
            throw new InvalidStreamFileException("Failed to parse block number from filename " + blockFile.getName());
        }
```
