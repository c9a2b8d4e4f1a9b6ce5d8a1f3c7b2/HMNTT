The code is verified against the actual implementation. All claims check out.

**Verification summary:**

1. Line 138 — the while condition `(response = grpcCall.read(...)) != null` exits the loop silently when `read()` returns `null` (server closes stream via `onCompleted()` without sending `STATUS=SUCCESS`). [1](#0-0) 

2. Lines 159–164 — both catch blocks require a thrown exception; a null-read produces none, so `onError()` is never called. [2](#0-1) 

3. `onError()` is the only path that increments `errors` and sets `active = false`; it is unreachable on null-exit. [3](#0-2) 

4. `getNextBlockNumber()` in `AbstractBlockSource` derives the next block from the last committed record file. If no block is committed (because `onBlockStream` was never called), it returns the same block number on the next scheduler tick. [4](#0-3) 

5. `getNode()` in `BlockNodeSubscriber` returns the first active node that has the block. A node that was never penalized stays active and is re-selected. [5](#0-4) 

---

# Audit Report

## Title
Silent Stream Termination Bypasses Error Accounting, Enabling Indefinite Block Processing Stall

## Summary
In `BlockNode.streamBlocks()`, when a block node closes the gRPC stream by returning `null` from `grpcCall.read()` without sending a `STATUS=SUCCESS` response, the while loop exits silently. No exception is thrown, `onError()` is never called, and the `onBlockStream` consumer is never invoked. Because the node's error counter is never incremented, it is never marked inactive, so it is re-selected on every subsequent retry, permanently stalling block ingestion for the targeted block.

## Finding Description
**File:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`
**Method:** `streamBlocks()`, lines 137–171

**Root cause:** The while loop condition at line 138 treats a `null` return from `grpcCall.read()` as a normal, non-error exit:

```java
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
```

When the server closes the stream via `onCompleted()` without sending a `STATUS=SUCCESS` message, `read()` returns `null`, the loop exits, and execution falls through to the `finally` block. The two catch blocks at lines 159–164 only fire on thrown exceptions. A null-terminated stream is not an exception, so neither `onError()` nor any error-signaling path is triggered. There is no post-loop check for `!serverSuccess`.

**`onError()` is the sole path** that increments `errors` and eventually sets `active = false`:
```java
private void onError() {
    errorsMetric.increment();
    if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
        active = false;
        ...
    }
}
```
Since `onError()` is bypassed, the node's error counter is not incremented and `active` remains `true`.

## Impact Explanation
A malicious or compromised block node can indefinitely prevent the mirror node from ingesting any block it serves:

1. `streamBlocks()` returns normally (no exception) → `doGet()` returns normally → `get()` returns normally.
2. `getNextBlockNumber()` derives the next block from the last committed record file. Since no block was committed, it returns the same block N on the next scheduler tick.
3. `getNode()` iterates the node list and returns the first active node that has block N. The malicious node, never penalized, is selected again.
4. Steps 1–3 repeat indefinitely.

All transactions in the stalled block are never verified, stored, or made available via the mirror node API. There is no automatic recovery and no error trace in metrics (error counter stays unchanged).

## Likelihood Explanation
Any operator of a configured block node can trigger this with a trivial server-side change: accept the subscription, optionally send some `BLOCK_ITEMS`, then close the stream without sending `END_OF_BLOCK` or `STATUS=SUCCESS`. No cryptographic material, privileged network access, or special protocol knowledge is required beyond operating a node that the mirror node trusts. The attack is repeatable with zero cost per attempt.

## Recommendation
Add a post-loop check that treats a non-success exit as an error:

```java
// after the while loop, still inside the try block:
if (!serverSuccess) {
    throw new BlockStreamException(
        "Stream closed by server without STATUS=SUCCESS");
}
```

This ensures `onError()` is called on null-terminated streams, the error counter is incremented, and the node is eventually marked inactive after `maxSubscribeAttempts` failures, allowing fallback to other nodes.

## Proof of Concept
1. Configure a block node server that, upon receiving a `SubscribeStreamRequest`, calls `responseObserver.onCompleted()` immediately (or after sending partial `BLOCK_ITEMS`) without sending a `STATUS=SUCCESS` response.
2. Point the mirror node at this server as its only (or first) configured block node.
3. Observe that `streamBlocks()` returns without throwing, `onBlockStream` is never called, the node's `active` field remains `true`, and `getNextBlockNumber()` returns the same block number on every subsequent scheduler tick.
4. Confirm via metrics that `hiero.mirror.importer.stream.error` counter for the node stays at 0 and the node is re-selected on every retry.

The existing test `streamBlockEndNothing` in `BlockNodeTest.java` (line 238) demonstrates that a stream with only an `END_OF_BLOCK` and no `BLOCK_ITEMS` returns normally without error — the same silent-exit behavior applies to a fully null-terminated stream. [6](#0-5)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L137-158)
```java
            boolean serverSuccess = false;
            while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
                switch (response.getResponseCase()) {
                    case BLOCK_ITEMS -> assembler.onBlockItemSet(response.getBlockItems());
                    case END_OF_BLOCK -> assembler.onEndOfBlock(response.getEndOfBlock());
                    case STATUS -> {
                        var status = response.getStatus();
                        if (status == SubscribeStreamResponse.Code.SUCCESS) {
                            // The server may end the stream gracefully for various reasons, and this shouldn't be
                            // treated as an error.
                            log.info("Block server ended the subscription with {}", status);
                            serverSuccess = true;
                            break;
                        }

                        throw new BlockStreamException("Received status " + response.getStatus() + " from block node");
                    }
                    default -> throw new BlockStreamException("Unknown response case " + response.getResponseCase());
                }

                errors.set(0);
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-164)
```java
        } catch (BlockStreamException ex) {
            onError();
            throw ex;
        } catch (Exception ex) {
            onError();
            throw new BlockStreamException(ex);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L196-206)
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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/AbstractBlockSource.java (L63-71)
```java
    private long getNextBlockNumber() {
        return cutoverService
                .getLastRecordFile()
                .map(RecordFile::getIndex)
                .map(v -> v + 1)
                .or(() -> Optional.ofNullable(
                        commonDownloaderProperties.getImporterProperties().getStartBlockNumber()))
                .orElse(GENESIS_BLOCK_NUMBER);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L108-130)
```java
    private BlockNode getNode(final AtomicLong nextBlockNumber) {
        final var nodeList = getBlockNodes();
        final var inactiveNodes = new ArrayList<BlockNode>();
        for (final var node : nodeList) {
            if (!node.tryReadmit(false).isActive()) {
                inactiveNodes.add(node);
                continue;
            }

            if (hasBlock(nextBlockNumber, node)) {
                return node;
            }
        }

        // find the first inactive node with the block and force activating it
        for (final var node : inactiveNodes) {
            if (hasBlock(nextBlockNumber, node)) {
                node.tryReadmit(true);
                return node;
            }
        }

        throw new BlockStreamException("No block node can provide block " + nextBlockNumber.get());
```

**File:** importer/src/test/java/org/hiero/mirror/importer/downloader/block/BlockNodeTest.java (L238-249)
```java
    void streamBlockEndNothing(final CapturedOutput capturedOutput, final Resources resources) {
        // given
        final var responses = List.of(subscribeStreamResponse(1));
        runBlockStreamSubscribeService(resources, ResponsesOrError.fromResponses(responses));

        // when
        node.streamBlocks(0, commonDownloaderProperties, IGNORE);

        // then
        assertThat(capturedOutput.getAll())
                .contains("Received end-of-block message for block 1 while there's no pending block items");
    }
```
