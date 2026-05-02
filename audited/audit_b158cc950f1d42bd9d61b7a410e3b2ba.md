### Title
Error Counter Reset Bypass Allows Malicious Block Node to Evade Inactivity Marking Indefinitely

### Summary
In `BlockNode.streamBlocks()`, the `errors.set(0)` call at line 157 executes after every successfully processed `grpcCall.read()` iteration — including iterations that occur within a streaming session that ultimately fails. A malicious block node can exploit this by sending one valid `BLOCK_ITEMS` message (triggering the reset) before each deliberate failure, keeping the cross-invocation error counter perpetually at 1 and never reaching `maxSubscribeAttempts` (default: 3). This prevents the node from ever being marked inactive, allowing it to remain in the active node pool indefinitely and cause sustained disruption to block ingestion.

### Finding Description

**Exact code path:**

`BlockNode.java`, `streamBlocks()`, lines 138–158:

```java
while (!serverSuccess && (response = grpcCall.read(...)) != null) {
    switch (response.getResponseCase()) {
        case BLOCK_ITEMS -> assembler.onBlockItemSet(response.getBlockItems());
        ...
        case STATUS -> {
            if (status != SUCCESS)
                throw new BlockStreamException(...);  // triggers onError()
        }
        default -> throw new BlockStreamException(...);  // triggers onError()
    }
    errors.set(0);  // LINE 157 — resets BEFORE the next iteration can fail
}
```

`BlockNode.java`, `onError()`, lines 196–207:

```java
private void onError() {
    errorsMetric.increment();
    if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
        active = false;
        ...
    }
}
```

**Root cause:** The `errors` counter is intended to count *consecutive failed `streamBlocks()` invocations* across calls. However, `errors.set(0)` is placed inside the per-message loop body, not after a fully successful streaming session. Any single successfully parsed response message within a doomed session resets the accumulated cross-invocation error count to zero before `onError()` increments it back to 1.

**Exploit flow:**
- Invocation 1: Malicious node sends `BLOCK_ITEMS` (valid) → `errors.set(0)` fires (errors = 0) → then sends `STATUS=NOT_AVAILABLE` → exception → `onError()` → `errors.incrementAndGet()` = 1
- Invocation 2: Same pattern → `errors.set(0)` (errors = 0) → `onError()` → errors = 1
- Invocation N: Same pattern → errors never reaches 3

The node is never marked inactive.

**Why existing checks are insufficient:**

The `BlockStreamVerifier` (`BlockStreamVerifier.java`, lines 98–137) performs `verifyBlockNumber()`, `verifyHashChain()`, and `verifySignature()` (TSS or wrapped record file). These cryptographic checks would catch any attempt to serve blocks with reordered or tampered content — the block hash and signature would be invalid. Therefore, the "reorganized transaction ordering" impact described in the question is **mitigated by the verifier**. However, the verifier does nothing to prevent the error counter bypass itself. The bypass is a real, standalone issue: the malicious node is never penalized regardless of how many times it fails.

### Impact Explanation

The concrete impact is **availability disruption, not transaction reordering**. The malicious block node remains permanently active in the node pool. Every invocation of `doGet()` in `BlockNodeSubscriber` selects this node (especially if it has higher priority), it sends one valid message and then fails, the exception propagates up through `BlockNodeSubscriber.doGet()`, and block ingestion stalls or retries indefinitely on the malicious node. Legitimate block nodes at lower priority are bypassed. In a single-node configuration, this is a complete denial of block stream ingestion. The cryptographic verifier prevents actual block content manipulation, so the severity is **Medium** (availability, not integrity).

### Likelihood Explanation

Precondition: the attacker must control a host that is registered as a block node in the mirror node's configuration (`hiero.mirror.importer.block.nodes`) or discoverable via auto-discovery (`autoDiscoveryEnabled=true`, the default). This is not a zero-privilege scenario — it requires being a configured or auto-discovered block node. However, with auto-discovery enabled and no authentication on the block node registration path, the bar is lower than traditional privileged access. The attack is trivially repeatable: one valid gRPC message per invocation is all that is needed, and the pattern is stable across all `maxSubscribeAttempts` values.

### Recommendation

Move `errors.set(0)` out of the per-message loop body and place it only after the `while` loop exits normally (i.e., when `serverSuccess == true` or the stream ends cleanly with `null`). This ensures the error counter is only reset when an entire streaming session completes successfully, not when a single message within a failing session is processed:

```java
// After the while loop, before the catch blocks:
if (serverSuccess || /* stream ended cleanly */) {
    errors.set(0);
}
```

Alternatively, reset `errors` only after a complete block has been successfully assembled and verified (i.e., inside `onEndOfBlock` after `blockStreamConsumer.accept()` returns without exception), which ties the reset to meaningful forward progress rather than any arbitrary message receipt.

### Proof of Concept

1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. Configure it as the sole (or highest-priority) block node in the mirror node's `hiero.mirror.importer.block.nodes`.
3. For every `SubscribeBlockStream` RPC call received, respond with exactly one valid `SubscribeStreamResponse` containing a `BLOCK_ITEMS` message with a well-formed `BlockHeader`, then immediately send `STATUS=NOT_AVAILABLE`.
4. Observe that `BlockNode.streamBlocks()` throws `BlockStreamException` on every invocation.
5. Observe via logs that "Marking connection to ... as inactive after 3 attempts" is **never** emitted, confirming `errors` never reaches `maxSubscribeAttempts`.
6. Observe that the mirror node continues selecting this node on every `doGet()` call, blocking block ingestion indefinitely. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L138-158)
```java
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockStreamVerifier.java (L98-137)
```java
    public void verify(final BlockFile blockFile) {
        final var startTime = Instant.now();
        final boolean wrapped = blockFile.hasRecordFile();

        boolean success = true;
        try {
            verifyBlockNumber(blockFile);
            verifyHashChain(blockFile);
            verifySignature(blockFile);

            final var consensusEnd = Instant.ofEpochSecond(0, blockFile.getConsensusEnd());
            streamLatencyMeterProvider
                    .withTags(BLOCK_NODE_TAG, blockFile.getNode(), WRAPPED_TAG, String.valueOf(wrapped))
                    .record(Duration.between(consensusEnd, Instant.now()));

            final var lastRecordFile = cutoverService.getLastRecordFile();
            final var recordFile = blockFileTransformer.transform(blockFile);
            streamFileNotifier.verified(recordFile);

            lastRecordFile.map(RecordFile::getConsensusStart).ifPresent(lastConsensusStart -> {
                final long latency = blockFile.getConsensusStart() - lastConsensusStart;
                streamCloseMetricProvider
                        .withTag(WRAPPED_TAG, String.valueOf(wrapped))
                        .record(latency, TimeUnit.NANOSECONDS);
            });
        } catch (Exception e) {
            success = false;
            throw e;
        } finally {
            streamVerificationMeterProvider
                    .withTags(
                            "success",
                            String.valueOf(success),
                            BLOCK_NODE_TAG,
                            blockFile.getNode(),
                            WRAPPED_TAG,
                            String.valueOf(wrapped))
                    .record(Duration.between(startTime, Instant.now()));
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L26-27)
```java
    @Min(1)
    private int maxSubscribeAttempts = 3;
```
