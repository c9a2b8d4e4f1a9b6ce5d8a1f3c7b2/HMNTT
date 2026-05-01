Looking at `BlockNode.java` `streamBlocks()` carefully, specifically the while loop condition and the error handling path. [1](#0-0) 

The while loop exits when `grpcCall.read()` returns `null`. The `onError()` path is only reached via `catch` blocks — not via a null return. If null is returned immediately, the method returns normally, `errors` is never incremented, and the node stays `active = true`. [2](#0-1) 

`getNode()` always selects the first active node with the block. Since the malicious node never gets marked inactive, it is always selected on every subsequent `get()` call. [3](#0-2) 

---

### Title
Silent Block Processing Stall via Immediate Null gRPC Stream Termination

### Summary
In `BlockNode.streamBlocks()`, when `grpcCall.read()` returns `null` immediately (server closes stream without sending any data), the while loop exits without invoking `onError()`. Because `onError()` is never called, the error counter is not incremented and the node is never marked inactive, causing the mirror node to silently and repeatedly select the same malicious node while making zero progress on block ingestion.

### Finding Description
**Exact location:** `BlockNode.java`, `streamBlocks()`, lines 138–158.

The loop condition is:
```java
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null)
```
A null return from `grpcCall.read()` is the normal gRPC stream-end signal. The code treats it as a clean exit — no exception is thrown, so neither `catch` block fires, and `onError()` is never called.

`onError()` is the only place that increments `errors` and sets `active = false`:
```java
// BlockNode.java lines 196-207
private void onError() {
    errorsMetric.increment();
    if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
        active = false;
        ...
    }
}
``` [4](#0-3) 

Because `active` stays `true`, `getNode()` always returns this node first (first active node with the block wins). `getNextBlockNumber()` in `AbstractBlockSource` returns the same block number on every `get()` call until a block is actually processed, so the mirror node loops forever against the malicious node. [5](#0-4) 

### Impact Explanation
A block node endpoint that immediately closes every gRPC stream will permanently stall block ingestion for any mirror node that selects it as its primary node. Because no error is recorded, the node is never demoted and healthy nodes are never tried. This halts the mirror node's view of the chain without any alarm being raised, satisfying the "≥30% processing node shutdown without brute force" severity classification.

### Likelihood Explanation
Any operator of a block node endpoint — including a node that was legitimate but is now adversarially controlled, or a node injected via a compromised discovery service — can trigger this with a trivially simple server implementation: accept the gRPC subscription and immediately close the stream. No authentication bypass or cryptographic attack is required. The attack is repeatable on every polling cycle.

### Recommendation
Treat a null return from `grpcCall.read()` before any block data has been received as an error condition. Specifically:

1. Track whether at least one `BLOCK_ITEMS` or `END_OF_BLOCK` response was received during the session.
2. If the loop exits via null and no data was received (and `serverSuccess` is false), call `onError()` before returning.
3. Alternatively, add an explicit check after the loop:
```java
if (!serverSuccess && !assembler.hasReceivedData()) {
    onError();
    throw new BlockStreamException("Stream ended with no data from block node");
}
```

### Proof of Concept
1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. On receiving any `SubscribeStreamRequest`, immediately call `onCompleted()` on the server-side stream observer (sends no messages, closes stream cleanly).
3. Configure the mirror node to use this endpoint as a block node.
4. Observe: `streamBlocks()` returns normally on every poll cycle, no error is logged, the node is never marked inactive, and block ingestion never advances.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L135-158)
```java
            SubscribeStreamResponse response;

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-171)
```java
        } catch (BlockStreamException ex) {
            onError();
            throw ex;
        } catch (Exception ex) {
            onError();
            throw new BlockStreamException(ex);
        } finally {
            final var call = callHolder.get();
            if (call != null) {
                call.cancel("unsubscribe", null);
                grpcBufferDisposer.accept(call);
            }
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L108-131)
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
