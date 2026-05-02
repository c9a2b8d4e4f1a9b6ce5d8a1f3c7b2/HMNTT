Looking at the actual `streamBlocks()` implementation in `BlockNode.java`: [1](#0-0) 

The while loop condition is `!serverSuccess && (response = grpcCall.read(...)) != null`. If `grpcCall.read()` returns `null` (stream closed by server without a `STATUS=SUCCESS` message), the loop exits silently — no exception is thrown, `onError()` is never called, and `blockStreamConsumer.accept()` (i.e., `onBlockStream()`) is never invoked. [2](#0-1) 

The catch blocks only fire on exceptions. A null-terminated stream is not an exception, so `onError()` is never called, the node's error counter is never incremented, and the node is never marked inactive. [3](#0-2) 

The node is only penalized via `onError()` → `errors.incrementAndGet()` → eventually `active = false`. Since null-read bypasses this entirely, the malicious node stays permanently active and is re-selected on every retry. [4](#0-3) 

`getNode()` iterates the list in order and returns the first active node that has the block. A malicious node that is first in the list and always claims to have the block will be selected on every retry indefinitely.

---

### Title
Silent Stream Termination Bypasses Error Accounting, Enabling Indefinite Block Processing Stall

### Summary
In `BlockNode.streamBlocks()`, when a block node closes the gRPC stream by returning `null` from `grpcCall.read()` without sending a `STATUS=SUCCESS` response, the while loop exits silently. No exception is thrown, `onError()` is never called, and the block's `onBlockStream()` consumer is never invoked. Because the node's error counter is never incremented, it is never marked inactive, so it is re-selected on every subsequent retry, permanently stalling block ingestion.

### Finding Description
**Code location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, `streamBlocks()`, lines 137–158.

**Root cause:** The while loop condition treats a `null` return from `grpcCall.read()` as a normal, non-error exit. The two catch blocks (lines 159–164) only fire on thrown exceptions. A null-terminated stream is not an exception, so neither `onError()` nor any error-signaling path is triggered.

**Exploit flow:**
1. Attacker controls a block node that is in the mirror node's configured node list (e.g., a legitimate operator turned malicious, or a compromised node).
2. Mirror node calls `streamBlocks()` for block N.
3. Malicious node accepts the subscription, optionally sends some `BLOCK_ITEMS` (populating `BlockAssembler.pending`), then closes the TCP/gRPC stream without sending `END_OF_BLOCK` or `STATUS=SUCCESS`.
4. `grpcCall.read()` returns `null`; the while loop exits.
5. `blockStreamConsumer.accept()` (→ `onBlockStream()` → `blockStreamVerifier.verify()`) is never called. Block N is not processed.
6. `onError()` is not called; `errors` counter stays at 0; node remains `active = true`.
7. Next scheduler tick: `getNextBlockNumber()` returns N again (block was never committed); `getNode()` selects the same malicious node again.
8. Steps 2–7 repeat indefinitely.

**Why existing checks fail:**
- The `catch (BlockStreamException)` and `catch (Exception)` blocks (lines 159–164) require an exception to be thrown — a null read produces none.
- The `errors.set(0)` reset inside the loop (line 157) is never reached on null exit, but neither is `errors.incrementAndGet()` in `onError()`, so the node is never penalized.
- There is no post-loop check for `!serverSuccess` or for non-empty `assembler.pending`.

### Impact Explanation
A malicious or compromised block node can indefinitely prevent the mirror node from ingesting any block it serves. Since the node is never marked inactive, no fallback to other nodes occurs. All transactions in the stalled block are never verified, stored, or made available via the mirror node API. This is a targeted, repeatable denial-of-service against block ingestion with no automatic recovery.

### Likelihood Explanation
Any operator of a configured block node can trigger this with a trivial server-side change (close the stream after accepting the subscription). No cryptographic material, privileged network access, or special protocol knowledge is required beyond operating a node that the mirror node trusts. The attack is repeatable with zero cost per attempt and leaves no error trace in the mirror node's metrics (error counter stays at 0).

### Recommendation
After the while loop, add an explicit check:

```java
if (!serverSuccess) {
    throw new BlockStreamException(
        "Block node closed stream without SUCCESS status");
}
```

This ensures `onError()` is called via the existing catch block, the node's error counter is incremented, and after `maxSubscribeAttempts` failures the node is marked inactive and a fallback node is tried. Additionally, check `assembler.pending.isEmpty()` to detect and reject partial blocks delivered before the premature stream close.

### Proof of Concept
1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. On receiving a `SubscribeStreamRequest`, send one valid `BLOCK_ITEMS` response, then close the stream (return from the server handler without writing a `STATUS` response).
3. Configure the mirror node to use this server as its sole block node.
4. Observe: `streamBlocks()` returns normally, no exception is logged, no error metric is incremented, the node remains active, and the mirror node retries the same node on the next tick — never advancing past block N.

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
