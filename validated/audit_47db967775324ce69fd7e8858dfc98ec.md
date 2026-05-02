I've verified the actual code. Here is my analysis:

**Code verification:**

The `streamBlocks()` method at lines 137–158 of `BlockNode.java`: [1](#0-0) 

When `STATUS=SUCCESS` is received: `serverSuccess = true` is set, `break` exits the switch, execution falls through to `errors.set(0)` at line 157, and then the while condition `!serverSuccess` terminates the loop. The reset happens unconditionally — confirmed.

The `onError()` method at lines 196–207: [2](#0-1) 

`onError()` is only called from the `catch` blocks (lines 159–164), never from the SUCCESS path.

`maxSubscribeAttempts` defaults to `3`: [3](#0-2) 

The test at lines 179–185 explicitly confirms the behavior — after 2 errors, a bare SUCCESS resets the counter and keeps the node active: [4](#0-3) 

All technical claims in the report are accurate. The vulnerability is real.

---

# Audit Report

## Title
Error Counter Reset via Bare SUCCESS Response Prevents Block Node Deactivation

## Summary
In `BlockNode.streamBlocks()`, the `errors` counter is unconditionally reset to `0` after any non-exception response, including a `STATUS=SUCCESS` response that delivers zero block data. A malicious block node operator can exploit this by cycling `maxSubscribeAttempts-1` error responses followed by one bare `SUCCESS` response, keeping the error counter perpetually below the deactivation threshold and preventing the node from ever being marked inactive.

## Finding Description
In `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, the `streamBlocks()` method processes responses in a while loop:

```java
// lines 137–158
boolean serverSuccess = false;
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
    switch (response.getResponseCase()) {
        case BLOCK_ITEMS -> assembler.onBlockItemSet(response.getBlockItems());
        case END_OF_BLOCK -> assembler.onEndOfBlock(response.getEndOfBlock());
        case STATUS -> {
            var status = response.getStatus();
            if (status == SubscribeStreamResponse.Code.SUCCESS) {
                serverSuccess = true;
                break;   // exits switch, falls through to errors.set(0)
            }
            throw new BlockStreamException(...);
        }
        default -> throw new BlockStreamException(...);
    }
    errors.set(0);   // ← resets counter for ALL non-exception paths, including bare SUCCESS
}
``` [1](#0-0) 

When `STATUS=SUCCESS` is received, `break` exits the switch and execution falls to `errors.set(0)` at line 157 before the while condition `!serverSuccess` terminates the loop. The counter is reset even though no block data was delivered.

`onError()` (lines 196–207) is only invoked from the `catch` blocks at lines 159–164. The SUCCESS path never calls `onError()`, so the deactivation threshold check at line 198 (`errors.incrementAndGet() >= maxSubscribeAttempts`) is never reached via this path. [5](#0-4) 

**Root cause:** `errors.set(0)` is placed unconditionally after the switch statement rather than only on paths that confirm actual block data delivery. A `SUCCESS` status with no preceding `BLOCK_ITEMS`/`END_OF_BLOCK` is treated identically to a fully successful block stream.

The existing test at lines 179–185 explicitly confirms this behavior is present and accepted: [4](#0-3) 

## Impact Explanation
With `maxSubscribeAttempts=3` (default per `StreamProperties` line 27), the attacker forces the importer into a perpetual cycle of 2 wasted failed subscribe attempts followed by 1 empty-success attempt, delivering zero blocks per cycle. The node is never deactivated and never falls back to an alternative block node or file source. Block ingestion stalls indefinitely for as long as the malicious node is the selected source.

In `BlockNodeSubscriber.getNode()` (lines 108–131), nodes are iterated in priority order; an active malicious node at the front of the list is always selected first, blocking access to healthy nodes behind it. [6](#0-5) 

## Likelihood Explanation
The precondition is operating a block node that the mirror node importer is configured to connect to — no privileged access to the importer or its infrastructure is required. Block nodes are external, third-party-operated infrastructure. The attack requires only the ability to craft gRPC `SubscribeStreamResponse` messages, which is trivially achievable by any block node operator. The pattern is simple, deterministic, and requires no timing precision: send `N-1` `NOT_AVAILABLE` responses then one `SUCCESS` response, repeat. The `maxSubscribeAttempts` value is static configuration, easily determined by probing.

## Recommendation
Move `errors.set(0)` so it is only executed on paths that confirm actual block data was delivered (i.e., after `BLOCK_ITEMS` or `END_OF_BLOCK` processing), not on the `STATUS=SUCCESS` path. One approach:

```java
case BLOCK_ITEMS -> {
    assembler.onBlockItemSet(response.getBlockItems());
    errors.set(0);
}
case END_OF_BLOCK -> {
    assembler.onEndOfBlock(response.getEndOfBlock());
    errors.set(0);
}
case STATUS -> {
    var status = response.getStatus();
    if (status == SubscribeStreamResponse.Code.SUCCESS) {
        serverSuccess = true;
        break;
    }
    throw new BlockStreamException(...);
}
```

Remove the unconditional `errors.set(0)` after the switch. Alternatively, track whether any block data was received during the session and only reset the counter if `assembler` processed at least one complete block.

## Proof of Concept
With `maxSubscribeAttempts=3`:

1. Mirror node calls `streamBlocks()` → malicious node responds with `NOT_AVAILABLE` → `onError()` increments `errors` to `1`. Node remains active.
2. Mirror node calls `streamBlocks()` again → malicious node responds with `NOT_AVAILABLE` → `onError()` increments `errors` to `2`. Node remains active.
3. Mirror node calls `streamBlocks()` again → malicious node responds with `STATUS=SUCCESS` (no block items) → `errors.set(0)` resets counter to `0`. No exception thrown, `onError()` never called. Node remains active.
4. Return to step 1. The cycle repeats indefinitely. The node is never deactivated. Zero blocks are ingested.

This is directly confirmed by the existing test at lines 164–198 of `BlockNodeTest.java`, which explicitly asserts that after 2 errors, a bare SUCCESS response keeps the node active with a reset error count. [7](#0-6)

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L27-27)
```java
    private int maxSubscribeAttempts = 3;
```

**File:** importer/src/test/java/org/hiero/mirror/importer/downloader/block/BlockNodeTest.java (L164-198)
```java
    void onError(Resources resources) {
        // given
        assertThat(node.isActive()).isTrue();
        var server = runBlockStreamSubscribeService(
                resources,
                ResponsesOrError.fromResponse(subscribeStreamResponse(SubscribeStreamResponse.Code.NOT_AVAILABLE)));

        // when fails twice in a row, the node should still be active
        for (int i = 0; i < 2; i++) {
            assertThatThrownBy(() -> node.streamBlocks(0, commonDownloaderProperties, IGNORE))
                    .isInstanceOf(BlockStreamException.class)
                    .hasMessageContaining("Received status NOT_AVAILABLE from block node");
            assertThat(node.isActive()).isTrue();
        }

        // when stream succeeds, the node is active and the error count is reset
        stopServer(server);
        server = runBlockStreamSubscribeService(
                resources,
                ResponsesOrError.fromResponse(subscribeStreamResponse(SubscribeStreamResponse.Code.SUCCESS)));
        node.streamBlocks(0, commonDownloaderProperties, IGNORE);
        assertThat(node.isActive()).isTrue();

        // when fails three times in a row
        stopServer(server);
        runBlockStreamSubscribeService(
                resources,
                ResponsesOrError.fromResponse(subscribeStreamResponse(SubscribeStreamResponse.Code.NOT_AVAILABLE)));
        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(() -> node.streamBlocks(0, commonDownloaderProperties, IGNORE))
                    .isInstanceOf(BlockStreamException.class)
                    .hasMessageContaining("Received status NOT_AVAILABLE from block node");
            boolean expected = i < 2;
            assertThat(node.isActive()).isEqualTo(expected);
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
