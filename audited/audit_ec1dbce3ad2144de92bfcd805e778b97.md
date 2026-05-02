### Title
Error Counter Reset Bypass via Intra-Stream `errors.set(0)` Allows Indefinite Griefing of Block Node Deactivation

### Summary
In `BlockNode.streamBlocks()`, `errors.set(0)` is called after every successful response message (`BLOCK_ITEMS`, `END_OF_BLOCK`) within the streaming loop, not only after a fully successful subscription. A malicious block node operator can exploit this by sending one valid `BLOCK_ITEMS` response at the start of each subscription call to reset the cross-call error counter before deliberately causing an error, permanently preventing the node from ever being marked inactive regardless of how many consecutive failed calls occur.

### Finding Description
**Exact code location**: `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, `streamBlocks()`, line 157; `onError()`, lines 196–206.

**Root cause**: The `errors` field is an `AtomicInteger` that persists across calls to `streamBlocks()`. Its intended semantic (per the Javadoc comment on `onError()` and the `maxSubscribeAttempts` property description) is to count *consecutive failed subscription attempts*. However, `errors.set(0)` is placed at the bottom of the per-response `while` loop body:

```java
// BlockNode.java lines 138–158
while (!serverSuccess && (response = grpcCall.read(...)) != null) {
    switch (response.getResponseCase()) {
        case BLOCK_ITEMS -> assembler.onBlockItemSet(response.getBlockItems());
        case END_OF_BLOCK -> assembler.onEndOfBlock(response.getEndOfBlock());
        case STATUS -> { ... throw or set serverSuccess ... }
        default -> throw new BlockStreamException(...);
    }
    errors.set(0);   // ← resets after ANY successful per-message case
}
``` [1](#0-0) 

`onError()` increments the counter only when an exception escapes `streamBlocks()`:

```java
// BlockNode.java lines 196–207
private void onError() {
    errorsMetric.increment();
    if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
        active = false; ...
    }
}
``` [2](#0-1) 

**Exploit flow** (with default `maxSubscribeAttempts = 3`): [3](#0-2) 

1. `errors` starts at 0.
2. **Call N** to `streamBlocks()`: attacker's node sends one syntactically valid `BLOCK_ITEMS` message (containing a proper `BLOCK_HEADER`). `assembler.onBlockItemSet()` succeeds, the switch falls through, and `errors.set(0)` executes — resetting `errors` from whatever accumulated value back to 0.
3. Attacker then sends an error status (e.g. `NOT_AVAILABLE`) or drops the connection. A `BlockStreamException` is thrown, `onError()` runs, `errors` becomes 1.
4. **Call N+1**: repeat step 2–3. `errors` is reset to 0 again before `onError()` can push it to 2.
5. `errors` never reaches `maxSubscribeAttempts` (3); `active` is never set to `false`.

**Why existing checks fail**: The `onError()` guard (`errors.incrementAndGet() >= maxSubscribeAttempts`) is correct in isolation, but the intra-loop `errors.set(0)` at line 157 fires before `onError()` can accumulate across calls. The existing test `onError` (BlockNodeTest.java lines 164–198) only validates the case where errors occur with *no* preceding valid response — it does not cover the interleaved-reset scenario. [4](#0-3) 

### Impact Explanation
A malicious block node that is registered in the mirror node's configuration (or auto-discovered) can permanently avoid deactivation. The mirror node will keep selecting it as the streaming source, wasting connection and processing resources on every scheduling cycle. If the malicious node is the highest-priority or only configured node, block ingestion stalls indefinitely. The impact is griefing/availability degradation with no economic damage to the broader network — consistent with the Medium classification.

### Likelihood Explanation
Any operator of a block node that is listed in the mirror node's configuration (no special cryptographic privilege required) can execute this attack. The technique requires only the ability to control the gRPC response stream, which is the normal capability of a block node operator. The attack is trivially repeatable and requires no timing precision — one valid `BLOCK_ITEMS` frame per call is sufficient.

### Recommendation
Move `errors.set(0)` outside the per-response loop so it only executes when the entire subscription completes successfully (i.e., after the loop exits with `serverSuccess == true`):

```java
// After the while loop, not inside it:
while (!serverSuccess && (response = grpcCall.read(...)) != null) {
    switch (...) { ... }
    // REMOVE errors.set(0) from here
}
if (serverSuccess) {
    errors.set(0);   // only reset on full success
}
```

This ensures the counter reflects true consecutive-failure semantics across subscription attempts.

### Proof of Concept
**Preconditions**: A block node controlled by the attacker is registered in the mirror node's `hiero.mirror.importer.block.nodes` configuration (or auto-discovered). `maxSubscribeAttempts = 3` (default).

**Steps**:
1. Attacker's gRPC server, on each `subscribeBlockStream` call, sends exactly one `SubscribeStreamResponse` with `BLOCK_ITEMS` containing a valid `BLOCK_HEADER` for the requested block number.
2. Immediately after, the server sends a `STATUS = NOT_AVAILABLE` response (or closes the stream with a gRPC error).
3. Observe: `BlockNode.streamBlocks()` processes the `BLOCK_ITEMS` message, executes `errors.set(0)` (line 157), then throws `BlockStreamException` on the status, calling `onError()` which sets `errors = 1`.
4. On the next scheduler invocation, `streamBlocks()` is called again. Repeat step 1–3. `errors` is reset to 0 before `onError()` increments it, so it returns to 1.
5. After any number of iterations, `errors` never reaches 3, `active` remains `true`, and the node is never deactivated.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L26-27)
```java
    @Min(1)
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
