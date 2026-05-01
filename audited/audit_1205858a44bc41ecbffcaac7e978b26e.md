Looking at the actual code in `BlockNode.java`, I can confirm the behavior and assess the vulnerability.

**Key code facts:**

- `BlockAssembler` is a private inner class of `BlockNode` [1](#0-0) 
- `onEndOfBlock()` clears `pending` at line 266 after successful processing, then returns [2](#0-1) 
- The `return;` after `Utility.handleRecoverableError()` confirms the method does **not** throw — execution returns to the `streamBlocks()` loop, which continues reading [3](#0-2) 
- The stream loop has no rate-limiting or duplicate-message detection [4](#0-3) 

**Critical precondition failure:**

The mirror node is the **gRPC client** — it connects *to* block nodes. For an attacker to exploit this, they must control a server that the mirror node connects to, which requires being in the `BlockNodeDiscoveryService` list or compromising a legitimate node. This is not an unprivileged position. I was unable to read `Utility.handleRecoverableError()` to confirm exact behavior, but the `return;` pattern confirms it does not throw.

---

### Title
Duplicate END_OF_BLOCK Messages Cause Unbounded Recoverable Error Logging in BlockAssembler

### Summary
A malicious block node can send repeated `END_OF_BLOCK` messages after a block has already been finalized. Each duplicate causes `onEndOfBlock()` to find `pending.isEmpty() == true` and invoke `Utility.handleRecoverableError()`, which logs a warning and returns without terminating the stream. The gRPC read loop continues indefinitely, allowing the attacker to flood the mirror node with log warnings.

### Finding Description
In `BlockNode.java`, `BlockAssembler.onEndOfBlock()` (lines 239–272) processes an `END_OF_BLOCK` message by assembling pending block items and calling `blockStreamConsumer.accept(...)`, then clears `pending` at line 266. If a second `END_OF_BLOCK` arrives for the same block, `pending.isEmpty()` is `true` at line 241, so `Utility.handleRecoverableError(...)` is called and the method returns early at line 244. The `streamBlocks()` loop at line 138 has no guard against this — it simply reads the next message. There is no counter, rate limiter, or stream termination triggered by this path. A malicious block node can send an unbounded sequence of `END_OF_BLOCK` messages, each producing a recoverable error log entry. [2](#0-1) [5](#0-4) [6](#0-5) 

### Impact Explanation
The impact is limited to griefing: excessive log output, potential log storage exhaustion, and CPU/IO overhead from repeated warning generation. There is no data corruption, no financial loss, and no block processing bypass. Severity is low-medium.

### Likelihood Explanation
Exploitation requires the attacker to control a server that the mirror node connects to as a block node. This is **not unprivileged** — it requires either being in the `BlockNodeDiscoveryService` configuration or compromising a legitimate block node. A purely external, unprivileged attacker cannot trigger this path. Likelihood is low.

### Recommendation
In `onEndOfBlock()`, after calling `Utility.handleRecoverableError()` for the empty-pending case, throw a `BlockStreamException` instead of returning. This terminates the stream and triggers the existing `onError()` / cooldown logic, preventing unbounded log flooding from a misbehaving node.

```java
if (pending.isEmpty()) {
    throw new BlockStreamException(
        "Received end-of-block for block " + blockNumber + " with no pending items");
}
```

### Proof of Concept
1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. Configure the mirror node to connect to this server as a block node.
3. Send one valid `BLOCK_ITEMS` (with `BLOCK_HEADER`) followed by one valid `END_OF_BLOCK`.
4. Immediately send 10,000 additional `END_OF_BLOCK` messages with the same block number.
5. Observe: the mirror node logs 10,000 recoverable error warnings without terminating the stream, and the loop continues consuming CPU and I/O for each message.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L209-213)
```java
    private final class BlockAssembler {

        private final Consumer<BlockStream> blockStreamConsumer;
        private final List<List<BlockItem>> pending = new ArrayList<>();
        private final Stopwatch stopwatch;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L239-244)
```java
        void onEndOfBlock(final BlockEnd blockEnd) {
            final long blockNumber = blockEnd.getBlockNumber();
            if (pending.isEmpty()) {
                Utility.handleRecoverableError(
                        "Received end-of-block message for block {} while there's no pending block items", blockNumber);
                return;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L264-268)
```java
            }

            pending.clear();
            pendingCount = 0;
            stopwatch.reset();
```
