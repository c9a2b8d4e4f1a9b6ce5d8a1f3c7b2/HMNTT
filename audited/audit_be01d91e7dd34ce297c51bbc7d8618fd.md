### Title
Malicious Block Node Can Persistently Evade Inactivity Penalty via Deliberate `serverStatus()` Timeout

### Summary
`BlockNode.getBlockRange()` catches all exceptions from a timed-out `serverStatus()` call and silently returns `EMPTY_BLOCK_RANGE` without invoking `onError()`. Because the error counter is never incremented through this path, a block node that deliberately delays every status response beyond `responseTimeout` (400 ms default) is never marked inactive, allowing it to cause a 400 ms stall and an `ERROR`-level log entry on every single block-selection cycle, indefinitely.

### Finding Description

**Exact code path:**

`StreamProperties.java` line 35 sets the default timeout: [1](#0-0) 

`BlockNode.getBlockRange()` applies that timeout and swallows every exception: [2](#0-1) 

`BlockNodeSubscriber.hasBlock()` treats `EMPTY_BLOCK_RANGE` as "node has no blocks": [3](#0-2) 

`BlockNodeSubscriber.getNode()` skips the node and, if no other node qualifies, throws: [4](#0-3) 

**Root cause — failed assumption:** The `onError()` / inactivity mechanism is only reachable through `streamBlocks()`: [5](#0-4) 

`getBlockRange()` has its own independent catch block that returns `EMPTY_BLOCK_RANGE` and never calls `onError()`. The design assumes that a node which fails status checks is merely "empty" rather than "misbehaving," so no penalty is applied. A malicious node exploits this gap to remain permanently active while being permanently useless.

**Auto-discovery amplifies reach:** With `autoDiscoveryEnabled=true`, block nodes are pulled from `RegisteredNodeRepository`. Any network participant who can register a `BLOCK_NODE`-typed service endpoint (a standard, unprivileged network operation) will have their node auto-discovered by every mirror-node importer: [6](#0-5) 

### Impact Explanation

- **Single malicious node among healthy peers:** Every `getNode()` call incurs a 400 ms stall while waiting for the timeout, plus an `ERROR`-level log entry. This repeats on every scheduled block-fetch cycle with no self-healing.
- **Sole configured/discovered node:** `getNode()` throws `BlockStreamException` every cycle. `CompositeBlockSource` counts 3 consecutive failures and switches away from `BLOCK_NODE` source (in `AUTO` mode) or fails completely (in `BLOCK_NODE`-only mode), halting block ingestion.
- **Multiple malicious nodes:** Stalls are additive (N × 400 ms per cycle), compounding the delay.

### Likelihood Explanation

The attacker only needs to operate a block node that is reachable by the importer — either by being manually configured by an operator or, more accessibly, by registering a tier-1 block node endpoint in the network's node registry when auto-discovery is enabled. Delaying a gRPC response is trivially implemented (e.g., `Thread.sleep` in the server handler). The attack is repeatable indefinitely because the node is never penalized, requires no ongoing authentication, and survives importer restarts.

### Recommendation

1. **Call `onError()` (or a dedicated status-error counter) inside `getBlockRange()`'s catch block**, so that a node which repeatedly times out on status checks is eventually marked inactive and subject to the existing `readmitDelay` cooldown — exactly as streaming errors are handled.
2. Alternatively, introduce a separate consecutive-status-failure counter with its own threshold, so transient network hiccups do not immediately deactivate a node while persistent misbehavior still does.
3. Consider adding a circuit-breaker that skips the `serverStatus()` call entirely for a node already known to be timing out, rather than paying the full `responseTimeout` cost on every cycle.

### Proof of Concept

1. Stand up a gRPC server implementing `BlockNodeServiceGrpc.BlockNodeServiceImplBase` whose `serverStatus()` handler sleeps for 500 ms before responding (just over the 400 ms default).
2. Configure the mirror-node importer to use only this node (or register it via auto-discovery).
3. Start the importer. Observe:
   - Every scheduled block-fetch cycle logs `ERROR: Failed to get server status for BlockNode(...)` with a `DEADLINE_EXCEEDED` cause.
   - `node.isActive()` remains `true` — the node is never marked inactive.
   - `getNode()` throws `BlockStreamException("No block node can provide block N")` on every cycle.
   - Block ingestion halts; the error repeats indefinitely without any back-off or recovery.
4. Confirm that adding a second healthy node causes the importer to recover, but the malicious node still consumes 400 ms on every cycle before the healthy node is tried.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L33-35)
```java
    @DurationMin(millis = 100)
    @NotNull
    private Duration responseTimeout = Duration.ofMillis(400);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L99-112)
```java
    public Range<Long> getBlockRange() {
        try {
            final var blockNodeService = BlockNodeServiceGrpc.newBlockingStub(channel)
                    .withDeadlineAfter(streamProperties.getResponseTimeout());
            final var response = blockNodeService.serverStatus(SERVER_STATUS_REQUEST);
            final long firstBlockNumber = response.getFirstAvailableBlock();
            return firstBlockNumber != -1
                    ? Range.closed(firstBlockNumber, response.getLastAvailableBlock())
                    : EMPTY_BLOCK_RANGE;
        } catch (Exception ex) {
            log.error("Failed to get server status for {}", this, ex);
            return EMPTY_BLOCK_RANGE;
        }
    }
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L133-145)
```java
    private static boolean hasBlock(final AtomicLong nextBlockNumber, final BlockNode node) {
        final var blockRange = node.getBlockRange();
        if (blockRange.isEmpty()) {
            return false;
        }

        if (nextBlockNumber.get() == EARLIEST_AVAILABLE_BLOCK_NUMBER) {
            nextBlockNumber.set(blockRange.lowerEndpoint());
            return true;
        } else {
            return blockRange.contains(nextBlockNumber.get());
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeDiscoveryService.java (L73-92)
```java
    private List<BlockNodeProperties> discover() {
        if (!blockProperties.isAutoDiscoveryEnabled()) {
            return Collections.emptyList();
        }

        try {
            final var nodes = registeredNodeRepository.findAllByDeletedFalseAndTypeContains(
                    RegisteredNodeType.BLOCK_NODE.getId());

            final List<BlockNodeProperties> propertiesList = new ArrayList<>(nodes.size());
            for (final var node : nodes) {
                toBlockNodeProperties(propertiesList, node.getServiceEndpoints());
            }

            return propertiesList;
        } catch (Exception ex) {
            log.error("Error during block nodes discovery: ", ex);
            return Collections.emptyList();
        }
    }
```
