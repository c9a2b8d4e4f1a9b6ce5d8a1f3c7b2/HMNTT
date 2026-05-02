### Title
Malicious Block Node Operator Can Cause Sustained Block Ingestion Blackout via Controlled Inactivation and Force-Readmit Bypass

### Summary
A block node operator can deliberately trigger the `onError()` inactivation path by returning error status codes, then prevent the force-readmit fallback in `getNode()` by returning an empty block range during `serverStatus` queries. When all configured block nodes are simultaneously held inactive this way, the importer cannot ingest blocks for the full `readmitDelay` duration — a minimum of 10 seconds per cycle enforced by `@DurationMin(seconds=10)`. The attack is repeatable indefinitely.

### Finding Description

**Code locations:**

`StreamProperties.java` lines 29–31 — enforces minimum readmit delay: [1](#0-0) 

`BlockNode.java` lines 196–206 — `onError()` marks node inactive after `maxSubscribeAttempts` (default 3) errors and sets `readmitTime`: [2](#0-1) 

`BlockNode.java` lines 99–112 — `getBlockRange()` returns `EMPTY_BLOCK_RANGE` on any exception or when `firstAvailableBlock == -1`: [3](#0-2) 

`BlockNodeSubscriber.java` lines 108–131 — `getNode()` fallback: force-readmits inactive nodes only if `hasBlock()` returns true; if all inactive nodes return empty block range, throws `BlockStreamException`: [4](#0-3) 

`BlockNodeSubscriber.java` lines 133–145 — `hasBlock()` calls `getBlockRange()` and returns false on empty range, preventing `tryReadmit(true)` from being reached: [5](#0-4) 

**Root cause and exploit flow:**

The design assumes that when all nodes are inactive, the force-readmit fallback (second loop in `getNode()`) will always find at least one node that can serve the block. This assumption fails when the attacker controls the block node's responses to `serverStatus`. The two-phase attack:

1. **Phase 1 — Inactivation**: The attacker's block node returns `NOT_AVAILABLE` (or any non-SUCCESS status) on `subscribeBlockStream`. Each such response triggers `onError()`. After `maxSubscribeAttempts` (default 3) consecutive errors, `active = false` and `readmitTime = now + readmitDelay`.

2. **Phase 2 — Force-readmit bypass**: When `getNode()` enters the fallback loop and calls `hasBlock()` → `getBlockRange()` → `serverStatus`, the attacker's node returns an error or sets `firstAvailableBlock = -1`. `getBlockRange()` catches the exception and returns `EMPTY_BLOCK_RANGE`. `hasBlock()` returns `false`. `tryReadmit(true)` is never called. The node remains inactive.

3. **Result**: With all nodes inactive and all returning empty block range, `getNode()` throws `BlockStreamException("No block node can provide block X")`. `CompositeBlockSource` catches it and calls `sourceHealth.onError()`, then waits `frequency` (default 100ms) before retrying — but every retry hits the same dead end until `readmitDelay` expires.

4. **Cycle repeats**: Once `readmitDelay` expires, `tryReadmit(false)` re-activates the node. The attacker immediately causes 3 more errors → node inactive again → repeat indefinitely.

**Why existing checks are insufficient:**

The force-readmit fallback (`tryReadmit(true)`) is the intended mitigation, but it is gated behind `hasBlock()` returning true: [6](#0-5) 

The attacker fully controls the `serverStatus` response, so they can always make `hasBlock()` return false. The `@DurationMin(seconds=10)` constraint on `readmitDelay` means the operator cannot reduce the blackout window below 10 seconds even if they wanted to. [1](#0-0) 

### Impact Explanation

**In `BLOCK_NODE` source mode**: No fallback exists. Block ingestion halts for the full `readmitDelay` per cycle (minimum 10 seconds, default 60 seconds). The attack is repeatable with no rate limiting, causing indefinite periodic blackouts.

**In `AUTO` source mode**: `CompositeBlockSource` switches to `BlockFileSource` after 3 consecutive failures of the block node subscriber: [7](#0-6) 

This mitigates the impact in AUTO mode, but only if cloud storage is available and up-to-date. If the deployment relies solely on block nodes (e.g., `sourceType=BLOCK_NODE`), the impact is a guaranteed periodic ingestion blackout. The severity matches the stated scope: griefing with no economic damage, but causing data ingestion delays.

### Likelihood Explanation

**Preconditions:**
- The attacker must operate a block node that is configured in the importer's `nodes[]` list.
- For a single-node deployment (common in testing and small production setups), one attacker is sufficient.
- For multi-node deployments, the attacker must control all configured nodes simultaneously — a stronger precondition that reduces likelihood.

**Feasibility**: The attack requires only standard gRPC protocol responses (returning `NOT_AVAILABLE` status and `firstAvailableBlock=-1`). No cryptographic bypass or privileged access is needed. The attacker is simply a block node operator behaving maliciously. The attack is fully repeatable with no cooldown on the attacker's side.

### Recommendation

1. **Decouple force-readmit from `hasBlock()`**: In the fallback loop, call `tryReadmit(true)` unconditionally for at least one inactive node (e.g., the highest-priority one), then attempt streaming. Do not gate force-readmission on a `serverStatus` call that the attacker controls.

2. **Remove or reduce the `@DurationMin(seconds=10)` floor**: If operators want a shorter readmit delay to reduce blackout windows, the constraint should not prevent it. The minimum should be configurable down to at least 1 second.

3. **Add a hard upper bound on consecutive blackout cycles**: Track how many consecutive `readmitDelay` cycles have elapsed with no successful block ingestion and trigger an alert or automatic failover.

4. **In `BLOCK_NODE` mode, add a fallback**: Even when `sourceType=BLOCK_NODE`, consider falling back to file source after sustained failure, rather than looping indefinitely.

### Proof of Concept

**Setup**: Configure the importer with a single block node pointing to an attacker-controlled gRPC server. Set `sourceType=BLOCK_NODE`.

**Step 1 — Inactivation** (repeat 3 times):
```
Attacker's subscribeBlockStream handler returns:
  SubscribeStreamResponse { status: NOT_AVAILABLE }
```
After 3 calls, `BlockNode.onError()` sets `active=false`, `readmitTime=now+readmitDelay`.

**Step 2 — Force-readmit bypass** (during each `getNode()` fallback call):
```
Attacker's serverStatus handler returns:
  ServerStatusResponse { firstAvailableBlock: -1 }
  // OR simply closes the connection with an error
```
`getBlockRange()` returns `EMPTY_BLOCK_RANGE`. `hasBlock()` returns false. `tryReadmit(true)` is never called.

**Step 3 — Observe blackout**:
`getNode()` throws `BlockStreamException`. `CompositeBlockSource` logs the error and retries after `frequency` (100ms). Every retry for the next `readmitDelay` seconds (minimum 10s) hits the same dead end. No blocks are ingested.

**Step 4 — Repeat**:
After `readmitDelay` expires, `tryReadmit(false)` re-activates the node. Return to Step 1. The cycle repeats indefinitely with a guaranteed minimum 10-second blackout per cycle.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L29-31)
```java
    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L58-76)
```java
    private SourceHealth getSourceHealth() {
        return switch (properties.getSourceType()) {
            case AUTO -> {
                if (blockNodeDiscoveryService.getBlockNodes().isEmpty()) {
                    yield blockFileSourceHealth;
                }

                if (!current.get().isHealthy()) {
                    var sourceHealth = current.get() == blockNodeSubscriberSourceHealth
                            ? blockFileSourceHealth
                            : blockNodeSubscriberSourceHealth;
                    current.set(sourceHealth);
                }

                yield current.get();
            }
            case BLOCK_NODE -> blockNodeSubscriberSourceHealth;
            case FILE -> blockFileSourceHealth;
        };
```
