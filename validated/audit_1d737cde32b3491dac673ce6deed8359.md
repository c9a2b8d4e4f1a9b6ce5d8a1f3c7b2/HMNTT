I have verified all code references in the claim against the actual source. Here is my assessment:

**All referenced code paths are confirmed:**

- `StreamProperties.java` — `maxSubscribeAttempts=3`, `readmitDelay=1m`, `@DurationMin(seconds=10)` minimum [1](#0-0) 
- `BlockNode.onError()` — deactivates after `maxSubscribeAttempts` errors [2](#0-1) 
- `BlockNode.streamBlocks()` — throws on non-SUCCESS, triggering `onError()` [3](#0-2) 
- `BlockNodeSubscriber.getNode()` force-readmit path calls `hasBlock()` on inactive nodes [4](#0-3) 
- `hasBlock()` calls `node.getBlockRange()` — a live gRPC `serverStatus` call [5](#0-4) 
- `getBlockRange()` returns `EMPTY_BLOCK_RANGE` on any exception [6](#0-5) 
- `CompositeBlockSource` `BLOCK_NODE` mode has no fallback [7](#0-6) 
- Auto-discovery from `registeredNodeRepository` is confirmed [8](#0-7) 

---

# Audit Report

## Title
Malicious Block Node Can Cause Repeatable Block Ingestion Blackouts via Controlled Error Cycling

## Summary
A block node operator can deliberately send exactly `maxSubscribeAttempts` (default: 3) error responses to trigger `active=false` on their node, then withhold `serverStatus` responses to defeat the force-readmit fallback, causing a block ingestion blackout lasting the full `readmitDelay` (minimum 10 seconds, default 1 minute). This cycle is indefinitely repeatable at zero cost to the attacker.

## Finding Description

**`StreamProperties.java`** defines the thresholds governing node deactivation and readmission: [1](#0-0) 

**`BlockNode.onError()`** deactivates the node after `maxSubscribeAttempts` consecutive failures, resetting the error counter and setting a future `readmitTime`: [2](#0-1) 

**`BlockNode.streamBlocks()`** throws `BlockStreamException` on any non-SUCCESS status response, which triggers `onError()`. Note that `errors.set(0)` at line 157 is only reached when the switch does not throw — it is never reached for `NOT_AVAILABLE` or other error codes: [9](#0-8) 

**`BlockNodeSubscriber.getNode()`** contains the intended force-readmit fallback: when all active nodes fail, it iterates inactive nodes and calls `hasBlock()` on each. If `hasBlock()` returns `true`, the node is force-readmitted: [10](#0-9) 

**The root cause** is that `hasBlock()` calls `node.getBlockRange()`, which makes a live gRPC `serverStatus` call to the attacker's node: [5](#0-4) 

**`getBlockRange()`** returns `EMPTY_BLOCK_RANGE` on any exception (including timeout after `responseTimeout`, default 400ms): [11](#0-10) 

The **failed assumption** is that an inactive node will always cooperate with `serverStatus` requests. Because the attacker controls the block node process, they can selectively drop or time out `serverStatus` responses while in the deactivated cooldown window, causing `hasBlock()` to return `false`, preventing force-readmit, and making `getNode()` throw `BlockStreamException("No block node can provide block N")`.

**Exploit flow (single malicious node scenario):**

1. Attacker's node sends `NOT_AVAILABLE` (or any non-SUCCESS) status on 3 consecutive subscribe calls → `onError()` fires 3 times → `active = false`, `errors` reset to 0, `readmitTime = now + readmitDelay`.
2. `getNode()` is called again: node is inactive → added to `inactiveNodes`.
3. Force-readmit path calls `hasBlock()` → calls `serverStatus` on attacker's node → attacker returns no response or times out → `EMPTY_BLOCK_RANGE` → `hasBlock()` returns `false`.
4. `getNode()` throws `BlockStreamException("No block node can provide block N")`.
5. In `BLOCK_NODE` source mode, `CompositeBlockSource` has no fallback; it keeps failing every `frequency` interval (default 100ms) for the entire `readmitDelay` window.
6. After `readmitDelay` expires, `tryReadmit(false)` succeeds → `active = true`.
7. Attacker resumes `serverStatus` responses → `hasBlock()` returns `true` → streaming resumes.
8. Attacker immediately sends 3 more error responses → repeat from step 1.

**Why existing checks are insufficient:**

- The force-readmit fallback (lines 122–128 of `BlockNodeSubscriber.java`) is the primary defense, but it is entirely dependent on the attacker's node cooperating with `serverStatus` — which the attacker controls.
- In `BLOCK_NODE` source mode, `CompositeBlockSource` unconditionally delegates to `blockNodeSubscriberSourceHealth` with no fallback to `BlockFileSource`: [12](#0-11) 
- The `AUTO` mode fallback to `BlockFileSource` after 3 `BlockNodeSubscriber` failures is a partial mitigation, but it only applies when `sourceType=AUTO` and a file source is available. In `BLOCK_NODE` mode there is no fallback.
- There is no rate-limiting, jitter, or exponential backoff on how quickly the error counter can be re-accumulated after a readmit.

## Impact Explanation

In `BLOCK_NODE` source mode (or `AUTO` mode when the file source is also unavailable, or when the malicious node is the only configured node), a single malicious block node operator can cause the importer to stop ingesting blocks for `readmitDelay` per cycle (minimum 10 seconds, default 1 minute). The cycle repeats indefinitely with no cost to the attacker. This is a denial-of-service against block ingestion, causing the mirror node's data to fall behind the chain by an unbounded amount over time.

## Likelihood Explanation

Block nodes are auto-discovered from `registeredNodeRepository`, populated from on-chain registered nodes: [8](#0-7) 

Any operator of a registered block node that is auto-discovered by the importer can perform this attack without any additional privilege, provided their node is the sole or highest-priority block node used by the importer. The attack requires only the ability to control the gRPC responses of one's own block node — a trivial capability for any node operator. The attack is repeatable indefinitely and requires no special tooling beyond a modified block node implementation.

## Recommendation

1. **Decouple force-readmit from a live attacker-controlled call.** The force-readmit decision should not depend on a live `serverStatus` call to the inactive node. Instead, force-readmit should be triggered unconditionally by time expiry (`readmitTime`) alone — i.e., `tryReadmit(false)` should be sufficient to re-activate a node after `readmitDelay` has elapsed, without requiring a successful `serverStatus` response.
2. **Apply exponential backoff with jitter** to the error counter re-accumulation after a readmit, so that a node that was just readmitted cannot be immediately re-deactivated in the same polling cycle.
3. **In `BLOCK_NODE` mode**, consider adding a fallback to `BlockFileSource` after sustained `BlockNodeSubscriber` failures, consistent with the `AUTO` mode behavior.
4. **Separate the `serverStatus` check** (used for `hasBlock()`) from the readmit decision. The `hasBlock()` check should only be used to select among already-active nodes, not as a gate for re-activating inactive ones.

## Proof of Concept

```
Setup: Mirror node configured with sourceType=BLOCK_NODE, single block node (attacker-controlled).

Step 1: Attacker's node responds to subscribeBlockStream with NOT_AVAILABLE status.
        → BlockNode.streamBlocks() throws BlockStreamException
        → BlockNode.onError() increments errors to 1 (active=true)

Step 2: Repeat step 1 twice more.
        → errors reaches maxSubscribeAttempts (3)
        → BlockNode.onError(): active=false, errors=0, readmitTime=now+60s

Step 3: BlockNodeSubscriber.getNode() is called.
        → node.tryReadmit(false).isActive() == false → added to inactiveNodes
        → Force-readmit path: hasBlock() → getBlockRange() → serverStatus gRPC call
        → Attacker's node does not respond within responseTimeout (400ms)
        → getBlockRange() catches exception, returns EMPTY_BLOCK_RANGE
        → hasBlock() returns false
        → getNode() throws BlockStreamException("No block node can provide block N")

Step 4: CompositeBlockSource.get() catches the exception, increments SourceHealth.errors.
        No fallback in BLOCK_NODE mode. Repeats every 100ms for 60 seconds.

Step 5: After 60 seconds, tryReadmit(false) succeeds → active=true.
        Attacker resumes serverStatus responses → hasBlock() returns true → streaming resumes.
        Attacker immediately sends 3 NOT_AVAILABLE responses → back to Step 2.

Result: ~60 seconds of block ingestion blackout per cycle, indefinitely repeatable.
```

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L26-35)
```java
    @Min(1)
    private int maxSubscribeAttempts = 3;

    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L142-164)
```java
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
        } catch (BlockStreamException ex) {
            onError();
            throw ex;
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L58-77)
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
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeDiscoveryService.java (L73-91)
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
```
