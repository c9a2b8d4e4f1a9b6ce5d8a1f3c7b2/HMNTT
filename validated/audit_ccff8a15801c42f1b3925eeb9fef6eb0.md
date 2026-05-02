I have verified all code references against the actual source. Here is my assessment:

**All referenced code paths are confirmed:**

- `StreamProperties.java` lines 27/31: `maxSubscribeAttempts = 3`, `readmitDelay = Duration.ofMinutes(1)`, minimum 10s enforced. [1](#0-0) 
- `BlockNode.onError()` lines 196–206: deactivates after `maxSubscribeAttempts` errors. [2](#0-1) 
- `BlockNode.streamBlocks()` lines 152/159–164: any non-SUCCESS status throws `BlockStreamException`, which calls `onError()`. [3](#0-2) 
- `BlockNodeSubscriber.getNode()` lines 122–128: force-readmit path calls `hasBlock()` on inactive nodes. [4](#0-3) 
- `hasBlock()` calls `node.getBlockRange()` (live gRPC `serverStatus` call). [5](#0-4) 
- `getBlockRange()` returns `EMPTY_BLOCK_RANGE` on any exception. [6](#0-5) 
- `CompositeBlockSource` in `BLOCK_NODE` mode has no fallback. [7](#0-6) 
- Auto-discovery via `registeredNodeRepository` confirmed. [8](#0-7) 

---

Audit Report

## Title
Malicious Block Node Can Cause Repeatable Block Ingestion Blackouts via Controlled Error Cycling

## Summary
A block node operator can deliberately send exactly `maxSubscribeAttempts` (default: 3) error responses to trigger `active=false` on their node, then withhold `serverStatus` responses to prevent the force-readmit fallback from activating. This causes block ingestion to fail for the full `readmitDelay` window (minimum 10 seconds, default 1 minute). The cycle is indefinitely repeatable at zero cost to the attacker.

## Finding Description

**Exact code path:**

`StreamProperties.java` defines the thresholds: [1](#0-0) 

`BlockNode.onError()` deactivates the node after `maxSubscribeAttempts` consecutive failures: [2](#0-1) 

`BlockNode.streamBlocks()` calls `onError()` on any non-SUCCESS status response: [9](#0-8) 

The intended mitigation is the force-readmit fallback in `BlockNodeSubscriber.getNode()`: [10](#0-9) 

**Root cause and failed assumption:**

The force-readmit fallback calls `hasBlock()`, which calls `node.getBlockRange()` — a live `serverStatus` gRPC call to the attacker's node: [5](#0-4) 

`getBlockRange()` returns `EMPTY_BLOCK_RANGE` on any exception: [11](#0-10) 

The failed assumption is that an inactive node will always respond to `serverStatus`. Because the attacker controls the block node process, they can selectively drop or timeout `serverStatus` responses while in the deactivated cooldown window, causing `hasBlock()` to return `false`, preventing force-readmit, and making `getNode()` throw `BlockStreamException("No block node can provide block N")`.

**Exploit flow:**

1. Attacker's node sends `NOT_AVAILABLE` (or any non-SUCCESS) status on 3 consecutive subscribe calls → `onError()` fires 3 times → `active = false`, `errors` reset to 0, `readmitTime = now + readmitDelay`.
2. `getNode()` is called again: `tryReadmit(false)` returns false (cooldown not elapsed) → node added to `inactiveNodes`.
3. Force-readmit path calls `hasBlock()` → calls `serverStatus` on attacker's node → attacker returns no response or times out → `EMPTY_BLOCK_RANGE` → `hasBlock()` returns `false`.
4. `getNode()` throws `BlockStreamException("No block node can provide block N")`.
5. In `BLOCK_NODE` source mode, `CompositeBlockSource` has no fallback; it keeps failing every `frequency` interval (default 100ms) for the entire `readmitDelay` window.
6. After `readmitDelay` expires, `tryReadmit(false)` succeeds → `active = true`.
7. Attacker resumes `serverStatus` responses → `hasBlock()` returns `true` → streaming resumes.
8. Attacker immediately sends 3 more error responses → repeat from step 1.

**Why existing checks are insufficient:**

- The force-readmit fallback (lines 122–128 of `BlockNodeSubscriber.java`) is the primary defense against waiting the full `readmitDelay`, but it is entirely dependent on the attacker's node cooperating with `serverStatus` — which the attacker controls.
- The `CompositeBlockSource` `AUTO` mode fallback to `BlockFileSource` after 3 `BlockNodeSubscriber` failures is a partial mitigation, but it only applies when `sourceType=AUTO` and a file source is available. In `BLOCK_NODE` mode there is no fallback: [12](#0-11) 
- There is no rate-limiting, jitter, or exponential backoff on how quickly the error counter can be re-accumulated after a readmit.

## Impact Explanation

In `BLOCK_NODE` source mode (or `AUTO` mode after the file source is also exhausted), a single malicious configured block node can cause the importer to stop ingesting blocks for `readmitDelay` per cycle (minimum 10 seconds, default 1 minute). The cycle repeats indefinitely with no cost to the attacker. This is a denial-of-service against block ingestion, causing the mirror node's data to fall behind the chain by an unbounded amount over time.

## Likelihood Explanation

Block nodes are auto-discovered from `registeredNodeRepository` (populated from on-chain registered nodes): [8](#0-7) 

Any operator of a registered block node that is auto-discovered by the importer can perform this attack without any additional privilege. The attack requires only the ability to control the gRPC responses of one's own block node — a trivial capability for any node operator. The attack is repeatable indefinitely and requires no special tooling beyond a modified block node implementation.

## Recommendation

1. **Decouple force-readmit from attacker-controlled `serverStatus`**: The force-readmit path should not rely on a live gRPC call to the inactive node. Instead, force-readmit should be triggered purely by time (e.g., a shorter secondary timer) or by a separate health-check mechanism that is not under the attacker's control.
2. **Add exponential backoff on re-accumulation**: After a node is readmitted and immediately fails again, apply exponential backoff to `readmitDelay` to prevent rapid cycling.
3. **Require multiple nodes in `BLOCK_NODE` mode**: Enforce a minimum of 2 configured block nodes, or fall back to `AUTO` mode when only one node is configured, to prevent single-node blackouts.
4. **Limit `serverStatus` timeout contribution to force-readmit**: If `getBlockRange()` throws or times out for an inactive node during the force-readmit check, treat it as "unknown" rather than "does not have block", and apply a separate retry with backoff rather than immediately skipping force-readmit.

## Proof of Concept

```
Setup: Mirror node configured with sourceType=BLOCK_NODE, single block node (attacker-controlled).

Step 1: Attacker's node responds to subscribe with NOT_AVAILABLE three times.
  → BlockNode.onError() fires 3 times
  → active=false, readmitTime=now+60s

Step 2: Mirror node calls getNode() for next block.
  → tryReadmit(false): readmitTime not elapsed → node stays inactive → added to inactiveNodes
  → Force-readmit path: hasBlock() → getBlockRange() → serverStatus gRPC call to attacker
  → Attacker drops/times out the serverStatus call
  → getBlockRange() catches exception, returns EMPTY_BLOCK_RANGE
  → hasBlock() returns false
  → getNode() throws BlockStreamException("No block node can provide block N")

Step 3: Mirror node retries every 100ms (frequency) for 60 seconds.
  → All retries fail identically (attacker continues withholding serverStatus)
  → Mirror node falls 60 seconds behind chain per cycle

Step 4: After 60s, tryReadmit(false) succeeds → active=true.
  → Attacker resumes serverStatus → hasBlock() returns true → streaming resumes
  → Attacker immediately sends 3 NOT_AVAILABLE responses → back to Step 1

Result: Indefinitely repeatable ~60s block ingestion blackouts.
```

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L26-31)
```java
    @Min(1)
    private int maxSubscribeAttempts = 3;

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
