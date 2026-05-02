All five code references check out exactly against the actual source. Here is the audit result:

---

Audit Report

## Title
Malicious Block Node Can Cause Intermittent Ingestion Stalls via Deliberate `serverStatus()` Response Timing Near Deadline

## Summary
`BlockNode.getBlockRange()` applies a configurable gRPC deadline to `serverStatus()` calls but silently catches all exceptions — including deadline-exceeded — returning `EMPTY_BLOCK_RANGE` without ever invoking `onError()`. Because `onError()` is the sole mechanism that increments the error counter and eventually sets `active = false`, a block node operator who deliberately delays responses to just under `responseTimeout` incurs zero penalty and remains permanently eligible for node selection, causing repeated ingestion stalls.

## Finding Description

**`StreamProperties.java` — default timeout:**
`responseTimeout` defaults to 400 ms with a minimum of 100 ms enforced by `@DurationMin(millis = 100)`. [1](#0-0) 

**`BlockNode.getBlockRange()` — silent failure path:**
Any exception (including `StatusRuntimeException` with `DEADLINE_EXCEEDED`) is caught, logged, and returns `EMPTY_BLOCK_RANGE`. `onError()` is never called here. [2](#0-1) 

**`BlockNode.onError()` — only reachable from `streamBlocks()`:**
`onError()` is a private method called exclusively from the two catch blocks inside `streamBlocks()`. A node that always times out at the status-check phase never reaches `streamBlocks()` and is therefore invisible to the circuit-breaker. [3](#0-2) [4](#0-3) 

**`BlockNodeSubscriber.hasBlock()` — propagates the empty range:**
`hasBlock()` calls `getBlockRange()` and returns `false` when the range is empty, causing the node to be skipped in selection. [5](#0-4) 

**`BlockNodeSubscriber.getNode()` — exhaustion path:**
`getNode()` iterates all active nodes calling `hasBlock()`, then falls through to inactive nodes, and throws `BlockStreamException("No block node can provide block …")` if none succeed. [6](#0-5) 

**Root cause:** The failed assumption is that a `serverStatus()` timeout is a transient network event. Because `onError()` is never invoked on a `getBlockRange()` failure, the node's `active` flag and `errors` counter are permanently untouched. The `maxSubscribeAttempts` / `readmitDelay` circuit-breaker only fires inside `streamBlocks()`; a node that never reaches the streaming phase bypasses it entirely. [7](#0-6) 

## Impact Explanation

- **Single malicious node (only configured node):** Every `getNode()` call waits the full 400 ms for the status timeout, then throws `BlockStreamException`. Ingestion stalls indefinitely.
- **Malicious node among multiple nodes:** The malicious node is tried first (sorted by `BlockNodeProperties` comparator). Each `getNode()` call wastes up to 400 ms before falling through to a healthy node, adding a sustained latency floor per block.
- **Intermittent variant:** If the response arrives exactly at the deadline boundary, behavior is non-deterministic under system load — sometimes the node appears to have the block, sometimes not — producing unpredictable node selection and sporadic `BlockStreamException` throws indistinguishable from legitimate failures.

## Likelihood Explanation

A block node operator must be statically configured in the importer's config file or registered via the auto-discovery path. In a permissioned deployment this requires admin action; in a semi-open deployment any registered operator can execute this attack. The timing manipulation is trivial: the server-side gRPC handler sleeps for `responseTimeout - ε` ms before responding. No cryptographic material, no special network position, and no memory-safety exploit is required. The attack is fully repeatable with zero ongoing effort once configured.

## Recommendation

1. **Increment the error counter (and potentially deactivate) on `getBlockRange()` failure.** The simplest fix is to call `onError()` — or a dedicated lighter-weight counter increment — inside the `catch` block of `getBlockRange()`, so repeated status-check timeouts eventually trigger the same `active = false` / `readmitDelay` circuit-breaker that `streamBlocks()` uses. [8](#0-7) 

2. **Separate the error threshold for status-check failures** from the streaming threshold if desired, so a single transient timeout does not immediately deactivate a node, but repeated ones do.

3. **Consider tracking consecutive `getBlockRange()` failures** with a dedicated counter and applying a back-off before retrying the same node, mirroring the `maxSubscribeAttempts` / `readmitDelay` logic already present. [7](#0-6) 

## Proof of Concept

1. Register or configure a block node whose gRPC `serverStatus` handler sleeps for `responseTimeout - 1 ms` (e.g., 399 ms) before returning any response (or simply never responds within the deadline).
2. Start the mirror-node importer with this node as the sole (or highest-priority) configured block node.
3. Observe that every call to `BlockNodeSubscriber.doGet()` → `getNode()` → `hasBlock()` → `BlockNode.getBlockRange()` waits the full 400 ms, returns `EMPTY_BLOCK_RANGE`, and — because `onError()` is never called — the node's `active` flag remains `true` and `errors` stays at 0.
4. With a single node: `getNode()` throws `BlockStreamException("No block node can provide block …")` on every cycle; ingestion halts.
5. With multiple nodes: the malicious node is polled first on every cycle, adding ≥400 ms latency per block indefinitely, with no automatic exclusion. [6](#0-5) [2](#0-1)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L27-31)
```java
    private int maxSubscribeAttempts = 3;

    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);
```

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-164)
```java
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
