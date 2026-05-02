The code references are all verified. Let me confirm the exact lines before rendering the final output.

All code references verified against the actual source. Every claim in the report maps to confirmed lines.

---

# Audit Report

## Title
Missing Circuit Breaker for `serverStatus()` Failures Enables Unbounded Error Log Flooding by Malicious Block Node

## Summary
`BlockNode.getBlockRange()` swallows all gRPC exceptions from `serverStatus()`, logs at `ERROR` level, and returns `EMPTY_BLOCK_RANGE` — but never calls `onError()`. Because `onError()` is the sole mechanism that marks a node inactive and enforces a cooldown, a block node that permanently rejects `serverStatus()` is never penalized: it is re-queried on every block retrieval, producing an unbounded stream of `ERROR`-level log entries with no backoff or circuit-breaker.

## Finding Description

**Step 1 — `getNode()` queries every active node on every block retrieval.**

`BlockNodeSubscriber.getNode()` iterates the full node list and calls `hasBlock()` for each node that `isActive()`: [1](#0-0) 

**Step 2 — `hasBlock()` delegates to `getBlockRange()`.**

`hasBlock()` calls `node.getBlockRange()` and returns `false` when the returned range is empty: [2](#0-1) 

**Step 3 — `getBlockRange()` catches all exceptions, logs at ERROR, and returns `EMPTY_BLOCK_RANGE` without calling `onError()`.**

```java
} catch (Exception ex) {
    log.error("Failed to get server status for {}", this, ex);
    return EMPTY_BLOCK_RANGE;
}
``` [3](#0-2) 

`EMPTY_BLOCK_RANGE` is `Range.closedOpen(0L, 0L)`, which Guava's `Range.isEmpty()` returns `true` for: [4](#0-3) 

**Step 4 — `streamBlocks()` failures DO call `onError()` — the asymmetry.**

Both `catch` blocks in `streamBlocks()` call `onError()`: [5](#0-4) 

`onError()` increments an error counter and, after `maxSubscribeAttempts` (default: **3**) consecutive failures, sets `active = false` and schedules a `readmitDelay` (default: **1 minute**) cooldown: [6](#0-5) 

**Step 5 — `getBlockRange()` has no equivalent protection.**

Because `getBlockRange()` never calls `onError()`, a node that always fails `serverStatus()` remains `active = true` indefinitely. It is never placed in the `inactiveNodes` list, never cooled down, and is re-queried on every call to `getNode()`.

The `responseTimeout` for each `serverStatus()` call defaults to **400 ms**: [7](#0-6) 

## Impact Explanation

Every call to `BlockNodeSubscriber.doGet()` triggers a `serverStatus()` RPC to the malicious node. With a 400 ms timeout, each call blocks for up to 400 ms and emits one `log.error(...)` entry. Under continuous block ingestion (the normal operating mode), this produces a sustained, unbounded stream of `ERROR`-level log entries — one per block retrieval per malicious node — with no backoff, no rate limit, and no circuit-breaker. Consequences include:

- **Log storage exhaustion**: high-volume ERROR output can fill disk or exceed log-aggregation quotas.
- **Alert saturation**: monitoring systems that page on ERROR rates are flooded with noise.
- **Signal burial**: legitimate errors from healthy nodes are obscured by the flood.
- **Latency overhead**: each block retrieval is delayed by up to 400 ms per malicious node before falling through to a healthy node.

The malicious node is never excluded from the node list for the lifetime of the process unless manually removed from configuration.

## Likelihood Explanation

The precondition is controlling a registered block node. This is satisfied by:

1. A configured node whose operator turns malicious (requires importer admin access to initially register, but no ongoing privilege once registered).
2. An auto-discovered node registered via a Hedera governance transaction — a lower-privilege path.

Once in place, the attack requires only that the node's gRPC server return any error (e.g., `UNAVAILABLE`, connection reset, deadline exceeded) on `serverStatus()` calls. This is trivially implemented, requires zero ongoing effort, and is indefinitely repeatable at negligible cost to the attacker.

## Recommendation

Apply the same circuit-breaker logic to `getBlockRange()` failures that already exists for `streamBlocks()` failures. Specifically, call `onError()` inside the `catch` block of `getBlockRange()`:

```java
} catch (Exception ex) {
    log.error("Failed to get server status for {}", this, ex);
    onError();                  // <-- add this
    return EMPTY_BLOCK_RANGE;
}
``` [3](#0-2) 

This reuses the existing `maxSubscribeAttempts` / `readmitDelay` mechanism: after 3 consecutive `serverStatus()` failures the node is marked inactive for 1 minute, exactly mirroring the behaviour already enforced for streaming failures. [8](#0-7) 

Optionally, a separate counter and threshold for status failures could be introduced if operators want independent tuning, but reusing the existing properties is the minimal, consistent fix.

## Proof of Concept

1. Register a block node whose gRPC server always returns `UNAVAILABLE` on `serverStatus()` (trivial with any gRPC server stub).
2. Start the importer with this node in the node list alongside one healthy node.
3. Observe that on every call to `BlockNodeSubscriber.get()`:
   - `getNode()` calls `hasBlock()` on the malicious node first (it is always `active = true`).
   - `getBlockRange()` times out after 400 ms and logs `ERROR: Failed to get server status for BlockNode(malicious-host:40840)`.
   - The node is **not** marked inactive; `isActive()` remains `true`.
4. After N block retrievals, N `ERROR` log entries have been emitted for the malicious node, with no sign of backoff or exclusion.
5. For contrast, configure the same node to fail `streamBlocks()` instead: after exactly 3 failures `isActive()` returns `false` and the node is cooled down for 1 minute — confirming the asymmetry. [9](#0-8) [5](#0-4)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L108-120)
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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L133-137)
```java
    private static boolean hasBlock(final AtomicLong nextBlockNumber, final BlockNode node) {
        final var blockRange = node.getBlockRange();
        if (blockRange.isEmpty()) {
            return false;
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L50-50)
```java
    private static final Range<Long> EMPTY_BLOCK_RANGE = Range.closedOpen(0L, 0L);
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
