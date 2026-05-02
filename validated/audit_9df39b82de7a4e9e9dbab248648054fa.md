All referenced code has been verified against the actual source. Every claim in the report maps to real, confirmed code.

**Verification summary:**

- `tryReadmit(true)` unconditionally sets `active = true` ignoring `readmitTime` — confirmed [1](#0-0) 
- `onError()` sets `active = false` and schedules `readmitTime = now + readmitDelay` after `maxSubscribeAttempts` failures — confirmed [2](#0-1) 
- `getNode()` second pass calls `tryReadmit(true)` on inactive nodes that claim to have the block — confirmed [3](#0-2) 
- `hasBlock()` calls `node.getBlockRange()` which issues a live gRPC `serverStatus` call — confirmed [4](#0-3) 
- `getBlockRange()` trusts the node's self-reported block range without validation — confirmed [5](#0-4) 
- `@DurationMin(seconds = 10)` on `readmitDelay` only enforced at config validation, not at runtime in `tryReadmit(true)` — confirmed [6](#0-5) 
- `CompositeBlockSource.SourceHealth.isHealthy()` switches source after 3 outer failures — confirmed [7](#0-6) 

Nothing in `SECURITY.md` excludes this finding. The "Impacts that only require DDoS" exclusion applies to the "Websites and Apps" section and does not apply here — this is a targeted bypass of a specific cooldown mechanism by a registered node operator, not a volumetric DDoS. The attacker is a registered block node, not a privileged governance address.

---

Audit Report

## Title
`readmitDelay` Cooldown Bypassed via Unconditional Force-Readmit in `BlockNodeSubscriber.getNode()`

## Summary
`BlockNodeSubscriber.getNode()` contains a fallback path that calls `tryReadmit(true)` on any inactive node that claims (via `serverStatus`) to have the requested block. Because `tryReadmit(true)` unconditionally sets `active = true` regardless of the `readmitDelay` timer, a malicious block node operator can cause the importer to re-attempt a deactivated node on every scheduling cycle with zero cooldown, completely nullifying the `readmitDelay` protection.

## Finding Description

**Exact code path:**

`BlockNode.tryReadmit(boolean force)` unconditionally sets `active = true` when `force == true`, ignoring `readmitTime`: [1](#0-0) 

`BlockNode.onError()` — after `maxSubscribeAttempts` (default 3) failures, sets `active = false` and schedules `readmitTime = now + readmitDelay` (default 1 minute): [2](#0-1) 

`BlockNodeSubscriber.getNode()` — first pass calls `tryReadmit(false)` (respects delay); if no active node has the block, second pass calls `hasBlock()` on each inactive node, and if the node claims to have the block, calls `tryReadmit(true)` (bypasses delay) and returns it: [8](#0-7) 

`hasBlock()` calls `node.getBlockRange()`, which issues a live gRPC `serverStatus` call to the block node. The attacker fully controls this response: [4](#0-3) 

`BlockNode.getBlockRange()` trusts the block node's self-reported `firstAvailableBlock`/`lastAvailableBlock` without any validation: [5](#0-4) 

**Root cause:** The design assumes the force-readmit path is a rare last-resort (all nodes inactive). It fails to account for a node that is the sole claimant of a block and can repeatedly cycle: fail → deactivate → immediately force-readmit → fail again. There is no counter, rate limit, or back-off tracking for force-readmit events.

**Exploit flow:**

1. Attacker operates a block node that is the only node claiming to have the next required block.
2. The node fails `streamBlocks()` 3 times (`maxSubscribeAttempts`) → `onError()` → `active = false`, `readmitTime = now + 60s`.
3. On the very next `getNode()` call: first pass calls `tryReadmit(false)` → delay not elapsed → node stays inactive → added to `inactiveNodes`. Second pass calls `hasBlock()` → attacker's `serverStatus` returns a range containing the requested block → `tryReadmit(true)` → `active = true` → node returned.
4. `streamBlocks()` is called → attacker fails it 3 more times → `active = false` again.
5. Steps 3–4 repeat indefinitely with no cooldown.

**Why existing checks fail:**

- `readmitDelay` (`@DurationMin(seconds = 10)`) — only enforced by `tryReadmit(false)`; `tryReadmit(true)` ignores it entirely: [6](#0-5) 
- `maxSubscribeAttempts` — still applies per cycle (3 failures needed), but the cycle restarts immediately on the next scheduler tick.
- `CompositeBlockSource.SourceHealth` — only switches source after 3 consecutive `BlockNodeSubscriber.get()` failures. In `BLOCK_NODE`-only mode there is no fallback at all: [7](#0-6) 

## Impact Explanation
The `readmitDelay` cooldown is completely nullified. The importer hammers the malicious node at the full scheduler frequency with no back-off. Each cycle wastes a `serverStatus` gRPC call plus 3 `streamBlocks()` gRPC calls. Block ingestion stalls for as long as the attacker sustains the attack. In `BLOCK_NODE`-only source mode there is no fallback to `BlockFileSource`, so the importer stops processing blocks entirely. In `AUTO` mode, after 3 consecutive outer failures `CompositeBlockSource` switches to `BlockFileSource`, but the attacker can resume the cycle whenever the importer switches back. [9](#0-8) 

## Likelihood Explanation
The attacker must operate a block node that is registered/configured in the importer. With `autoDiscoveryEnabled = true` (the default), nodes are discovered from the database; a node registered as a `BLOCK_NODE` type with all three required APIs is automatically included. The attacker needs no credentials beyond being a registered block node. The attack is trivially repeatable: simply always return a valid block range from `serverStatus` and always fail `streamBlocks()`. No timing precision is required. [5](#0-4) 

## Recommendation
The force-readmit path should not unconditionally bypass the `readmitDelay`. Options include:

1. **Track force-readmit attempts separately:** Introduce a `forceReadmitCount` counter. After N force-readmits without a successful block, enforce the `readmitDelay` even for the force path.
2. **Apply a separate, shorter cooldown for force-readmit:** Instead of bypassing the delay entirely, use a shorter but non-zero cooldown (e.g., `readmitDelay / maxSubscribeAttempts`) for the force path, preventing tight cycling.
3. **Remove the force-readmit path entirely:** If all nodes are inactive, throw `BlockStreamException` immediately and let `CompositeBlockSource` handle the fallback. The force-readmit path's benefit (unblocking when all nodes are inactive) does not justify the complete bypass of the cooldown.
4. **Validate `serverStatus` responses:** Cross-check the claimed block range against the importer's own known block height before trusting it for force-readmit decisions.

## Proof of Concept

```
Setup: Single block node configured. maxSubscribeAttempts=3, readmitDelay=60s, frequency=100ms.

Attacker node behavior:
  - serverStatus: always returns firstAvailableBlock=N, lastAvailableBlock=N+1000
  - streamBlocks: always returns SubscribeStreamResponse.Code.NOT_AVAILABLE

Tick 1: getNode() → tryReadmit(false) → active=true → hasBlock() → streamBlocks() → onError() [errors=1]
Tick 2: getNode() → tryReadmit(false) → active=true → hasBlock() → streamBlocks() → onError() [errors=2]
Tick 3: getNode() → tryReadmit(false) → active=true → hasBlock() → streamBlocks() → onError() [errors=3 >= 3] → active=false, readmitTime=now+60s
Tick 4: getNode() → tryReadmit(false) → delay not elapsed → inactive → inactiveNodes=[node]
         → hasBlock() [serverStatus call] → range contains N → tryReadmit(true) → active=true → returned
         → streamBlocks() → onError() [errors=1]
Tick 5: getNode() → tryReadmit(false) → active=true → hasBlock() → streamBlocks() → onError() [errors=2]
Tick 6: getNode() → tryReadmit(false) → active=true → hasBlock() → streamBlocks() → onError() [errors=3] → active=false
Tick 7: same as Tick 4 — readmitDelay bypassed again

Result: readmitDelay of 60s is never observed. Cycle repeats every ~300ms (3 ticks × 100ms).
        Block ingestion stalls indefinitely. No cooldown applied.
``` [3](#0-2)

### Citations

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L184-190)
```java
    public BlockNode tryReadmit(final boolean force) {
        if (!active && (force || Instant.now().isAfter(readmitTime.get()))) {
            active = true;
        }

        return this;
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L29-31)
```java
    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L87-89)
```java
        boolean isHealthy() {
            return errors.get() < 3;
        }
```
