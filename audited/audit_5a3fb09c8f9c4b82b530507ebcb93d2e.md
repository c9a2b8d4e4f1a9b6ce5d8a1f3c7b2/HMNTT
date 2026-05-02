### Title
Force-Readmit Bypass Enables Permanent Block Ingestion DoS via Malicious STATUS Responses in `BLOCK_NODE` Mode

### Summary
A malicious block node that returns a valid block range via `serverStatus` but consistently sends non-SUCCESS `STATUS` responses in the streaming protocol can exhaust the `maxSubscribeAttempts` counter, mark itself inactive, and then be immediately force-readmitted on the very next `get()` call — completely bypassing the `readmitDelay` cooldown. When all configured block nodes behave this way and `sourceType = BLOCK_NODE`, there is no fallback path, permanently halting block ingestion with no recovery mechanism.

### Finding Description

**Step 1 — STATUS non-SUCCESS throws and calls `onError()`:**

In `BlockNode.streamBlocks()`, any STATUS response that is not `SUCCESS` unconditionally throws: [1](#0-0) 

The `catch` block calls `onError()`: [2](#0-1) 

**Step 2 — `onError()` marks the node inactive after `maxSubscribeAttempts=3`:** [3](#0-2) 

The `readmitDelay` defaults to 1 minute, intended as a cooldown: [4](#0-3) 

**Step 3 — Force-readmit completely bypasses the cooldown:**

In `BlockNodeSubscriber.getNode()`, when all nodes are inactive, the second loop calls `hasBlock()` (which issues a `serverStatus` gRPC call). If the malicious node returns a valid block range, `hasBlock()` returns `true` and `tryReadmit(true)` is called unconditionally: [5](#0-4) 

`tryReadmit(true)` ignores `readmitTime` entirely: [6](#0-5) 

The node is immediately re-selected, `streamBlocks()` is called again, it fails again, and the cycle repeats on every scheduled `get()` invocation.

**Step 4 — `BLOCK_NODE` source type has no fallback:**

`CompositeBlockSource.getSourceHealth()` for `BLOCK_NODE` mode unconditionally returns `blockNodeSubscriberSourceHealth` regardless of its health state: [7](#0-6) 

The `AUTO` mode fallback (switching to `BlockFileSource` after 3 failures) is only available in the `AUTO` branch: [8](#0-7) 

With `BLOCK_NODE` mode, there is no escape path. The `SourceHealth.isHealthy()` check is never consulted: [9](#0-8) 

**Root cause:** The failed assumption is that `readmitDelay` provides a meaningful cooldown. It does not — the force-readmit path in `getNode()` bypasses it entirely whenever all nodes are inactive and any node claims to have the requested block. Combined with `BLOCK_NODE` mode having no fallback, this creates a permanent halt condition.

### Impact Explanation

Block ingestion stops completely and permanently for any mirror node operator running with `sourceType = BLOCK_NODE`. No new blocks are processed, no transactions are indexed, and the mirror node falls arbitrarily far behind the chain. The `readmitDelay` cooldown — the only rate-limiting mechanism — is rendered inoperative, so the failure loop runs at the full scheduler frequency with no recovery. Operators have no automated recovery path; manual intervention (reconfiguring or removing the malicious node) is required.

### Likelihood Explanation

The precondition is that the attacker controls all configured block nodes, or there is only a single block node configured. This is realistic because:
- Many deployments start with a single trusted block node endpoint
- An attacker who can perform DNS/BGP hijacking against the configured hostname(s) satisfies the precondition without any privileged access to the mirror node itself
- The block node protocol has no mutual authentication requirement enforced at the application layer — the mirror node simply connects to whatever host/port is configured
- The attack payload is trivial: respond to `serverStatus` with a valid block range, respond to `subscribeBlockStream` with a single `STATUS = NOT_AVAILABLE` message

No credentials, no privileged access, and no knowledge of internal state are required. The attack is fully repeatable and deterministic.

### Recommendation

1. **Fix the force-readmit bypass**: In `getNode()`, do not force-readmit a node simply because it claims to have the block via `serverStatus`. Force-readmit should only occur after the `readmitDelay` has elapsed, or require a separate operator-triggered action. Remove or gate the `tryReadmit(true)` call in the inactive-node fallback loop.

2. **Add a fallback for `BLOCK_NODE` mode**: Even in `BLOCK_NODE` mode, `CompositeBlockSource` should consult `SourceHealth.isHealthy()` and either alert loudly or apply exponential backoff rather than hammering a permanently-failing source at full scheduler frequency.

3. **Rate-limit `serverStatus` calls from inactive nodes**: The `hasBlock()` call on an inactive node should itself be subject to the `readmitDelay`, not just the streaming attempt.

### Proof of Concept

1. Configure the mirror node with `sourceType = BLOCK_NODE` and a single block node endpoint pointing to an attacker-controlled gRPC server.
2. The attacker's server implements `BlockNodeService.serverStatus()` to return `firstAvailableBlock = N`, `lastAvailableBlock = N+100` (any range containing the next expected block).
3. The attacker's server implements `BlockStreamSubscribeService.subscribeBlockStream()` to immediately send a single `SubscribeStreamResponse` with `status = NOT_AVAILABLE` and then close the stream.
4. Observe: on each scheduled `get()` call, `BlockNodeSubscriber.doGet()` calls `getNode()`, which calls `hasBlock()` (serverStatus succeeds, returns valid range), selects the node, calls `streamBlocks()`, receives `NOT_AVAILABLE`, throws `BlockStreamException`, calls `onError()`. After 3 attempts the node is marked inactive. On the 4th call, `getNode()` enters the inactive-node loop, calls `hasBlock()` again (serverStatus succeeds again), calls `tryReadmit(true)`, returns the node, and `streamBlocks()` fails again immediately — bypassing the 1-minute `readmitDelay` entirely.
5. Block ingestion halts permanently. No blocks are processed. The mirror node diverges from chain state indefinitely.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L142-153)
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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-161)
```java
        } catch (BlockStreamException ex) {
            onError();
            throw ex;
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L27-31)
```java
    private int maxSubscribeAttempts = 3;

    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L122-128)
```java
        // find the first inactive node with the block and force activating it
        for (final var node : inactiveNodes) {
            if (hasBlock(nextBlockNumber, node)) {
                node.tryReadmit(true);
                return node;
            }
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L60-73)
```java
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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L74-74)
```java
            case BLOCK_NODE -> blockNodeSubscriberSourceHealth;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/CompositeBlockSource.java (L87-89)
```java
        boolean isHealthy() {
            return errors.get() < 3;
        }
```
