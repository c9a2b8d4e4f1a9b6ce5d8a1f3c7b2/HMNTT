### Title
Rogue Block Node Can Trigger Repeated `onError()` via Oversized gRPC Responses, Causing Self-Deactivation and Block Ingestion Disruption

### Summary
The `BlockNode.streamBlocks()` method uses a generic `catch (Exception ex)` handler that treats gRPC `StatusRuntimeException` errors from oversized inbound messages identically to legitimate stream errors, calling `onError()` each time. A rogue block node that deliberately sends responses exceeding `maxStreamResponseSize` (default 36 MB) can exhaust `maxSubscribeAttempts` (default 3) and force its own deactivation. If the rogue node is the sole or primary configured node — possible via the default-enabled auto-discovery path — block ingestion halts until the `readmitDelay` (default 1 minute) expires, after which the cycle repeats indefinitely.

### Finding Description

**Code locations:**

`StreamProperties.java` line 24 — limit definition: [1](#0-0) 

`BlockNode.java` lines 74–80 — limit applied to the gRPC channel: [2](#0-1) 

`BlockNode.java` lines 159–164 — generic catch wraps gRPC size-limit errors as node errors: [3](#0-2) 

`BlockNode.onError()` lines 196–207 — error counter and deactivation logic: [4](#0-3) 

**Root cause:** The `catch (Exception ex)` block makes no distinction between a transient network error, a protocol violation, and a gRPC `StatusRuntimeException` raised by the client-side `maxInboundMessageSize` guard. All paths call `onError()`, incrementing the same error counter. The failed assumption is that every exception reaching that handler represents a misbehaving-but-recoverable node rather than a deliberately crafted oversized payload.

**Exploit flow:**
1. Rogue node is added to the mirror node's block-node list (see preconditions below).
2. On each `streamBlocks()` call the rogue node sends a single gRPC `SubscribeStreamResponse` frame whose serialized size exceeds 36 MB.
3. The gRPC client raises `StatusRuntimeException(RESOURCE_EXHAUSTED)` before any application-level data is processed.
4. `catch (Exception ex)` at line 162 catches it, calls `onError()`, and re-throws as `BlockStreamException`.
5. `onError()` increments `errors`; after 3 consecutive failures `active` is set to `false` and `readmitTime` is set to `now + 1 minute`.
6. `BlockNodeSubscriber.getNode()` finds no active node and throws `BlockStreamException("No block node can provide block …")`, halting ingestion.
7. After 1 minute the node is force-readmitted and the cycle repeats.

**Auto-discovery entry point (unprivileged path):**
`BlockProperties.java` line 27 shows `autoDiscoveryEnabled = true` by default. [5](#0-4) 

`BlockNodeDiscoveryService.discover()` reads tier-1 block nodes directly from the database, which is populated from on-chain `NodeCreate`/`NodeUpdate` transactions parsed from the record stream. [6](#0-5) 

Submitting such a transaction requires only HBAR (no governance privilege), so any HBAR holder can inject a node into the auto-discovered list.

**Why existing checks are insufficient:**
- `maxInboundMessageSize` is a *client-side* guard; it protects memory but its rejection is indistinguishable from a real error at the application layer.
- `errors.set(0)` at line 157 only resets on a *successful* response; an attacker that never sends a valid response keeps the counter climbing. [7](#0-6) 
- `tryReadmit(true)` in `getNode()` force-readmits inactive nodes only when *all* nodes are inactive, meaning the rogue node is immediately retried, restarting the deactivation cycle. [8](#0-7) 

### Impact Explanation
If the rogue node is the only node (or all legitimate nodes are simultaneously unavailable), block ingestion stops entirely. Every 1-minute readmit window is immediately consumed by another oversized-response attack, creating a perpetual denial-of-service. Fund-transfer blocks are not ingested, meaning balance changes, token transfers, and contract results are not reflected in the mirror node's state for the duration of the attack.

### Likelihood Explanation
The precondition — controlling a node that appears in the mirror node's list — is achievable without privileged access when `autoDiscoveryEnabled = true` (the default). The attack is cheap to execute (one oversized gRPC frame per attempt), fully repeatable, and requires no knowledge of internal state beyond the public gRPC API. The impact is conditional on the rogue node being the sole active node, which limits real-world severity when multiple legitimate nodes are configured, but is realistic in single-node or degraded deployments.

### Recommendation
1. **Distinguish size-limit errors from stream errors.** Catch `StatusRuntimeException` separately and check `status.getCode() == Status.Code.RESOURCE_EXHAUSTED`; do not call `onError()` for client-side size-limit rejections — these indicate a misbehaving peer, not a transient failure worth retrying.
2. **Authenticate auto-discovered nodes.** Require mutual TLS or a cryptographic proof-of-identity before a discovered node is used for streaming, so that registering a Hedera node transaction alone is insufficient to become a trusted block source.
3. **Cap the deactivation cycle.** Introduce a per-node permanent-ban threshold (e.g., after N readmit cycles with no successful blocks) so a persistently malicious node is removed from rotation rather than retried indefinitely.
4. **Separate error counters by error type.** Protocol violations (oversized frames, unexpected response cases) should use a stricter counter than transient network errors.

### Proof of Concept
1. Register a block node on the Hedera network (any `NodeCreate` transaction with `BLOCK_NODE` type and the three required APIs) pointing to an attacker-controlled server.
2. Wait for the mirror node to parse the transaction and auto-discover the node (`autoDiscoveryEnabled = true`).
3. On the attacker's server, implement `BlockStreamSubscribeService.subscribeBlockStream()` to respond with a single `SubscribeStreamResponse` whose serialized byte length exceeds 36 MB (e.g., a `BLOCK_ITEMS` message with a large padding field).
4. Observe the mirror node log: `StatusRuntimeException: RESOURCE_EXHAUSTED: gRPC message exceeds maximum size` is caught, `onError()` is called, and after 3 attempts the log shows `"Marking connection to BlockNode(…) as inactive after 3 attempts"`.
5. If this is the only configured node, `BlockNodeSubscriber.getNode()` throws `BlockStreamException("No block node can provide block …")` and ingestion halts.
6. After 1 minute the node is force-readmitted; repeat step 3 to sustain the DoS indefinitely.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L22-27)
```java
    @DataSizeUnit(DataUnit.MEGABYTES)
    @NotNull
    private DataSize maxStreamResponseSize = DataSize.ofMegabytes(36);

    @Min(1)
    private int maxSubscribeAttempts = 3;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L74-80)
```java
        final int maxInboundMessageSize =
                (int) streamProperties.getMaxStreamResponseSize().toBytes();

        this.channel = channelBuilderProvider
                .get(properties.getHost(), properties.getPort(), properties.isRequiresTls())
                .maxInboundMessageSize(maxInboundMessageSize)
                .build();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L155-158)
```java
                }

                errors.set(0);
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockProperties.java (L27-27)
```java
    private boolean autoDiscoveryEnabled = true;
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
