### Title
Post-Add Check in `BlockAssembler.append()` Allows Heap Exhaustion via Crafted Multi-Set Block Stream

### Summary
In `BlockNode.java`, the `BlockAssembler.append()` method adds each incoming `BlockItemSet` to the `pending` list and increments `pendingCount` **before** checking against `maxBlockItems`. A malicious block node can send hundreds of `BlockItemSet` messages each containing up to the per-message size limit worth of items, causing up to `maxBlockItems + (batchSize - 1)` items to accumulate across hundreds of separate heap-allocated `List` objects before the exception is thrown, maximizing heap fragmentation and potentially exhausting JVM memory.

### Finding Description

**Exact code path:**

`importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`, `BlockAssembler.append()`, lines 291–297:

```java
pending.add(blockItems);           // (1) list added unconditionally
pendingCount += blockItems.size(); // (2) count updated
if (pendingCount > streamProperties.getMaxBlockItems()) {  // (3) check fires AFTER add
    throw new BlockStreamException(...);
}
```

**Root cause:** The guard at line 293 is a post-add check. By the time the exception is thrown, the `pending` `List<List<BlockItem>>` already holds every batch that was received, including the one that pushed `pendingCount` over the limit. There is no pre-add check, no per-set item count limit, and no cap on the number of `List` objects that can accumulate in `pending`.

**Exploit flow:**

1. Attacker controls or compromises a block node endpoint (configured statically or auto-discovered via `BlockNodeDiscoveryService` from `registeredNodeRepository`).
2. Mirror node connects and calls `streamBlocks()`, entering the `while` loop at line 138.
3. Attacker sends: `BlockItemSet #1` = `BLOCK_HEADER` + 999 items (1 000 total). `pending` now has 1 list; `pendingCount = 1 000`.
4. Attacker sends `BlockItemSet #2 … #N`, each with 999 items. Each iteration: `pending.add(...)` allocates a new list reference, `pendingCount += 999`.
5. With default `maxBlockItems = 800 000`: the exception fires after ≈ 801 sets, at which point `pending` holds ≈ 801 separate `List<BlockItem>` objects totalling ≈ 800 000+ `BlockItem` protobuf objects.
6. Each `BlockItemSet` gRPC message is bounded only by `maxStreamResponseSize = 36 MB` (line 74–75 of `BlockNode.java`). Worst case: 801 × 36 MB ≈ **28.8 GB** of live heap before the exception propagates and GC can reclaim.

**Why existing checks fail:**

- `maxBlockItems` check (line 293): fires post-add; does not prevent accumulation.
- `maxStreamResponseSize = 36 MB` (line 24 of `StreamProperties.java`, applied as `maxInboundMessageSize` at line 79 of `BlockNode.java`): limits each individual gRPC message but places no bound on how many messages accumulate in `pending` before the limit is hit.
- No per-set item count limit exists anywhere in the path.

### Impact Explanation

A single malicious or compromised block node can drive the mirror node importer JVM into an `OutOfMemoryError` or severe GC pressure before the `BlockStreamException` is thrown. Because `pending` accumulates hundreds of separate `ArrayList` objects (one per `BlockItemSet`), the heap becomes highly fragmented, making GC less effective. The importer process handles all block ingestion; crashing or stalling it halts the entire mirror node pipeline. This is a non-network-based DoS against a critical infrastructure component.

### Likelihood Explanation

Block nodes are auto-discovered from `registeredNodeRepository` via `BlockNodeDiscoveryService.discover()` (lines 73–92 of `BlockNodeDiscoveryService.java`) when `autoDiscoveryEnabled` is true. Any registered `BLOCK_NODE`-type node that advertises `STATUS`, `PUBLISH`, and `SUBSCRIBE_STREAM` APIs is eligible. A malicious operator who registers a compliant block node endpoint can trigger this without any further privilege escalation. The attack is repeatable: after the `readmitDelay` (default 1 minute), the mirror node will reconnect and the attack can be replayed.

### Recommendation

Move the limit check **before** the add, and also add a per-set item count guard:

```java
private void append(final List<BlockItem> blockItems, final BlockItem.ItemCase firstItemCase) {
    if (firstItemCase == BLOCK_HEADER && !pending.isEmpty()) { ... }
    else if (firstItemCase != BLOCK_HEADER && pending.isEmpty()) { ... }

    // Pre-add check: reject before touching pending
    int newCount = pendingCount + blockItems.size();
    if (newCount > streamProperties.getMaxBlockItems()) {
        throw new BlockStreamException(String.format(
            "Too many block items in a pending block: received %d, limit %d",
            newCount, streamProperties.getMaxBlockItems()));
    }

    pending.add(blockItems);
    pendingCount = newCount;
}
```

Additionally, consider adding a `maxPendingSets` bound to cap the number of `List` objects that can accumulate in `pending`, independent of item count.

### Proof of Concept

1. Stand up a gRPC server implementing `BlockStreamSubscribeService` at a registered block node endpoint.
2. Configure or register it so the mirror node's `BlockNodeDiscoveryService` picks it up.
3. When the mirror node calls `SubscribeBlockStream`, respond with:
   - Message 1: `BlockItemSet` containing `BLOCK_HEADER` + 999 minimal `BlockItem` objects.
   - Messages 2–802: each a `BlockItemSet` containing 999 minimal `BlockItem` objects (no `BLOCK_HEADER`).
4. Observe: `BlockAssembler.pending` grows to 801 entries; `pendingCount` reaches 800 000; `BlockStreamException` is thrown only after all 801 lists are heap-resident.
5. Scale item payload toward the 36 MB per-message limit to amplify heap pressure toward the ~28.8 GB theoretical maximum. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L74-80)
```java
        final int maxInboundMessageSize =
                (int) streamProperties.getMaxStreamResponseSize().toBytes();

        this.channel = channelBuilderProvider
                .get(properties.getHost(), properties.getPort(), properties.isRequiresTls())
                .maxInboundMessageSize(maxInboundMessageSize)
                .build();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L211-216)
```java
        private final Consumer<BlockStream> blockStreamConsumer;
        private final List<List<BlockItem>> pending = new ArrayList<>();
        private final Stopwatch stopwatch;
        private final Duration timeout;
        private long loadStart;
        private int pendingCount = 0;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L291-297)
```java
            pending.add(blockItems);
            pendingCount += blockItems.size();
            if (pendingCount > streamProperties.getMaxBlockItems()) {
                throw new BlockStreamException(String.format(
                        "Too many block items in a pending block: received %d, limit %d",
                        pendingCount, streamProperties.getMaxBlockItems()));
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L19-24)
```java
    @Min(1000)
    private int maxBlockItems = 800_000;

    @DataSizeUnit(DataUnit.MEGABYTES)
    @NotNull
    private DataSize maxStreamResponseSize = DataSize.ofMegabytes(36);
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
