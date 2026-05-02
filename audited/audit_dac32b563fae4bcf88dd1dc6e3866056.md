### Title
Count-Based `maxBlockItems` Guard Allows Heap Exhaustion (OOM) Before DoS Protection Activates in `BlockAssembler.append()`

### Summary
`BlockAssembler.append()` in `BlockNode.java` accumulates deserialized `BlockItem` objects into the `pending` list and only checks the item **count** against `maxBlockItems` (default 800,000) after the items are already added to the heap. Because each individual gRPC message is independently capped at `maxStreamResponseSize` (36 MB) but there is no cumulative byte-size guard on the `pending` list, a malicious block node can stream hundreds of messages each containing one maximally-sized item, exhausting JVM heap long before the integer count threshold is ever reached.

### Finding Description

**Exact code path:**

`StreamProperties.java` defines the two relevant limits: [1](#0-0) 

`BlockNode` constructor applies `maxStreamResponseSize` as a per-message gRPC cap: [2](#0-1) 

`BlockAssembler.append()` adds items to `pending` **before** checking the count: [3](#0-2) 

**Root cause and failed assumption:**

The design assumes that limiting the number of items (count) is equivalent to limiting memory consumption. This is false: each `BlockItem` can carry arbitrary-length protobuf byte/string fields up to the 36 MB per-message ceiling. The `pending` list is a `List<List<BlockItem>>` that grows unboundedly across successive `BlockItemSet` messages until `pendingCount` exceeds 800,000. There is no running byte-size accumulator anywhere in `BlockAssembler`. [4](#0-3) 

**Exploit flow:**

1. Attacker registers as a block node via an on-chain `RegisteredNodeCreate` transaction (HIP-1137). With `autoDiscoveryEnabled=true` (the default), `BlockNodeDiscoveryService` reads the `registered_node` table and adds the attacker's endpoint to the active node list. [5](#0-4) 

2. The mirror node importer connects and calls `streamBlocks()`. The attacker's server responds with a valid `BLOCK_HEADER` item in the first `BlockItemSet`, then streams a continuous sequence of `BlockItemSet` messages each containing exactly **one** `BlockItem` whose string/bytes fields are padded to ~36 MB (the per-message limit).

3. Each message passes the gRPC `maxInboundMessageSize` check (it is exactly at the limit). Each call to `append()` adds the deserialized list to `pending` and increments `pendingCount` by 1.

4. With a typical 4 GB JVM heap, OOM occurs after approximately **111 messages** (4 GB / 36 MB). The `maxBlockItems` count check would not fire until message **800,001**. The check is therefore ~7,200× too late to prevent OOM.

**Why existing checks are insufficient:**

- `maxStreamResponseSize` (36 MB): limits each individual gRPC frame, not the cumulative in-memory accumulation across frames.
- `maxBlockItems` (800,000): a pure integer counter with no relationship to byte size; provides zero protection when items are large.
- No timeout on total streaming duration per block prevents slow-drip attacks. [6](#0-5) 

### Impact Explanation

An attacker who can register as a block node (a permissionless on-chain operation under HIP-1137 with `autoDiscoveryEnabled=true`) can crash the importer process with an `OutOfMemoryError`. This halts all block ingestion, causing the mirror node to fall behind the chain and making all downstream APIs (REST, gRPC) serve stale data. Because the importer is a single-threaded poller, one successful OOM attack fully stops the service until the process is restarted. The attack is repeatable: after restart the importer will reconnect to the same registered block node and the crash can be triggered again immediately.

### Likelihood Explanation

The precondition — being a registered block node — is achievable by any Hedera account holder who can pay transaction fees for a `RegisteredNodeCreate` transaction. `autoDiscoveryEnabled` defaults to `true`. No cryptographic credential or administrator approval is required beyond submitting the on-chain transaction. The attack requires only a TCP server that speaks the block-node gRPC protocol and sends oversized items; this is straightforward to implement. The attack is repeatable and requires no ongoing network access beyond the initial registration.

### Recommendation

1. **Add a cumulative byte-size guard in `BlockAssembler`.** Track `pendingBytes` alongside `pendingCount` and throw `BlockStreamException` when the total exceeds a configurable `maxPendingBlockBytes` limit (e.g., `maxStreamResponseSize * some_multiplier`, or a separate property). Check this limit in `append()` immediately after updating the counter, before the next message is accepted.

2. **Check byte size before adding to `pending`.** Reorder `append()` so the guard fires before `pending.add(blockItems)`, preventing the allocation from landing on the heap at all.

3. **Add a `maxBlockBytes` property to `StreamProperties`** (analogous to `maxBlockItems`) with a sensible default (e.g., 256 MB) and a `@DataSizeUnit` annotation consistent with `maxStreamResponseSize`.

4. **Consider bounding `maxBlockItems` relative to `maxStreamResponseSize`** so that `maxBlockItems * maxStreamResponseSize` cannot exceed available heap.

### Proof of Concept

```
Preconditions:
  - Hedera account with HBAR for transaction fees
  - autoDiscoveryEnabled = true (default)
  - Mirror node importer JVM heap = 4 GB (typical)

Steps:
1. Submit RegisteredNodeCreate on-chain with attacker's host:port advertising
   STATUS, PUBLISH, SUBSCRIBE_STREAM APIs (required by BlockNodeDiscoveryService
   TIER_ONE_BLOCK_NODE_APIS filter).

2. Wait for mirror node to ingest the transaction and invalidate the discovery
   cache (RegisteredNodeChangedEvent fires → cache cleared → next getBlockNodes()
   call returns attacker's node).

3. Run attacker gRPC server implementing BlockStreamSubscribeService:
   a. On SubscribeBlockStream RPC, send one SubscribeStreamResponse containing
      a BlockItemSet with a single BLOCK_HEADER BlockItem whose bytes field is
      padded to 35,999,999 bytes (just under 36 MB maxInboundMessageSize).
   b. Continue sending SubscribeStreamResponse messages each with one BlockItem
      (non-BLOCK_HEADER type, e.g. EVENT_HEADER) padded to 35,999,999 bytes.
      Never send END_OF_BLOCK or BlockProof.

4. Observe:
   - Each message passes the per-message gRPC size check.
   - BlockAssembler.append() adds each item to pending and increments
     pendingCount by 1.
   - After ~111 messages (~4 GB allocated), JVM throws OutOfMemoryError.
   - pendingCount at OOM = ~111, far below maxBlockItems threshold of 800,000.
   - Importer process crashes; mirror node stops ingesting blocks.

5. After restart, importer reconnects to the same registered block node
   (still in the database) and the crash repeats immediately.
```

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L19-24)
```java
    @Min(1000)
    private int maxBlockItems = 800_000;

    @DataSizeUnit(DataUnit.MEGABYTES)
    @NotNull
    private DataSize maxStreamResponseSize = DataSize.ofMegabytes(36);
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L209-216)
```java
    private final class BlockAssembler {

        private final Consumer<BlockStream> blockStreamConsumer;
        private final List<List<BlockItem>> pending = new ArrayList<>();
        private final Stopwatch stopwatch;
        private final Duration timeout;
        private long loadStart;
        private int pendingCount = 0;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L283-298)
```java
        private void append(final List<BlockItem> blockItems, final BlockItem.ItemCase firstItemCase) {
            if (firstItemCase == BLOCK_HEADER && !pending.isEmpty()) {
                throw new BlockStreamException(
                        "Received block items of a new block while the previous block is still pending");
            } else if (firstItemCase != BLOCK_HEADER && pending.isEmpty()) {
                throw new BlockStreamException("Incorrect first block item case " + firstItemCase);
            }

            pending.add(blockItems);
            pendingCount += blockItems.size();
            if (pendingCount > streamProperties.getMaxBlockItems()) {
                throw new BlockStreamException(String.format(
                        "Too many block items in a pending block: received %d, limit %d",
                        pendingCount, streamProperties.getMaxBlockItems()));
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
