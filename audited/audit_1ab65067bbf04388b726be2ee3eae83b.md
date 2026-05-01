### Title
Malicious Block Node Can Cause Indefinite Block Ingestion Latency via Slow-Drip gRPC Streaming

### Summary
The `BlockAssembler.timeout()` method in `BlockNode.java` uses a `Stopwatch` that resets after every completed block (`onEndOfBlock()`), granting the malicious node a fresh full timeout budget for each successive block. A malicious block node can exploit this by sending block items just slowly enough to keep the remaining timeout positive, completing each block just before expiry, then immediately starting the next — keeping the importer's synchronous `streamBlocks()` call blocked indefinitely. No existing check detects or disconnects a slow-but-non-erroring node.

### Finding Description

**Exact code path:**

`BlockNode.java` — `BlockAssembler.timeout()` (lines 274–281): [1](#0-0) 

```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS);
}
```

This value is consumed in the streaming loop at line 138: [2](#0-1) 

```java
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
```

**Root cause — the stopwatch resets per block, not per connection:**

`onEndOfBlock()` calls `stopwatch.reset()` (line 268), which stops and zeroes the stopwatch: [3](#0-2) 

The next call to `timeout()` sees `!stopwatch.isRunning()` as `true`, restarts the stopwatch, and returns the **full** `timeout.toMillis()` again. The malicious node therefore receives a fresh, full timeout budget for every block it delivers.

**Exploit flow:**

1. Malicious node sends `BLOCK_HEADER` for block N → stopwatch starts.
2. Node sends subsequent `BlockItemSet` messages at a rate that keeps the remaining timeout just above zero (e.g., one item every `timeout - ε` ms).
3. Node sends `END_OF_BLOCK` for block N just before the timeout expires → `stopwatch.reset()` is called.
4. Node immediately sends `BLOCK_HEADER` for block N+1 → stopwatch restarts with full budget.
5. Steps 2–4 repeat indefinitely.

**Why existing checks are insufficient:**

- `onError()` / `maxSubscribeAttempts` / `readmitDelay` — only triggered by exceptions, never by a slow-but-non-erroring stream: [4](#0-3) 

- `maxBlockItems` — limits item count per block, not delivery speed: [5](#0-4) 

- `maxStreamResponseSize` — limits individual message size, not delivery rate: [6](#0-5) 

- `responseTimeout` (400 ms default) — only used for the `getBlockRange()` / `serverStatus` RPC, **not** for `streamBlocks`: [7](#0-6) 

**Synchronous blocking:** `streamBlocks()` is called synchronously from `BlockNodeSubscriber.doGet()`, which is called from `AbstractBlockSource.get()`. There is no parallelism; while one node's `streamBlocks()` is executing, no other node can be polled: [8](#0-7) 

### Impact Explanation

A malicious block node can hold the importer's single streaming thread indefinitely, one block at a time, each block consuming up to the full configured timeout. Block ingestion latency spikes proportionally. Because `streamBlocks()` is synchronous and the importer selects one node per block, legitimate block nodes cannot be used while the malicious node is active. The importer falls behind the chain tip, degrading mirror node data freshness for all downstream consumers. Severity is **medium** (griefing / availability degradation; no direct fund loss).

### Likelihood Explanation

The attacker must control a block node reachable by the importer — either via static configuration or via the `BlockNodeDiscoveryService` auto-discovery path (`autoDiscoveryEnabled = true` by default): [9](#0-8) 

No authentication of block nodes is visible in the code path reviewed. An operator of any node that the importer is pointed at (or that is discovered) can execute this attack without any privileged access to the importer itself. The attack is repeatable and requires only network-level participation.

### Recommendation

1. **Add a wall-clock deadline for the entire block, not just per-read.** The stopwatch should NOT reset after `onEndOfBlock()`; instead, maintain a single deadline for the entire streaming session or enforce a maximum wall-clock time per block independent of item delivery cadence.
2. **Add a per-item inactivity timeout** separate from the cumulative block timeout, so that any gap between consecutive items exceeding a threshold (e.g., 500 ms) terminates the connection.
3. **Track slow-stream events** (e.g., blocks that consume >X% of the timeout budget) and apply the same backoff/readmit logic as errors after repeated occurrences.
4. **Authenticate block nodes** (mTLS or equivalent) so that only trusted nodes can serve streams to the importer.

### Proof of Concept

**Preconditions:**
- Attacker controls a gRPC server implementing `BlockStreamSubscribeService`.
- The importer is configured (or auto-discovers) the attacker's node as a block node.

**Steps:**

1. Attacker's node responds to `serverStatus` with a valid block range containing the next expected block N.
2. On `SubscribeBlockStream` RPC, attacker's node sends:
   - `BLOCK_ITEMS` with a valid `BLOCK_HEADER` for block N immediately.
   - Subsequent `BLOCK_ITEMS` messages at intervals of `(timeout - 50ms)` ms, where `timeout` = `commonDownloaderProperties.getTimeout()`.
   - `END_OF_BLOCK` for block N just before the timeout expires.
3. Immediately after step 2, repeat for block N+1, N+2, … indefinitely.
4. **Observed result:** The importer's `streamBlocks()` call never returns; block ingestion latency grows without bound. The `onError()` counter remains at zero because no exception is thrown. The node is never marked inactive.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L101-103)
```java
            final var blockNodeService = BlockNodeServiceGrpc.newBlockingStub(channel)
                    .withDeadlineAfter(streamProperties.getResponseTimeout());
            final var response = blockNodeService.serverStatus(SERVER_STATUS_REQUEST);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L138-138)
```java
            while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L266-271)
```java
            pending.clear();
            pendingCount = 0;
            stopwatch.reset();

            final var filename = BlockFile.getFilename(blockNumber, false);
            blockStreamConsumer.accept(new BlockStream(block, null, filename, loadStart));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L274-281)
```java
        long timeout() {
            if (!stopwatch.isRunning()) {
                stopwatch.start();
                return timeout.toMillis();
            }

            return timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS);
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L293-297)
```java
            if (pendingCount > streamProperties.getMaxBlockItems()) {
                throw new BlockStreamException(String.format(
                        "Too many block items in a pending block: received %d, limit %d",
                        pendingCount, streamProperties.getMaxBlockItems()));
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L23-24)
```java
    @NotNull
    private DataSize maxStreamResponseSize = DataSize.ofMegabytes(36);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNodeSubscriber.java (L58-70)
```java
    protected void doGet(final long blockNumber) {
        final var nextBlockNumber = new AtomicLong(blockNumber);
        final var node = getNode(nextBlockNumber);
        if (blockNumber == EARLIEST_AVAILABLE_BLOCK_NUMBER && !shouldGetBlock(nextBlockNumber.get())) {
            return;
        }

        log.info("Start streaming block {} from {}", nextBlockNumber.get(), node);
        node.streamBlocks(
                nextBlockNumber.get(),
                commonDownloaderProperties,
                (stream) -> onBlockStream(stream, node.getProperties().getEndpoint()));
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockProperties.java (L27-27)
```java
    private boolean autoDiscoveryEnabled = true;
```
