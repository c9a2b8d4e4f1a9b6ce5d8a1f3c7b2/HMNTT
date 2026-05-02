The code confirms all claims in the report. Let me verify the key facts:

1. `timeout()` at line 280 returns `timeout.toMillis() - stopwatch.elapsed(MILLISECONDS)` with no `Math.max(0, ...)` guard — confirmed negative values are possible.
2. Line 138 passes that value directly to `grpcCall.read()` — confirmed.
3. `onError()` is only called in `catch` blocks (lines 159–164), never on a `null` return — confirmed.
4. `stopwatch.reset()` only happens inside `onEndOfBlock()` (line 268) — confirmed.
5. Nothing in SECURITY.md excludes this class of vulnerability.

---

Audit Report

## Title
Silent Block Drop via Negative Timeout in `BlockAssembler.timeout()` Allows Malicious Block Node to Suppress Transaction Indexing

## Summary
`BlockAssembler.timeout()` computes the remaining read budget as `timeout.toMillis() - stopwatch.elapsed(MILLISECONDS)` with no lower bound. Once elapsed time exceeds the configured timeout, this returns a negative value that is passed directly to `grpcCall.read()`. Java's `BlockingQueue.poll(long, TimeUnit)` semantics treat a non-positive timeout as an immediate non-blocking poll, returning `null` instantly. The while loop exits normally — no exception, no error counter increment, no node penalty — silently discarding any partially assembled block.

## Finding Description

**Exact location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`

`BlockAssembler.timeout()` at lines 274–281:

```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS);
    // ^^^ NO Math.max(0, ...) guard — can return negative
}
``` [1](#0-0) 

The negative value is forwarded verbatim at line 138:

```java
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
``` [2](#0-1) 

`grpcCall` is a `BlockingClientCall` from gRPC-java, whose `read(timeout, unit)` delegates to a `LinkedBlockingQueue.poll(timeout, unit)`. Java's `BlockingQueue.poll` with a non-positive timeout returns `null` immediately if no message is already buffered. The while-loop condition `!= null` then evaluates to `false`, and the loop exits cleanly.

**Why existing checks fail:**

- `onError()` is only invoked inside `catch` blocks at lines 159–164. A `null` return from `read()` is not an exception — it exits the loop silently. [3](#0-2) 

- `errors.set(0)` at line 157 is only reached when a response is successfully processed; it is never reached on the null-exit path. [4](#0-3) 

- `stopwatch.reset()` at line 268 is only called inside `onEndOfBlock()`, which the attacker never triggers. [5](#0-4) 

- There is no log statement, no metric, and no `BlockStreamException` thrown when the loop exits via `null`.

## Impact Explanation
Every block the attacker targets is silently dropped: `blockStreamConsumer` (i.e., `onBlockStream`) is never called, so the `BlockStream` containing all transactions of that block is never passed to the verifier or parser. Transactions in those blocks are never indexed in the mirror node database, making them invisible to all downstream consumers (REST API, gRPC API, etc.). Because no error counter is incremented and the node is never penalized, the attacker can sustain this indefinitely against a single-node configuration, or rotate across multiple nodes in a multi-node configuration to suppress blocks across the board. [6](#0-5) 

## Likelihood Explanation
The precondition is controlling one block node endpoint that the mirror node trusts. Block nodes are external infrastructure; a compromised or maliciously registered node satisfies this. No cryptographic material, no privileged network position, and no mirror-node credentials are required. The timing manipulation (delay until elapsed > timeout) is trivially implemented by any TCP-level server that simply stops writing to the stream after the first message. The attack is fully repeatable and requires no special knowledge beyond the configured timeout value (a well-known configuration property).

## Recommendation
Apply a lower bound of zero in `BlockAssembler.timeout()`:

```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return Math.max(0L, timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS));
}
```

Additionally, when the while loop exits via `null` (timeout expiry) while `pending` is non-empty, treat it as an error: call `onError()`, log a warning, and optionally throw a `BlockStreamException` so the node's error counter is incremented and the node can be penalized after repeated offenses. [1](#0-0) 

## Proof of Concept

1. Stand up a gRPC server implementing `BlockStreamSubscribeService`.
2. On `subscribeBlockStream`, immediately send one `SubscribeStreamResponse` containing a `BlockItemSet` with a valid `BLOCK_HEADER` item.
3. After sending that single message, stop writing to the stream (hold the connection open but send nothing further).
4. The mirror node's `streamBlocks()` loop will block on `grpcCall.read(T, MILLISECONDS)` for the full configured timeout `T`.
5. After `T` milliseconds, `assembler.timeout()` returns a value ≤ 0.
6. `grpcCall.read(≤0, MILLISECONDS)` returns `null` immediately.
7. The while loop exits. `pending` contains the `BLOCK_HEADER` items but `onEndOfBlock()` was never called, so `blockStreamConsumer` is never invoked.
8. `streamBlocks()` returns normally. No error is recorded; `node.isActive()` remains `true`.
9. The block and all its transactions are permanently absent from the mirror node database.
10. Repeat for every subsequent block request to suppress indexing indefinitely. [7](#0-6)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L114-172)
```java
    public void streamBlocks(
            final long blockNumber,
            final CommonDownloaderProperties commonDownloaderProperties,
            final Consumer<BlockStream> onBlockStream) {
        final var callHolder =
                new AtomicReference<@Nullable BlockingClientCall<SubscribeStreamRequest, SubscribeStreamResponse>>();

        try {
            final long endBlockNumber = Objects.requireNonNullElse(
                    commonDownloaderProperties.getImporterProperties().getEndBlockNumber(), -1L);
            final var assembler = new BlockAssembler(onBlockStream, commonDownloaderProperties.getTimeout());
            final var request = SubscribeStreamRequest.newBuilder()
                    .setEndBlockNumber(endBlockNumber)
                    .setStartBlockNumber(blockNumber)
                    .build();
            final var grpcCall = ClientCalls.blockingV2ServerStreamingCall(
                    channel,
                    BlockStreamSubscribeServiceGrpc.getSubscribeBlockStreamMethod(),
                    CallOptions.DEFAULT,
                    request);
            callHolder.set(grpcCall);
            SubscribeStreamResponse response;

            boolean serverSuccess = false;
            while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
                switch (response.getResponseCase()) {
                    case BLOCK_ITEMS -> assembler.onBlockItemSet(response.getBlockItems());
                    case END_OF_BLOCK -> assembler.onEndOfBlock(response.getEndOfBlock());
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
        } finally {
            final var call = callHolder.get();
            if (call != null) {
                call.cancel("unsubscribe", null);
                grpcBufferDisposer.accept(call);
            }
        }
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L266-268)
```java
            pending.clear();
            pendingCount = 0;
            stopwatch.reset();
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
