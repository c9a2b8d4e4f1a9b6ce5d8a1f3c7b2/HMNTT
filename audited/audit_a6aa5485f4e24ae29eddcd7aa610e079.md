### Title
`BlockAssembler.timeout()` Returns Negative Value Passed to `grpcCall.read()`, Causing Silent Premature Stream Termination

### Summary
`BlockAssembler.timeout()` computes remaining time as `timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS)` with no lower-bound clamping. When elapsed time exceeds the configured timeout (achievable by a malicious block node operator timing responses near the deadline), the method returns a negative `long`. This negative value is passed directly to `grpcCall.read(timeout, MILLISECONDS)`, which — per Java's `LinkedBlockingQueue.poll(long, TimeUnit)` semantics — returns `null` immediately when given a non-positive timeout, causing the streaming `while` loop to exit silently as if the stream ended normally.

### Finding Description

**Exact code location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`

`BlockAssembler.timeout()` (lines 274–281):
```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS);
}
``` [1](#0-0) 

The stopwatch starts on the **first** call to `timeout()` — which happens before the first `grpcCall.read()` — not when the first `BlockItemSet` arrives. It is only reset in `onEndOfBlock()` via `stopwatch.reset()`. [2](#0-1) 

The return value is passed unclamped to `grpcCall.read()` at line 138:
```java
while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
``` [3](#0-2) 

**Root cause:** No `Math.max(0, ...)` or minimum-value guard on the return path at line 280. The failed assumption is that `stopwatch.elapsed()` will never exceed `timeout.toMillis()` between the first `timeout()` call and the next one.

**Exploit flow:**
1. Attacker operates (or compromises) a block node that the mirror node subscribes to.
2. The mirror node calls `timeout()` → stopwatch starts → `grpcCall.read(T, ms)` blocks for up to T ms.
3. The malicious server deliberately delays the first `BlockItemSet` until just before T ms (e.g., T−1 ms), so the read returns successfully.
4. `onBlockItemSet()` is called; the loop iterates.
5. `timeout()` is called again: `elapsed ≈ T ms` → returns `T − T = 0` or, with any scheduling jitter/overhead, a **negative value**.
6. `grpcCall.read(negative, MILLISECONDS)` is invoked. Internally, gRPC-Java's `BlockingClientCall` uses a `LinkedBlockingQueue`; `poll(negative, unit)` returns `null` immediately if no message is already buffered.
7. The `while` condition evaluates `null != null → false`; the loop exits silently — no exception, no error counter increment (`errors.set(0)` at line 157 was not reached for this iteration).
8. The `finally` block cancels the call. The mirror node retries the same block, and the attack can be repeated indefinitely.

**Why existing checks fail:**
- The `catch (BlockStreamException ex)` / `catch (Exception ex)` blocks at lines 159–164 are never reached because `grpcCall.read()` returning `null` is treated as a normal end-of-stream, not an error. [4](#0-3) 
- The `onError()` / error counter path is bypassed entirely.
- There is no minimum-value guard anywhere in `timeout()`.

### Impact Explanation
A malicious block node can force the mirror node into a perpetual retry loop against that node: each subscription attempt terminates silently after the first `BlockItemSet`, the block is never fully assembled, and `onEndOfBlock()` is never called. Block ingestion stalls for all blocks served by that node. If the mirror node has no other active nodes for the required block range (see `getNode()` logic), it throws `BlockStreamException("No block node can provide block …")`, halting block processing entirely. This is a targeted, repeatable denial-of-service against block ingestion. [5](#0-4) 

### Likelihood Explanation
Any block node operator — a role that does not require special privileges beyond running a node — can deliberately time their first `BlockItemSet` response to arrive near the timeout boundary. The attack requires no cryptographic material, no authentication bypass, and no insider access. It is fully repeatable: the attacker simply keeps the connection open and delays each response. Under adverse but realistic network conditions (high latency, jitter), this can also be triggered unintentionally, making it hard to distinguish from a legitimate timeout.

### Recommendation
Clamp the return value of `timeout()` to a minimum of `1` (or `0` if the caller handles zero correctly):

```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return Math.max(1L, timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS));
}
```

Additionally, treat a `null` return from `grpcCall.read()` when the stopwatch is still running (i.e., a block is partially assembled) as a timeout error rather than a clean end-of-stream, so `onError()` is invoked and the error counter is incremented correctly.

### Proof of Concept
1. Stand up a malicious gRPC block node implementing `BlockStreamSubscribeService`.
2. On `subscribeBlockStream`, wait until `(configuredTimeout − 5ms)` has elapsed, then send one `SubscribeStreamResponse` containing a valid `BlockItemSet` with a `BLOCK_HEADER` item.
3. After sending, do not send `END_OF_BLOCK` or any further messages; hold the stream open.
4. The mirror node's `grpcCall.read(T, ms)` returns the first response after ~T ms.
5. The next `assembler.timeout()` call computes `T − (T + jitter) < 0`.
6. `grpcCall.read(negative, MILLISECONDS)` returns `null` immediately.
7. The `while` loop exits; the block is never completed; the mirror node retries.
8. Repeat from step 2 on each new subscription to keep the mirror node permanently stalled on that block.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L108-130)
```java
        } catch (Exception ex) {
            log.error("Failed to get server status for {}", this, ex);
            return EMPTY_BLOCK_RANGE;
        }
    }

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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L138-138)
```java
            while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-165)
```java
        } catch (BlockStreamException ex) {
            onError();
            throw ex;
        } catch (Exception ex) {
            onError();
            throw new BlockStreamException(ex);
        } finally {
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
