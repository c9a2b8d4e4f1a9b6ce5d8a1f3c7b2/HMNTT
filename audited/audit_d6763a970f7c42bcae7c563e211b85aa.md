### Title
Silent Block Drop via Negative Timeout in `BlockAssembler.timeout()` Allows Malicious Block Node to Suppress Transaction Indexing

### Summary
`BlockAssembler.timeout()` computes the remaining read budget as `timeout.toMillis() - stopwatch.elapsed(MILLISECONDS)` with no floor at zero. Once elapsed time exceeds the configured timeout, this returns a zero or negative value that is passed directly to `grpcCall.read()`. Java's blocking-queue poll semantics treat a non-positive timeout as an immediate non-blocking poll, returning `null` instantly. The while loop exits normally — no exception, no error counter increment, no node penalty — silently discarding any partially assembled block.

### Finding Description

**Exact location:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`

- `BlockAssembler.timeout()` — lines 274–281
- `grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)` — line 138

**Code path:**

```
BlockNode.streamBlocks()
  └─ while loop: grpcCall.read(assembler.timeout(), MILLISECONDS)
       └─ BlockAssembler.timeout()
            ├─ first call: stopwatch.start(); return timeout.toMillis()   // full budget
            └─ subsequent calls: return timeout.toMillis() - stopwatch.elapsed(MILLISECONDS)
                                 // can be 0 or NEGATIVE — no Math.max(0, …) guard
``` [1](#0-0) 

**Root cause:** `timeout()` has no lower bound. When `stopwatch.elapsed() > timeout.toMillis()`, the method returns a negative `long`. That value is forwarded verbatim to `grpcCall.read(negativeValue, MILLISECONDS)`. [2](#0-1) 

In gRPC-java, `BlockingClientCall.read()` delegates to a `LinkedBlockingQueue.poll(timeout, unit)`. Java's `BlockingQueue.poll(long, TimeUnit)` with a non-positive timeout returns `null` immediately if no message is already buffered. The while-loop condition `!= null` then evaluates to `false`, and the loop exits cleanly.

**Why existing checks fail:**

- `onError()` is only invoked inside `catch` blocks (lines 159–164). A `null` return from `read()` is not an exception — it exits the loop silently.
- `errors.set(0)` (line 157) is only reached when a response is successfully processed; it is never reached on the null-exit path.
- `stopwatch.reset()` (line 268) is only called inside `onEndOfBlock()`, which the attacker never triggers.
- There is no log statement, no metric, and no `BlockStreamException` thrown when the loop exits via `null`. [3](#0-2) 

**Exploit flow:**

1. Attacker operates (or compromises) a block node that the mirror node is configured to subscribe to.
2. Mirror node calls `streamBlocks()`. First `timeout()` call starts the stopwatch and returns `T` (full timeout, e.g. the default from `CommonDownloaderProperties`).
3. `grpcCall.read(T, MILLISECONDS)` blocks up to `T` ms.
4. Attacker sends one valid `BlockItemSet` containing a `BLOCK_HEADER` item quickly (e.g. at `t = 1 ms`). `onBlockItemSet()` appends it to `pending`.
5. Attacker withholds all further messages. The stopwatch keeps running.
6. At `t > T`, the next loop iteration calls `timeout()`, which returns `T - elapsed < 0`.
7. `grpcCall.read(negative, MILLISECONDS)` returns `null` immediately.
8. While loop exits. `pending` is non-empty but `onEndOfBlock()` was never called, so `blockStreamConsumer` is never invoked.
9. `streamBlocks()` returns normally. The block and all its transactions are silently discarded.
10. No error is recorded; the node remains `active`; the attacker can repeat on every subsequent block request.

### Impact Explanation

Every block the attacker chooses to target is silently dropped: `blockStreamConsumer` (i.e. `onBlockStream`) is never called, so the `BlockStream` containing all transactions of that block is never passed to the verifier or parser. Transactions in those blocks are never indexed in the mirror node database, making them invisible to all downstream consumers (REST API, gRPC API, etc.). Because no error counter is incremented and the node is never penalized, the attacker can sustain this indefinitely against a single-node configuration, or rotate across multiple nodes in a multi-node configuration to suppress blocks across the board.

### Likelihood Explanation

The precondition is controlling one block node endpoint that the mirror node trusts. Block nodes are external infrastructure; a compromised or maliciously registered node satisfies this. No cryptographic material, no privileged network position, and no mirror-node credentials are required. The timing manipulation (delay until elapsed > timeout) is trivially implemented by any TCP-level server that simply stops writing to the stream after the first message. The attack is fully repeatable and requires no special knowledge beyond the configured timeout value (which is a well-known configuration property).

### Recommendation

1. **Floor the timeout at 1 ms** inside `timeout()` to prevent a non-positive value from ever reaching `grpcCall.read()`:

```java
long timeout() {
    if (!stopwatch.isRunning()) {
        stopwatch.start();
        return timeout.toMillis();
    }
    return Math.max(1L, timeout.toMillis() - stopwatch.elapsed(TimeUnit.MILLISECONDS));
}
```

2. **Treat a `null` return from `read()` as a timeout error**, not a clean exit. After the while loop, check whether `pending` is non-empty and throw a `BlockStreamException` (which triggers `onError()` and increments the error counter):

```java
// after the while loop
if (!assembler.isPending()) { /* ok */ }
else { throw new BlockStreamException("Block stream timed out with pending items"); }
```

3. **Log a warning** whenever `read()` returns `null` mid-block so operators can detect the pattern.

4. **Consider a per-`BlockItemSet` deadline** (reset on each successful receive) rather than a single wall-clock budget for the entire block, so a slow-but-steady legitimate node is not penalized while still bounding attacker-induced delays.

### Proof of Concept

```
1. Configure mirror node with a single block node pointing to attacker-controlled server.
2. Attacker server implements SubscribeBlockStream gRPC:
   a. On receiving SubscribeStreamRequest, wait 10 ms.
   b. Send one SubscribeStreamResponse{block_items: {block_items: [BlockItem{block_header: ...}]}}.
   c. Stop writing. Hold the TCP connection open indefinitely.
3. Mirror node calls streamBlocks(blockNumber=N).
   - First timeout() → stopwatch starts, returns T (e.g. 30 000 ms).
   - grpcCall.read(30000, MILLISECONDS) blocks; receives the BLOCK_HEADER item at ~10 ms.
   - onBlockItemSet() appends to pending.
   - Second timeout() at t ≈ 10 ms → returns 29 990 ms.
   - grpcCall.read(29990, MILLISECONDS) blocks for ~29 990 ms with no data arriving.
   - At t ≈ 30 010 ms, third timeout() → returns 30 000 - 30 010 = -10 (negative).
   - grpcCall.read(-10, MILLISECONDS) returns null immediately.
4. While loop exits. blockStreamConsumer never called. Block N silently dropped.
5. No exception thrown, no error counter incremented, node stays active.
6. Repeat for every subsequent block request.
```

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L138-138)
```java
            while (!serverSuccess && (response = grpcCall.read(assembler.timeout(), TimeUnit.MILLISECONDS)) != null) {
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L155-172)
```java
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
