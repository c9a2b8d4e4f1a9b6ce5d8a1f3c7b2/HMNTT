I have verified all code references against the actual repository. Here is my assessment:

**Verification results:**

- `streamBlocks()` catch structure at lines 159–164: confirmed — only `BlockStreamException` and `Exception` are caught; `java.lang.Error` subclasses are not. [1](#0-0) 
- `doGet()` calls `node.streamBlocks()` at line 66 with no `Throwable` catch: confirmed. [2](#0-1) 
- `BlockAssembler.append()` enforces only item count (`pendingCount > maxBlockItems`), no byte budget: confirmed. [3](#0-2) 
- `maxBlockItems` default = 800,000; `maxStreamResponseSize` default = 36 MB: confirmed. [4](#0-3) 
- `onError()` is the sole path that increments `errors`, sets `active = false`, and schedules `readmitTime`: confirmed. [5](#0-4) 
- `errors.set(0)` is called after each successful response iteration: confirmed. [6](#0-5) 

All technical claims are accurate. The SECURITY.md "Impacts that only require DDoS" exclusion applies to the *Websites and Apps* subsection and does not cover this backend service vulnerability, which additionally constitutes selective transaction suppression rather than generic availability denial.

---

# Audit Report

## Title
`Error`-Subclass Exceptions Bypass `onError()` in `BlockNode.streamBlocks()`, Keeping Malicious Node Permanently Active

## Summary
`BlockNode.streamBlocks()` catches only `BlockStreamException` and `Exception`, leaving `java.lang.Error` subclasses (e.g., `OutOfMemoryError`) uncaught by the error-accounting path. Because `BlockAssembler` enforces only an item-count limit (not a byte limit) on its accumulated `pending` list, a malicious block node can stream many large `BlockItemSet` responses within a single block to exhaust JVM heap. The resulting `OutOfMemoryError` propagates without ever invoking `onError()`, so the node's `active` flag and `errors` counter are never updated. The node is re-selected on every subsequent polling cycle, enabling persistent, targeted suppression of any chosen block.

## Finding Description

**Catch structure in `BlockNode.streamBlocks()` (lines 159–164):**

```java
} catch (BlockStreamException ex) {
    onError();
    throw ex;
} catch (Exception ex) {
    onError();
    throw new BlockStreamException(ex);
} finally {
    // only cancels the gRPC call
}
```

`java.lang.Error` is a direct subclass of `java.lang.Throwable`, not of `java.lang.Exception`. Any `Error` thrown inside the `try` block skips both catch clauses, skips `onError()`, and propagates through the `finally` block (which only cancels the gRPC call and disposes the buffer). [1](#0-0) 

**`BlockNodeSubscriber.doGet()` (line 66)** calls `node.streamBlocks(...)` with no surrounding `Throwable` catch, so any `Error` propagates unchecked to the caller. [7](#0-6) 

**Root cause — byte-unbounded accumulation in `BlockAssembler.append()` (lines 283–298):**

```java
pending.add(blockItems);
pendingCount += blockItems.size();
if (pendingCount > streamProperties.getMaxBlockItems()) {
    throw new BlockStreamException(...);
}
```

The guard counts *items*, not *bytes*. The gRPC channel enforces `maxInboundMessageSize` (default 36 MB) per individual `SubscribeStreamResponse`, but the assembler accumulates all responses for a block into `pending` without any byte budget. A malicious node can send N responses each containing one `BlockItem` of ~36 MB; the item count stays at N while heap consumption grows at 36 MB × N. [3](#0-2) 

**Defaults (StreamProperties.java):**
- `maxBlockItems` = 800,000 (item count)
- `maxStreamResponseSize` = 36 MB (per-message, not aggregate) [4](#0-3) 

**Why existing checks are insufficient:**

| Check | What it limits | What it misses |
|---|---|---|
| `maxInboundMessageSize` (36 MB) | Single gRPC message | Cross-message accumulation in `pending` |
| `maxBlockItems` (800,000) | Item *count* | Item *byte size* |
| `catch (Exception ex)` | Checked + unchecked exceptions | `java.lang.Error` hierarchy |

**`onError()` never called → node stays active:**

`onError()` (lines 196–207) is the sole mechanism that increments `errors`, compares against `maxSubscribeAttempts`, sets `active = false`, and schedules `readmitTime`. Without it, `active` remains `true` and `errors` stays at 0 (or is reset to 0 by `errors.set(0)` at line 157 on the last successful response before the attack). [5](#0-4) [6](#0-5) 

## Impact Explanation

A block node operator (no mirror-node credentials required) can target any specific block number:

1. Serve all preceding blocks normally, keeping `errors` reset to 0 each time.
2. For the targeted block, stream enough large `BlockItemSet` responses to exhaust heap.
3. `OutOfMemoryError` fires; `onError()` is skipped; the node remains `active = true`, `errors = 0`.
4. `AbstractBlockSource.get()` is called again on the next polling tick; `getNode()` selects the same node (still active, errors = 0); the attack repeats indefinitely.

The targeted block — and every transaction it contains — is never persisted to the mirror node database. Downstream API consumers, explorers, and compliance tools see those transactions as non-existent. This constitutes **selective transaction suppression with no automatic recovery**.

## Likelihood Explanation

**Preconditions:**
- Attacker controls or compromises one block node that the mirror node is configured to use (no mirror-node credentials needed).
- The mirror node's JVM heap is finite (always true).

**Feasibility:** The attack requires only a modified gRPC server that streams oversized `BlockItemSet` responses for a chosen block number. The default `maxStreamResponseSize` of 36 MB and `maxBlockItems` of 800,000 make the byte-budget gap wide enough to trigger OOM on any normally-provisioned JVM before the item-count guard fires.

**Repeatability:** Because `onError()` is never called, the node is never cooled down. The attack repeats on every polling cycle with no operator intervention required.

## Recommendation

1. **Catch `Throwable` (or at minimum `Error`) in `streamBlocks()`:**
   ```java
   } catch (BlockStreamException ex) {
       onError();
       throw ex;
   } catch (Exception ex) {
       onError();
       throw new BlockStreamException(ex);
   } catch (Error err) {
       onError();
       throw err;
   }
   ```
   This ensures `onError()` is always invoked regardless of what is thrown, so the node is correctly penalized.

2. **Add a byte-budget guard in `BlockAssembler.append()`:** Track the cumulative serialized size of all items added to `pending` and throw `BlockStreamException` when a configurable byte limit is exceeded, independent of item count.

3. **Add a `Throwable` catch in `BlockNodeSubscriber.doGet()`** as a defense-in-depth measure to prevent unhandled `Error`s from bypassing the node-selection logic entirely.

## Proof of Concept

```
1. Stand up a malicious gRPC server implementing BlockStreamSubscribeService.
2. Configure the mirror node to use this server as a block node.
3. For blocks 0..N-1, respond normally (valid BlockItemSet + EndOfBlock).
4. For block N (the target):
   a. Send a valid BLOCK_HEADER BlockItemSet (so pending is initialized).
   b. Repeatedly send BlockItemSet responses each containing one BlockItem
      whose serialized size is ~36 MB (the maxInboundMessageSize limit).
   c. Do NOT send EndOfBlock; keep streaming until OOM fires.
5. Observe: OutOfMemoryError propagates; onError() is never called;
   node.isActive() == true; errors == 0.
6. On the next polling cycle, the same node is selected again and step 4 repeats.
7. Block N is never persisted; all transactions in block N are permanently absent
   from the mirror node database.
```

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L157-157)
```java
                errors.set(0);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L159-171)
```java
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L20-24)
```java
    private int maxBlockItems = 800_000;

    @DataSizeUnit(DataUnit.MEGABYTES)
    @NotNull
    private DataSize maxStreamResponseSize = DataSize.ofMegabytes(36);
```
