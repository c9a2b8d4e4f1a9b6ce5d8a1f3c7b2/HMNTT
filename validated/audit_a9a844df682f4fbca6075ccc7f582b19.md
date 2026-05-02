The code has been verified against all claims. The `errors.set(0)` at line 157 is confirmed inside the while loop, firing after every non-throwing response. The `onError()` method at lines 196–207 matches exactly. The exploit flow is logically sound and the SECURITY.md does not exclude this class of finding.

---

Audit Report

## Title
Error Counter Reset on Intermediate Response Prevents Block Node Deactivation

## Summary
In `BlockNode.streamBlocks()`, the `errors` counter is unconditionally reset to zero after every non-throwing loop iteration — including `BLOCK_ITEMS` and `END_OF_BLOCK` responses. A malicious block node operator can exploit this by sending one valid intermediate response before each error, keeping the counter perpetually at 1 and never reaching the `maxSubscribeAttempts` threshold needed to mark the node inactive.

## Finding Description

**File:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`

The `errors.set(0)` call at line 157 is placed unconditionally after the `switch` statement, inside the `while` loop body. It executes after any response that does not throw — including `BLOCK_ITEMS` and `END_OF_BLOCK` — not only after a fully successful stream completion (`STATUS = SUCCESS`). [1](#0-0) 

The `onError()` method increments `errors` only when an exception is thrown, and deactivates the node only when the counter reaches `maxSubscribeAttempts`: [2](#0-1) 

`maxSubscribeAttempts` defaults to 3 and is constrained to a minimum of 1: [3](#0-2) 

**Exploit flow (maxSubscribeAttempts = 3):**

| Attempt | Attacker sends | `errors` after reset | `errors` after `onError()` | Node active? |
|---------|---------------|----------------------|---------------------------|--------------|
| 1 | `BLOCK_ITEMS` → `NOT_AVAILABLE` | 0 | 1 | yes |
| 2 | `BLOCK_ITEMS` → `NOT_AVAILABLE` | 0 | 1 | yes |
| N | `BLOCK_ITEMS` → `NOT_AVAILABLE` | 0 | 1 | yes (forever) |

The counter never accumulates across attempts because `errors.set(0)` fires on the `BLOCK_ITEMS` response before the error status is sent in the same or next call.

## Impact Explanation

The deactivation mechanism in `onError()` is permanently bypassed for any block node that sends at least one valid intermediate response per attempt. `BlockNodeSubscriber.getNode()` skips only inactive nodes; since the malicious node is never marked inactive, it is always selected. [4](#0-3) 

If the malicious node is the highest-priority or only configured node, every block ingestion attempt fails, causing persistent latency or a complete stall in block processing. The `readmitDelay` cooldown is also never applied, so there is no self-healing. [5](#0-4) 

## Likelihood Explanation

Any operator of a configured block node can execute this attack. The only requirement is that the node's gRPC server sends one `BLOCK_ITEMS` response before each error status response — a trivial modification to a standard block node implementation. No special privileges, timing precision, or coordination are required. The pattern is repeatable indefinitely. [6](#0-5) 

## Recommendation

Move `errors.set(0)` outside the while loop so it only executes after the loop exits normally (i.e., after a full successful stream, not after each intermediate response):

```java
// After the while loop, not inside it
if (serverSuccess) {
    errors.set(0);
}
```

Alternatively, only reset `errors` when `serverSuccess` is set to `true` inside the `STATUS` case, ensuring the counter is cleared only on a complete, graceful stream termination — not on partial data delivery. [7](#0-6) 

## Proof of Concept

Configure a gRPC server as a block node that, for every `SubscribeBlockStream` call:
1. Sends one `SubscribeStreamResponse` with `BLOCK_ITEMS` (any valid `BlockItemSet`).
2. Immediately sends a `SubscribeStreamResponse` with `STATUS = NOT_AVAILABLE`.

Observe that after N repeated calls (N > `maxSubscribeAttempts`), `BlockNode.isActive()` remains `true` and the node is never deactivated, while a correctly behaving node sending only error responses would be deactivated after 3 attempts. [2](#0-1)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L138-158)
```java
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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L26-27)
```java
    @Min(1)
    private int maxSubscribeAttempts = 3;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/StreamProperties.java (L29-31)
```java
    @DurationMin(seconds = 10)
    @NotNull
    private Duration readmitDelay = Duration.ofMinutes(1);
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
