### Title
Unbounded Error Log Generation via `getBlockRange()` Failures Without Node Deactivation

### Summary
`BlockNode.getBlockRange()` catches all exceptions and logs them at ERROR level but never calls `onError()`, meaning the error counter is never incremented and the node is never deactivated regardless of how many consecutive failures occur. A malicious or compromised block node peer that consistently rejects the `serverStatus` gRPC call will be retried on every scheduling cycle indefinitely, generating unbounded ERROR-level log entries (each with a full stack trace) with no circuit-breaker or backoff, enabling disk exhaustion via log flooding.

### Finding Description
**Exact code path:**

In `BlockNode.java` lines 99–112, `getBlockRange()` catches all exceptions and returns `EMPTY_BLOCK_RANGE` without calling `onError()`:

```java
public Range<Long> getBlockRange() {
    try {
        ...
        final var response = blockNodeService.serverStatus(SERVER_STATUS_REQUEST);
        ...
    } catch (Exception ex) {
        log.error("Failed to get server status for {}", this, ex);  // ERROR log + full stack trace
        return EMPTY_BLOCK_RANGE;                                    // no onError() call
    }
}
```

By contrast, `streamBlocks()` (lines 159–164) correctly calls `onError()` on every exception, which increments `errors` and deactivates the node after `maxSubscribeAttempts` (default 3):

```java
private void onError() {
    errorsMetric.increment();
    if (errors.incrementAndGet() >= streamProperties.getMaxSubscribeAttempts()) {
        active = false;
        ...
    }
}
```

**Call chain that triggers repeated logging:**

`AbstractBlockSource.get()` → `BlockNodeSubscriber.doGet()` → `getNode()` → `hasBlock()` → `node.getBlockRange()` (lines 133–134 of `BlockNodeSubscriber.java`). On every scheduling cycle, `getNode()` iterates all active nodes and calls `hasBlock()` for each. Because a node that always fails `getBlockRange()` is never marked inactive, it is included in every iteration, generating one ERROR log entry (with full exception stack trace) per scheduling cycle per malicious node.

**Root cause:** The failed assumption is that `getBlockRange()` failures are transient/benign and do not warrant the same circuit-breaker treatment as `streamBlocks()` failures. In reality, a peer that consistently drops the `serverStatus` connection is indistinguishable from a malicious peer and should be subject to the same deactivation logic.

### Impact Explanation
Each `log.error()` call with a full gRPC stack trace produces several kilobytes of log data. With `responseTimeout = 400ms` (default in `StreamProperties.java` line 35), a single malicious node can generate ~2–3 error log entries per second per scheduling cycle. Over hours, this produces gigabytes of log data. If log rotation is absent or misconfigured, disk exhaustion causes the JVM or OS to crash or hang, taking down the mirror node importer — a non-network DoS. With multiple malicious nodes configured (or discovered via auto-discovery), the rate scales linearly.

### Likelihood Explanation
The attacker must control a host reachable at a configured or auto-discovered block node address. This is achievable by: (1) registering a malicious node via the auto-discovery mechanism (`registeredNodeRepository`, which reads from the network's registered node database — permissive in open networks); (2) compromising a legitimate block node; or (3) DNS/BGP hijacking of a configured endpoint. No cryptographic credential or on-chain privilege is required to simply accept a TCP connection and immediately close it, which is sufficient to trigger the exception path. The attack is fully repeatable and requires no ongoing effort once the malicious node is reachable.

### Recommendation
Call `onError()` (or a dedicated `onStatusError()` variant) inside the `catch` block of `getBlockRange()`, so that repeated `serverStatus` failures count toward the deactivation threshold:

```java
} catch (Exception ex) {
    log.error("Failed to get server status for {}", this, ex);
    onError();          // add this line
    return EMPTY_BLOCK_RANGE;
}
```

Alternatively, add a separate `getBlockRange`-specific failure counter with its own deactivation threshold and backoff, and replace `log.error` with `log.warn` after the first failure to reduce per-entry log volume. Also consider adding exponential backoff before retrying a node whose `getBlockRange()` has failed.

### Proof of Concept
1. Configure or inject (via auto-discovery) a block node entry pointing to an attacker-controlled server (e.g., `attacker.example.com:40840`).
2. On the attacker's server, listen on port 40840 and immediately close every incoming TCP connection (e.g., `while true; do nc -l 40840; done`).
3. Start the mirror node importer with this block node configured.
4. On every scheduling cycle, `BlockNodeSubscriber.get()` → `getNode()` → `hasBlock()` → `getBlockRange()` will attempt a gRPC `serverStatus` call, receive a connection reset, throw a `StatusRuntimeException`, and log `log.error("Failed to get server status for BlockNode(attacker.example.com:40840)", ex)` with a full stack trace.
5. The node is never deactivated (`active` remains `true`), so step 4 repeats on every cycle indefinitely.
6. Observe the log file growing without bound; no circuit-breaker fires.