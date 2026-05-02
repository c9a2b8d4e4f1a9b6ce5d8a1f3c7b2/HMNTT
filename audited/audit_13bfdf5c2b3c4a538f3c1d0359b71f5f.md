### Title
Unbounded Historical Block Tag Cardinality Inflation in MeterRegistry via Unprivileged `callContract()` Requests

### Summary
The `getBlock()` method in `ContractCallService` converts a historical block's `consensusEnd` nanosecond timestamp into a `YearMonth` string used as the `TAG_BLOCK` metric tag value. The only guard applied is `t <= Utils.getCurrentTimestamp()`, which exclusively filters future timestamps. Any past timestamp — including those from Hedera's genesis in September 2019 — passes the filter and produces a unique `YearMonth` tag value (e.g., `"2019-09"`, `"2020-03"`). An unprivileged user can systematically submit requests referencing one block per calendar month since genesis, creating ~72+ unique tag combinations in the `MeterRegistry` and inflating its cardinality.

### Finding Description

**Exact code path:**

`ContractCallService.java`, `getBlock()`, lines 177–184:
```java
private String getBlock() {
    return ContractCallContext.get()
            .getTimestamp()
            .filter(t -> t <= Utils.getCurrentTimestamp()) // Filter future timestamps to reduce cardinality
            .map(t ->
                    YearMonth.from(Instant.ofEpochSecond(0L, t).atZone(UTC)).toString())
            .orElse(BlockType.LATEST.toString());
}
```

`updateMetrics()`, lines 163–170, uses the result directly as a tag:
```java
invocationCounter.withTags(tags.and(TAG_BLOCK, block)).increment();
```

**Root cause:** The comment explicitly states the filter exists "to reduce cardinality," but the predicate `t <= Utils.getCurrentTimestamp()` only rejects future timestamps. All past timestamps — including those from years ago — satisfy the predicate and are mapped to a `YearMonth` string. Each unique `YearMonth` value combined with `TAG_STATUS` and `TAG_TYPE` registers a new `Counter` in the `MeterRegistry`.

**Exploit flow:**
1. `callContract()` sets `ctx.setBlockSupplier(...)` using `recordFileService.findByBlockType(params.getBlock())` — no restriction on which historical block number is accepted.
2. `ContractCallContext.getTimestamp()` (line 111–116) returns `Optional.ofNullable(getRecordFile()).map(RecordFile::getConsensusEnd)` when `useHistorical()` is true.
3. The `consensusEnd` of a genesis-era record file is a nanosecond timestamp from ~September 2019, which trivially satisfies `t <= Utils.getCurrentTimestamp()`.
4. `YearMonth.from(Instant.ofEpochSecond(0L, t).atZone(UTC)).toString()` produces `"2019-09"`.
5. `invocationCounter.withTags(tags.and(TAG_BLOCK, "2019-09")).increment()` registers a new `Counter` in the `MeterRegistry`.

**Why existing checks fail:** `RecordFileServiceImpl.findByBlockType()` (lines 19–29) accepts any block index via `recordFileRepository.findByIndex(block.number())` with no lower-bound restriction. The gas throttle manager limits gas consumption but does not prevent repeated requests with distinct historical block numbers.

### Impact Explanation
Each unique `(YearMonth, status, callType)` triple registers a new `Counter` in the `MeterRegistry`. Hedera mainnet has operated since September 2019 (~78 months as of May 2026). With multiple status values (SUCCESS + various `ResponseCodeEnum` error names) and multiple call types, an attacker can create hundreds of unique meter registrations. This inflates memory usage in the monitoring subsystem, degrades Prometheus/Micrometer scrape performance, and can cause monitoring dashboards and alerting systems to malfunction or become unresponsive — a classic cardinality-explosion griefing attack against the observability infrastructure.

### Likelihood Explanation
No authentication or privilege is required. Any caller of the `eth_call` or `eth_estimateGas` JSON-RPC endpoint can supply an arbitrary block number. The attacker needs only to enumerate one valid block number per calendar month since genesis (~78 requests total to exhaust all unique `YearMonth` values). This is trivially repeatable, requires no special knowledge, and the gas throttle does not prevent it since each request can use minimal gas.

### Recommendation
Apply a lower-bound guard symmetric to the existing upper-bound guard. For example, cap the tag to the current `YearMonth` for any timestamp older than a configurable retention window (e.g., 12 months), or bucket all timestamps older than a fixed cutoff into a single sentinel value such as `"historical"`:

```java
private String getBlock() {
    final long now = Utils.getCurrentTimestamp();
    final long cutoff = /* e.g., 12 months ago in nanos */;
    return ContractCallContext.get()
            .getTimestamp()
            .filter(t -> t <= now && t >= cutoff)
            .map(t -> YearMonth.from(Instant.ofEpochSecond(0L, t).atZone(UTC)).toString())
            .orElse(BlockType.LATEST.toString());
}
```
Alternatively, replace the `YearMonth` tag entirely with a boolean `"historical"` / `"latest"` tag, which bounds cardinality to a constant.

### Proof of Concept
1. Obtain the block number of the first record file on mainnet (block 0 / `EARLIEST`).
2. For each calendar month from September 2019 to the present (~78 months), find one valid block number whose record file has a `consensusEnd` within that month.
3. For each such block number, send an `eth_call` JSON-RPC request with `"blockNumber": "<hex_block_number>"` to the mirror node web3 endpoint.
4. After all ~78 requests, query the Prometheus metrics endpoint (`/actuator/prometheus`) and search for `hiero_mirror_web3_evm_invocation_total`.
5. Observe ~78 distinct `block` label values (e.g., `block="2019-09"`, `block="2019-10"`, …, `block="2026-05"`), each representing a separately registered `Counter` in the `MeterRegistry`, confirming unbounded cardinality inflation from unprivileged requests.