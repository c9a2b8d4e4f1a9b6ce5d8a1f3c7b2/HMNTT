### Title
Unprivileged Historical Block Injection Causes Metric Tag Pollution via Unbounded Past `YearMonth` Cardinality

### Summary
The `getBlock()` method in `ContractCallService` converts a historical block's `consensusEnd` nanosecond timestamp into a `YearMonth` string used as a Micrometer counter tag. The only guard present filters out **future** timestamps to reduce cardinality, but applies no lower-bound filter on **past** timestamps. Any unauthenticated caller can supply an arbitrary historical block number, causing the `hiero.mirror.web3.evm.invocation` counter to be emitted with a `block` tag value from any past year-month that has a corresponding record file in the database.

### Finding Description

**Exact code path:**

`callContract(CallServiceParameters, ContractCallContext)` sets the block supplier lazily: [1](#0-0) 

After execution, `doProcessCall` calls `updateMetrics`, which calls `getBlock()`: [2](#0-1) 

`getBlock()` reads the timestamp from the context and converts it to a `YearMonth` string: [3](#0-2) 

`ContractCallContext.getTimestamp()` returns the record file's `consensusEnd` whenever the block is not `LATEST`: [4](#0-3) 

`RecordFileServiceImpl.findByBlockType` resolves any user-supplied block number directly to a database record file with no age restriction: [5](#0-4) 

**Root cause:** The sole guard in `getBlock()` is `t <= Utils.getCurrentTimestamp()`, which only discards timestamps in the future. It was added to prevent unbounded cardinality from future-dated blocks, but the symmetric problem — unbounded cardinality from arbitrarily old past blocks — is completely unaddressed. Any block number accepted by `BlockType.of()` (decimal or hex, no lower bound) that resolves to an existing record file will produce a distinct `YearMonth` tag value. [6](#0-5) 

**Failed assumption:** The developer assumed that only future timestamps create cardinality risk. In practice, the Hedera mainnet has record files dating back to 2019, giving an attacker ~60+ distinct `YearMonth` values to inject into the metric registry.

### Impact Explanation

Every distinct `(status, type, block)` tag combination creates a new time-series in the Micrometer registry (and downstream in Prometheus/Grafana). By cycling through historical block numbers whose record files span different calendar months, an attacker can:

1. **Pollute monitoring dashboards** — the `hiero.mirror.web3.evm.invocation` counter will show non-zero invocation counts attributed to year-months from years ago, making it appear the mirror node was actively processing EVM calls during those historical periods.
2. **Cause metric cardinality explosion** — each unique `YearMonth` tag value is a new time-series. Sustained automated requests across all historical months exhaust Prometheus label cardinality limits and degrade monitoring infrastructure.
3. **Undermine alerting integrity** — rate-of-change alerts and anomaly detection based on the `block` tag dimension become unreliable.

The impact is confined to observability/monitoring integrity; it does not affect on-chain state or funds.

### Likelihood Explanation

- **No authentication required.** The `/api/v1/contracts/call` endpoint is public per the OpenAPI spec. [7](#0-6) 
- **Trivially reproducible.** A single HTTP POST with `{"block": "1", ...}` is sufficient to inject a tag from the genesis record file's year-month.
- **Automatable at scale.** An attacker can enumerate all historical block numbers in a loop, injecting one new `YearMonth` tag per distinct calendar month covered by the chain's history.
- **No rate-limiting specific to historical block queries** is visible in the code path.

### Recommendation

Apply a minimum-age guard symmetric to the existing maximum-age guard. For example, only emit a historical `YearMonth` tag if the timestamp falls within a configurable recent window (e.g., the last N months), and fall back to `BlockType.LATEST.toString()` for anything older:

```java
private String getBlock() {
    final long now = Utils.getCurrentTimestamp();
    final long cutoff = /* e.g. */ now - Duration.ofDays(90).toNanos();
    return ContractCallContext.get()
            .getTimestamp()
            .filter(t -> t <= now && t >= cutoff)
            .map(t -> YearMonth.from(Instant.ofEpochSecond(0L, t).atZone(UTC)).toString())
            .orElse(BlockType.LATEST.toString());
}
```

Alternatively, remove the `block` tag from the invocation counter entirely and track historical vs. latest calls via the existing `type` tag or a boolean `historical` tag, eliminating unbounded cardinality by design.

### Proof of Concept

**Preconditions:** Mirror node is running with historical data ingested (record files from multiple calendar months exist in the database).

**Steps:**

1. Identify the block number of a record file whose `consensusEnd` falls in a past year-month (e.g., block `1` from 2019):
   ```
   GET /api/v1/blocks/1
   ```
2. Send a contract call targeting that historical block:
   ```http
   POST /api/v1/contracts/call
   Content-Type: application/json

   {
     "block": "1",
     "data": "0x",
     "to": "0x0000000000000000000000000000000000000167",
     "gas": 21000
   }
   ```
3. Observe the Micrometer/Prometheus metrics endpoint:
   ```
   GET /actuator/prometheus
   ```
4. **Expected result:** `hiero_mirror_web3_evm_invocation_total{block="2019-09",...}` (or whichever year-month block 1's `consensusEnd` maps to) appears with a non-zero count.
5. Repeat step 2 with block numbers spanning different calendar months to inject additional historical `YearMonth` tag values into the metric registry.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L100-107)
```java
    protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx)
            throws MirrorEvmTransactionException {
        ctx.setCallServiceParameters(params);
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));

        return doProcessCall(params, params.getGas(), false);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L163-170)
```java
    protected final void updateMetrics(CallServiceParameters parameters, long gasUsed, int iterations, String status) {
        final var block = getBlock();
        final var callType = parameters.getCallType().toString();
        final var iterationTag = String.valueOf(iterations);
        var tags = Tags.of(TAG_STATUS, status, TAG_TYPE, callType);
        invocationCounter.withTags(tags.and(TAG_BLOCK, block)).increment();
        gasUsedCounter.withTags(tags.and(TAG_ITERATION, iterationTag)).increment(gasUsed);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L177-184)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L111-119)
```java
    public Optional<Long> getTimestamp() {
        if (useHistorical()) {
            return getTimestampOrDefaultFromRecordFile();
        }
        return Optional.empty();
    }

    private Optional<Long> getTimestampOrDefaultFromRecordFile() {
        return timestamp.or(() -> Optional.ofNullable(getRecordFile()).map(RecordFile::getConsensusEnd));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-29)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        } else if (block.isHash()) {
            return recordFileRepository.findByHash(block.name());
        }

        return recordFileRepository.findByIndex(block.number());
    }
```

**File:** rest/api/v1/openapi.yml (L461-474)
```yaml
  /api/v1/contracts/call:
    post:
      summary: Invoke a smart contract
      description:
        Returns a result from EVM execution such as cost-free execution of read-only smart contract queries, gas estimation, and transient simulation of read-write operations. If the `estimate` field is set to true gas estimation is executed.
        This API can process calls against the `latest` block or specific historical blocks when a hexadecimal or decimal block number is provided in the `block` field.
      operationId: contractCall
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ContractCallRequest"
      responses:
```
