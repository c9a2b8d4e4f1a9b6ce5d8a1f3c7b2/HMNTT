### Title
Oversized File Injection Causes Permanent Record Ingestion Stall in S3StreamFileProvider

### Summary
An attacker with write access to the cloud storage bucket can upload files exceeding the 50 MiB `maxSize` limit into every consensus node's path. Because the size filter in `S3StreamFileProvider.list()` silently discards oversized objects while `pathResult.update(true)` is still called (preventing any fallback), the `lastStreamFile` pointer never advances, causing the downloader to re-scan the same oversized batch on every poll cycle and stall record ingestion indefinitely without crashing the importer.

### Finding Description

**Exact code path:**

In `S3StreamFileProvider.list()`:

```
importer/src/main/java/org/hiero/mirror/importer/downloader/provider/S3StreamFileProvider.java
Lines 98–114
```

The S3 listing returns up to `batchSize` (default `25 * 2 = 50`) objects after `startAfter`. The critical sequence is:

1. **Line 100–102** — `pathResult.update(!l.contents().isEmpty())` is evaluated against the *raw* S3 response, before any size filtering. If S3 returns 50 oversized objects, `update(true)` is called, permanently suppressing the `NODE_ID` fallback path. [1](#0-0) 

2. **Line 105** — `.filter(r -> r.size() <= downloaderProperties.getMaxSize())` silently drops every oversized object, producing an empty Flux downstream. [2](#0-1) 

3. **Line 114** — `switchIfEmpty` only falls back when `pathResult.fallback()` is true (i.e., in AUTO mode trying NODE_ID). Because `update(true)` was already called in step 1, `fallback()` returns `false`, so `Flux.empty()` is returned. [3](#0-2) 

4. Back in `Downloader.downloadAndParseSigFiles()`, the collected `signatures` multimap is empty. No call to `onVerified()` is made, so `lastStreamFile` is never updated. [4](#0-3) 

5. On the next scheduled poll, `getStartAfterFilename()` returns the same unchanged `lastStreamFile`, producing the same `startAfter` value, listing the same batch of oversized files, and repeating the cycle forever. [5](#0-4) 

**Root cause:** The `pathResult.update()` call uses the pre-filter S3 response count, not the post-filter count. This creates a logical disconnect: the system believes it found files (preventing fallback), but the filter discards all of them, and the progress pointer never advances.

**`maxSize` default:** [6](#0-5) 

### Impact Explanation

Record ingestion halts permanently without any crash or alerting beyond a repeated log line `"No new signature files to download after file: …"`. The importer process stays alive and healthy from a JVM perspective, but no new record files are ever processed. All downstream consumers (REST API, gRPC API) serve stale data. Because the attack targets every node's path simultaneously, the consensus threshold (1/3 of nodes) can never be met even if some nodes are unaffected, matching the "≥30% of network processing nodes shut down" severity classification.

### Likelihood Explanation

The precondition is write access to the cloud storage bucket. For production Hedera mainnet/testnet, the bucket is not publicly writable, so the attacker must either: (a) exploit a misconfigured bucket ACL, (b) compromise a node's upload credentials, or (c) target a self-hosted mirror node deployment where the operator has misconfigured bucket permissions. The attack itself requires only uploading ≥50 files per node path with names lexicographically after the last processed file — a trivial operation once write access is obtained. The stall is permanent and self-sustaining; the attacker does not need to maintain any ongoing connection.

### Recommendation

Fix the logical disconnect between the pre-filter and post-filter counts:

1. **Move `pathResult.update()` to after the size filter**, so it reflects whether any *usable* files were found, not just whether S3 returned any objects.
2. **Alternatively**, when the post-filter Flux is empty but the pre-filter S3 response was non-empty (all objects were oversized), log a warning and advance `startAfterFilename` past the last oversized object's key to prevent re-scanning the same batch.
3. **Add a metric/alert** for the case where all objects in a batch are rejected by the size filter, so operators are notified rather than silently stalled.

### Proof of Concept

**Preconditions:** Write access to the cloud storage bucket; knowledge of the last processed record file name (obtainable from the mirror node REST API).

**Steps:**

1. Determine `lastProcessedFile` (e.g., `2024-01-01T00_00_00.000000000Z.rcd_sig`) from the mirror node's `/api/v1/blocks` endpoint.

2. For each consensus node path (e.g., `record/record0.0.3/`, `record/record0.0.4/`, …), upload 50 files named lexicographically after `lastProcessedFile` but before the next legitimate file, each exceeding 50 MiB:
   ```
   record/record0.0.3/2024-01-01T00_00_00.000000001Z.rcd_sig  (51 MiB of zeros)
   record/record0.0.3/2024-01-01T00_00_00.000000002Z.rcd_sig  (51 MiB of zeros)
   ... (48 more)
   ```
   Repeat for every node path.

3. Wait for the next downloader poll cycle (default 500 ms for record files).

4. Observe: the S3 listing returns the 50 oversized files per node; all are filtered by the size check; `pathResult.update(true)` suppresses fallback; `signatures` is empty; `lastStreamFile` is unchanged.

5. On every subsequent poll, the same 50 oversized files are returned and discarded. The mirror node's latest block number stops incrementing permanently. The importer logs only `"No new signature files to download after file: 2024-01-01T00_00_00.000000000Z.rcd_sig"` at INFO level every 500 ms.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/provider/S3StreamFileProvider.java (L100-102)
```java
                .doOnNext(l -> {
                    pathResult.update(!l.contents().isEmpty());
                    log.debug("Returned {} s3 objects", l.contents().size());
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/provider/S3StreamFileProvider.java (L105-105)
```java
                .filter(r -> r.size() <= downloaderProperties.getMaxSize())
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/provider/S3StreamFileProvider.java (L114-114)
```java
                .switchIfEmpty(Flux.defer(() -> pathResult.fallback() ? list(node, lastFilename) : Flux.empty()));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L227-240)
```java
        long total = signatures.size();
        if (total > 0) {
            var rate = (int) (1000000.0 * total / stopwatch.elapsed(TimeUnit.MICROSECONDS));
            var counts = signatures.keySet().stream()
                    .limit(10)
                    .collect(Collectors.toMap(
                            Function.identity(), s -> signatures.get(s).size()));
            log.info("Downloaded {} signatures in {} ({}/s): {}", total, stopwatch, rate, counts);
        } else {
            log.info(
                    "No new signature files to download after file: {}. Retrying in {} s",
                    startAfterFilename,
                    downloaderProperties.getFrequency().toMillis() / 1_000f);
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L253-264)
```java
    private StreamFilename getStartAfterFilename() {
        return lastStreamFile
                .get()
                .or(() -> {
                    Optional<StreamFile<I>> streamFile = dateRangeCalculator.getLastStreamFile(streamType);
                    lastStreamFile.compareAndSet(Optional.empty(), streamFile);
                    return streamFile;
                })
                .map(StreamFile::getName)
                .map(StreamFilename::from)
                .orElse(StreamFilename.EPOCH);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/CommonDownloaderProperties.java (L61-62)
```java
    @Min(2L)
    private long maxSize = 50L * 1024L * 1024L; // 50 MiB
```
