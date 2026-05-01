### Title
Silent Importer Stall via Malformed Data Files Uploaded to Cloud Storage Bucket

### Summary

In `Downloader.verifySignatures()`, when `streamFileReader.read(streamFileData)` throws an unchecked exception that is not `FileOperationException`, `HashMismatchException`, or `TransientProviderException` (e.g., `InvalidStreamFileException` or `StreamFileReaderException`), the generic `catch (Exception e)` block silently logs an error and advances to the next CONSENSUS_REACHED node. If an attacker with write access to the cloud storage bucket replaces the data files for all CONSENSUS_REACHED nodes with malformed content, every node attempt fails, `verifySignatures()` returns `false`, `lastStreamFile` is never advanced, and the importer retries the same batch indefinitely — stalling all stream processing.

### Finding Description

**Exact code path:**

`Downloader.java`, `verifySignatures()`, lines 320–383:

```java
T streamFile = streamFileReader.read(streamFileData);   // line 336 — throws before verify()
verify(streamFile, signature);                           // line 338 — never reached
```

Catch blocks at lines 363–379:
```java
} catch (FileOperationException | HashMismatchException | TransientProviderException e) {
    log.warn(...);   // named exceptions: warn + continue
} catch (Exception e) {
    log.error("Error downloading data file from node {} ...", nodeId, ...);
    // generic: error + continue — InvalidStreamFileException lands here
}
```

**Root cause:**

`InvalidStreamFileException` and `StreamFileReaderException` both extend `ImporterException` → `MirrorNodeException` → `RuntimeException`. Neither is listed in the explicit multi-catch. They fall to the generic `catch (Exception e)`, which logs an error and silently continues to the next node.

`CompositeRecordFileReader.read()` throws `InvalidStreamFileException` for any unrecognized version byte and `StreamFileReaderException` wrapping any `IOException`. A file containing arbitrary bytes (e.g., a version integer not in `{1,2,5,6}`) reliably triggers `InvalidStreamFileException` at line 55 of `CompositeRecordFileReader.java`.

**Why hash verification does not protect:**

`verify(streamFile, signature)` (line 338) is called *after* `read()`. If `read()` throws, `verify()` is never reached. The attacker does not need to produce a file whose hash matches the signature — they only need to produce a file that crashes the parser.

**Stall mechanism:**

After all CONSENSUS_REACHED nodes are exhausted, `verifySignatures()` returns `false` (line 382). Back in `verifySigsAndDownloadDataFiles()` (line 308–311), this only logs `"None of the data files could be verified"` — no exception is thrown, no state is advanced. `lastStreamFile` (the `AtomicReference` at line 86) is never updated because `onVerified()` is never called. On the next scheduled invocation, `getStartAfterFilename()` returns the same filename (line 253–263), the same batch is downloaded, and the cycle repeats indefinitely.

### Impact Explanation

The importer permanently stalls on the targeted batch file. No subsequent record files, balance files, or event files are processed. The mirror node falls arbitrarily far behind the network. Because the failure is only logged (not alerted), operators may not notice until the mirror node's data is visibly stale. This constitutes a sustained denial-of-service against the mirror node's stream processing pipeline, matching the described scope of "shutdown of ≥30% of network processing nodes without brute force."

### Likelihood Explanation

The precondition is write access to the cloud storage bucket. This is achievable via: misconfigured bucket ACLs (public write), compromised cloud credentials, or a supply-chain/insider attack on the storage layer. The attacker does not need any Hedera network keys or node access. Once write access is obtained, the attack is trivially repeatable: upload a 4-byte file (e.g., `\x00\x00\x00\x07` — version 7, unsupported) to the data file path for each CONSENSUS_REACHED node. The attack persists until an operator manually removes the malformed files and restarts the importer.

### Recommendation

1. **Treat `InvalidStreamFileException` and `StreamFileReaderException` as deterministic parse failures, not transient node errors.** Add them to the explicit catch alongside `HashMismatchException`:
   ```java
   } catch (FileOperationException | HashMismatchException
            | InvalidStreamFileException | StreamFileReaderException
            | TransientProviderException e) {
       log.warn(...);
   }
   ```
   This does not fix the stall by itself, but correctly classifies the failure.

2. **Distinguish "all nodes returned a parse error" from "transient failure."** If every CONSENSUS_REACHED node produces a deterministic parse exception for the same filename, the importer should raise a hard error (throw, alert, or halt) rather than silently returning `false` and retrying.

3. **Add a circuit-breaker or retry limit** in `verifySigsAndDownloadDataFiles()`: after N consecutive failures on the same `earliestFilename`, disable the downloader and emit a metric/alert rather than looping forever.

4. **Enforce bucket write restrictions** via IAM policies so that only authorized node operators can write data files.

### Proof of Concept

**Preconditions:** Attacker has write access to the GCS/S3 bucket used by the mirror node importer.

**Steps:**

1. Observe the importer's current `lastStreamFile` (e.g., `2024-01-01T00_00_00Z.rcd`). The next batch will target `2024-01-01T00_00_05Z.rcd`.

2. For each node folder that will have `CONSENSUS_REACHED` status (at minimum 1/3 of staked nodes), upload a malformed file to the data file path:
   ```
   recordstreams/record<nodeId>/2024-01-01T00_00_05Z.rcd
   ```
   Content: any 4 bytes with an unsupported version, e.g. `\x00\x00\x00\x07`.

3. Leave the corresponding `.rcd_sig` signature files untouched (they were uploaded by the real nodes and are cryptographically valid).

4. Wait for the importer's next scheduled `download()` invocation.

**Observed result:**
- `nodeSignatureVerifier.verify()` succeeds (signatures are valid).
- `verifySignatures()` is called; for each CONSENSUS_REACHED node, `CompositeRecordFileReader.read()` throws `InvalidStreamFileException("Unsupported record file version 7 in file ...")`.
- The generic `catch (Exception e)` logs `"Error downloading data file from node X ..."` and continues.
- After all nodes are exhausted, `verifySignatures()` returns `false`.
- `lastStreamFile` is unchanged.
- Every subsequent scheduled run repeats identically — the importer is permanently stalled. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L253-263)
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
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L308-311)
```java
            boolean valid = verifySignatures(signatures, earliestFilename);
            if (!valid) {
                log.error("None of the data files could be verified, signatures: {}", signatures);
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L331-379)
```java
            try {
                var dataFilename = signature.getDataFilename();
                var node = signature.getNode();
                var streamFileData = Objects.requireNonNull(
                        streamFileProvider.get(dataFilename).block());
                T streamFile = streamFileReader.read(streamFileData);

                verify(streamFile, signature);

                var archiveDestinationFolder = importerProperties.getArchiveDestinationFolderPath(streamFileData);

                if (downloaderProperties.isWriteFiles()) {
                    Utility.archiveFile(streamFileData.getFilePath(), streamFile.getBytes(), archiveDestinationFolder);
                }

                if (downloaderProperties.isWriteSignatures()) {
                    signatures.forEach(s -> Utility.archiveFile(
                            s.getFilename().getBucketFilePath(), s.getBytes(), archiveDestinationFolder));
                }

                if (!downloaderProperties.isPersistBytes()) {
                    streamFile.setBytes(null);
                }

                if (dataFilename.getInstant().isAfter(endDate)) {
                    downloaderProperties.setEnabled(false);
                    log.warn("Disabled polling after downloading all files <= endDate ({})", endDate);
                    return false;
                }

                onVerified(streamFileData, streamFile);
                return true;
            } catch (FileOperationException | HashMismatchException | TransientProviderException e) {
                final var previous =
                        lastStreamFile.get().map(StreamFile::getName).orElse("None");
                log.warn(
                        "Failed processing signatures after {} from node {} corresponding to {}. Earliest failure in batch is {}. {}",
                        previous,
                        nodeId,
                        signature.getFilename(),
                        earliestFilename,
                        e.getMessage());
            } catch (Exception e) {
                log.error(
                        "Error downloading data file from node {} corresponding to {}. Will retry another node",
                        nodeId,
                        signature.getFilename(),
                        e);
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/record/CompositeRecordFileReader.java (L54-63)
```java
                default:
                    throw new InvalidStreamFileException(
                            String.format("Unsupported record file version %d in file %s", version, filename));
            }

            RecordFile recordFile = reader.read(streamFileData);
            count = recordFile.getCount();
            return recordFile;
        } catch (IOException e) {
            throw new StreamFileReaderException("Error reading record file " + filename, e);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/exception/InvalidStreamFileException.java (L6-6)
```java
public class InvalidStreamFileException extends ImporterException {
```
