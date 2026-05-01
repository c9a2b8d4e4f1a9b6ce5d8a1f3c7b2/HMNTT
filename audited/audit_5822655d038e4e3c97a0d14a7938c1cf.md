### Title
`onErrorContinue` Silently Drops Node Signatures on Parse Failure, Enabling Consensus Stall via Malformed Signature File Injection

### Summary
In `downloadAndParseSigFiles()`, a single `onErrorContinue` operator swallows all exceptions thrown by `signatureFileReader.read()` for any node, only emitting a log error and silently excluding that node's signature from `sigFilesMap`. If an attacker with write access to the cloud storage bucket injects malformed signature files for ≥1/3 of nodes (the consensus threshold), no consensus can be reached and the importer cannot make forward progress, effectively stalling stream file ingestion for as long as the malformed files remain.

### Finding Description

**Exact code location:**

`importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java`, lines 211–225:

```java
final var signatures = Objects.requireNonNull(Flux.fromIterable(nodes)
    .flatMap(node -> streamFileProvider
        .list(node, startAfterFilename)
        .take(listLimit)
        .map(s -> {
            var streamFileSignature = signatureFileReader.read(s);   // throws on malformed input
            streamFileSignature.setNode(node);
            streamFileSignature.setStreamType(streamType);
            return streamFileSignature;
        })
        .onErrorContinue((e, s) -> log.error(                        // ← swallows ALL errors
            "Error downloading signature files for node {}", node, e)))
    ...
    .collect(this::getStreamFileSignatureMultiMap, (map, s) -> map.put(s.getFilename(), s))
    ...
    .block());
``` [1](#0-0) 

**Root cause:** `onErrorContinue` is a Reactor operator that, when an error occurs in an upstream element, discards that element and resumes the stream. Here it is scoped to the entire per-node `flatMap` pipeline. Any exception from `signatureFileReader.read()` — including `InvalidStreamFileException` or `SignatureFileParsingException` thrown by `ProtoSignatureFileReader`, `SignatureFileReaderV5`, or `SignatureFileReaderV2` on malformed input — causes the signature for that node to be silently omitted from `sigFilesMap`. Only a `log.error` is emitted; no counter is incremented, no exception propagates. [2](#0-1) 

**Consensus threshold:** `NodeSignatureVerifier.verify()` delegates to `consensusValidator.validate()`, which requires at least 1/3 of total node stake to have verified signatures. [3](#0-2) 

If ≥1/3 of nodes' signatures are absent from `sigFilesMap` (because `onErrorContinue` dropped them), `consensusValidator.validate()` throws `SignatureVerificationException`.

**Error handling in `verifySigsAndDownloadDataFiles()`:** The exception is caught; if more filename groups remain it logs a warning and continues; if it is the last group it re-throws. [4](#0-3) 

**Error handling in `downloadNextBatch()`:** The re-thrown `SignatureVerificationException` is caught and only logged as a warning. The method returns normally; `lastStreamFile` is never updated. [5](#0-4) 

On the next polling cycle the importer re-attempts the same files. As long as the malformed files remain in the bucket, every cycle fails identically — the importer makes no forward progress.

### Impact Explanation

The importer permanently stalls ingestion of all stream file types (record, balance, event) for the affected network. No new transactions are indexed into the mirror node database. Downstream consumers (REST API, gRPC API, monitoring) receive no new data. The impact matches the stated scope: shutdown of ≥30% of network processing nodes' contribution to the mirror node without brute-force key compromise.

### Likelihood Explanation

**Precondition:** The attacker must have write access to the cloud storage bucket paths for ≥1/3 of nodes' signature files. This is not a zero-privilege attack — it requires compromised cloud credentials, a misconfigured bucket ACL (e.g., public write), or a supply-chain compromise of the storage layer. This is a meaningful barrier. However, cloud bucket misconfigurations are a well-documented real-world attack surface, and the mirror node's bucket is explicitly designed to be publicly readable, making ACL misconfiguration plausible.

**Repeatability:** Once malformed files are in place, the attack is self-sustaining with no further attacker action. The importer will retry indefinitely and fail every cycle.

**Detection:** Only `log.error` and `log.warn` are emitted. No dedicated metric counter is incremented for the `onErrorContinue` path specifically. Operators relying solely on log-level alerting may not notice until significant lag accumulates.

### Recommendation

1. **Replace `onErrorContinue` with explicit error handling:** Convert parse failures into a sentinel value or use `onErrorResume` to return an empty `Mono`, and increment a dedicated Micrometer counter per node per failure so alerting thresholds can be set.
2. **Add a minimum-signature-count guard before calling `verifySigsAndDownloadDataFiles`:** If `sigFilesMap` contains signatures from fewer than 1/3 of expected nodes, emit a structured alert (metric + log at ERROR with node IDs) before attempting verification.
3. **Separate transient I/O errors from structural parse errors:** Transient errors (network timeout, `TransientProviderException`) may warrant silent retry; structural parse errors (malformed file bytes) should be treated as a security-relevant anomaly and surfaced immediately.

### Proof of Concept

**Preconditions:**
- Attacker has write access to the cloud storage bucket (e.g., via misconfigured ACL or compromised credentials).
- Network has N nodes; attacker targets ⌈N/3⌉ of them.

**Steps:**

1. Identify the signature file paths for ⌈N/3⌉ nodes for the next expected stream filename (e.g., `recordstreams/record0.0.3/2024-01-01T00_00_00.000000000Z.rcd_sig`).
2. Replace each targeted node's `.rcd_sig` file with a zero-byte or random-byte file. `ProtoSignatureFileReader.readSignatureFile()` will throw `InvalidStreamFileException` (wrong version byte or failed proto parse).
3. Wait for the importer's next polling cycle (`downloaderProperties.getFrequency()`).
4. Observe in logs: `ERROR … Error downloading signature files for node X` for each targeted node (from `onErrorContinue`), followed by `WARN … Signature verification failed` (from `downloadNextBatch`).
5. Confirm `lastStreamFile` is not updated — the importer retries the same timestamp on every subsequent cycle and never advances.
6. The attack persists until the malformed files are removed from the bucket. [1](#0-0) [6](#0-5)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L165-169)
```java
        } catch (SignatureVerificationException e) {
            log.warn(e.getMessage());
        } catch (Exception e) {
            log.error("Error downloading files", e);
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L211-225)
```java
        final var signatures = Objects.requireNonNull(Flux.fromIterable(nodes)
                .flatMap(node -> streamFileProvider
                        .list(node, startAfterFilename)
                        .take(listLimit)
                        .map(s -> {
                            var streamFileSignature = signatureFileReader.read(s);
                            streamFileSignature.setNode(node);
                            streamFileSignature.setStreamType(streamType);
                            return streamFileSignature;
                        })
                        .onErrorContinue((e, s) -> log.error("Error downloading signature files for node {}", node, e)))
                .timeout(downloaderProperties.getCommon().getTimeout())
                .collect(this::getStreamFileSignatureMultiMap, (map, s) -> map.put(s.getFilename(), s))
                .subscribeOn(Schedulers.parallel())
                .block());
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/Downloader.java (L296-306)
```java
            try {
                nodeSignatureVerifier.verify(signatures);
            } catch (SignatureVerificationException ex) {
                var statusMapMessage = statusMap(signatures, nodeIds);
                if (sigFilenameIter.hasNext()) {
                    log.warn("{}. Trying next group: {}", ex.getMessage(), statusMapMessage);
                    continue;
                }

                throw new SignatureVerificationException(ex.getMessage() + ": " + statusMapMessage);
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/NodeSignatureVerifier.java (L22-44)
```java
     * Verifies that the signature files satisfy the consensus requirement:
     * <ol>
     *  <li>If NodeStakes are within the NodeStakeRepository, at least 1/3 of the total node stake amount has been
     *  signature verified.</li>
     *  <li>If no NodeStakes are in the NodeStakeRepository, At least 1/3 signature files are present</li>
     *  <li>For a signature file, we validate it by checking if it's signed by corresponding node's PublicKey. For valid
     *      signature files, we compare their hashes to see if at least 1/3 have hashes that match. If a signature is
     *      valid, we put the hash in its content and its file to the map, to see if at least 1/3 valid signatures have
     *      the same hash</li>
     * </ol>
     *
     * @param signatures a list of signature files which have the same filename
     * @throws SignatureVerificationException
     */
    public void verify(Collection<StreamFileSignature> signatures) throws SignatureVerificationException {

        for (StreamFileSignature streamFileSignature : signatures) {
            if (verifySignature(streamFileSignature)) {
                streamFileSignature.setStatus(SignatureStatus.VERIFIED);
            }
        }

        consensusValidator.validate(signatures);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reader/signature/ProtoSignatureFileReader.java (L42-44)
```java
        } catch (IllegalArgumentException | IOException e) {
            throw new InvalidStreamFileException(filename, e);
        }
```
