All code claims are verifiable. Let me confirm each one against the actual source.

**Confirmed: Missing `return`** — `BlockNode.java` lines 241–244 show the `pending.isEmpty()` branch calls `handleRecoverableError` and then `return`s. Lines 248–253 show the block-number mismatch branch calls `handleRecoverableError` with **no `return`**, falling through to line 270. [1](#0-0) 

**Confirmed: `handleRecoverableError` behavior** — throws `ParserException` when `HALT_ON_ERROR_PROPERTY=true`, logs and returns normally when false (default). [2](#0-1) 

**Confirmed: Path A catch** — `ParserException` is not a `BlockStreamException`, so it is caught by the generic `catch (Exception ex)` at lines 162–164, which calls `onError()` and re-throws as `BlockStreamException`. [3](#0-2) 

**Confirmed: Path B fall-through** — line 270 uses `blockNumber` from `blockEnd.getBlockNumber()` (attacker-controlled) to build the filename, not `blockHeader.getNumber()`. [4](#0-3) 

**Confirmed: `verifyBlockNumber()` downstream catch** — parses block number from filename and compares to `blockFile.getIndex()` (set from `BlockHeader.number` by the reader); a mismatch throws `InvalidStreamFileException`. [5](#0-4) 

**SECURITY.md scope check** — The exclusion list does not exclude attacks from malicious block nodes. "Impacts that only require DDoS" is listed under Websites and Apps and does not apply here, since the attack exploits a specific code defect with a crafted protobuf field. No other exclusion applies. [6](#0-5) 

---

# Audit Report

## Title
Missing `return` After Block Number Mismatch in `BlockAssembler.onEndOfBlock()` Enables Malicious Block Node to Abort Streaming Sessions

## Summary
In `BlockNode.java`, the inner class `BlockAssembler.onEndOfBlock()` correctly guards the `pending.isEmpty()` case with a `return` after calling `Utility.handleRecoverableError()`, but omits the equivalent `return` for the `BlockHeader.number != EndOfBlock.blockNumber` mismatch case. This asymmetric omission causes two distinct failure paths depending on the `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR` setting, both of which terminate the streaming session and drop all transactions in the affected block.

## Finding Description

**File:** `importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java`
**Class:** `BlockAssembler` (inner class of `BlockNode`)
**Method:** `onEndOfBlock()`
**Lines:** 239–272

The `pending.isEmpty()` guard at line 241 calls `handleRecoverableError` and then `return`s (line 244). The block-number mismatch guard at lines 248–253 calls `handleRecoverableError` but has **no `return`**, allowing execution to fall through to the block assembly and `blockStreamConsumer.accept()` call at lines 270–271. [1](#0-0) 

`Utility.handleRecoverableError()` has two behaviors controlled by the `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR` system property:
- **`true`:** throws `ParserException`
- **`false` (default):** logs at ERROR level and returns normally [2](#0-1) 

**Path A — `HALT_ON_ERROR_PROPERTY=true`:**
`handleRecoverableError` throws `ParserException`. This is not a `BlockStreamException`, so it bypasses the first `catch` block and is caught by the generic `catch (Exception ex)` at lines 162–164, which calls `onError()` and re-throws as `BlockStreamException`. The block is never assembled; all transactions in it are dropped for this streaming cycle. [3](#0-2) 

**Path B — `HALT_ON_ERROR_PROPERTY=false` (default):**
`handleRecoverableError` logs and returns. Execution falls through to line 270, where `BlockFile.getFilename(blockNumber, false)` uses the attacker-supplied `blockNumber` from `blockEnd.getBlockNumber()` to construct the filename. The `BlockStream` is passed to `blockStreamConsumer` with this attacker-controlled filename. Downstream, `BlockStreamVerifier.verifyBlockNumber()` parses the block number from the filename and compares it to `blockFile.getIndex()` (which is set from `BlockHeader.number` by the reader). Since these differ, `InvalidStreamFileException` is thrown, which is also caught by the generic `catch (Exception ex)` in `streamBlocks()`, calling `onError()` and terminating the session. [5](#0-4) 

## Impact Explanation
Every time a malicious block node sends a `BlockEnd` message with a `blockNumber` that differs from the `BlockHeader.number` already in the stream, the streaming session is aborted and the block's transactions are not recorded in the mirror node for that cycle. If the attacker controls the only configured block node, or all configured block nodes, and cloud storage fallback is disabled or unavailable, the mirror node stalls indefinitely at the targeted block number. Downstream consumers (REST API, gRPC API, event streaming) receive no data for that block or any subsequent block. The `onError()` / `maxSubscribeAttempts` / `readmitDelay` mechanism only throttles reconnection; it does not prevent the attacker from repeating the attack on every new session.

## Likelihood Explanation
The precondition is controlling a block node — an external infrastructure component registered with the mirror node via configuration. A malicious operator running their own block node, or an attacker who has compromised a legitimate block node host, satisfies this precondition without any privileged access to the mirror node itself. The attack requires crafting a single protobuf field (`EndOfBlock.blockNumber`) to a value differing from `BlockHeader.number`. It is trivially repeatable on every new streaming session and requires no cryptographic material or consensus participation.

## Recommendation
Add a `return` statement immediately after the `Utility.handleRecoverableError(...)` call in the block-number mismatch branch of `onEndOfBlock()`, mirroring the existing pattern in the `pending.isEmpty()` branch:

```java
if (blockHeader.getNumber() != blockNumber) {
    Utility.handleRecoverableError(
            "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
            blockHeader.getNumber(),
            blockNumber);
    return;  // ← add this
}
```

This ensures that in the default configuration (Path B), the malformed `EndOfBlock` message is discarded without assembling a block with an attacker-controlled filename, eliminating the downstream `InvalidStreamFileException` and the resulting session termination. [7](#0-6) 

## Proof of Concept

1. Configure the mirror node to stream from a block node under attacker control.
2. The attacker's block node sends a valid stream of `BlockItemSet` messages for block N (including a `BlockHeader` with `number = N`).
3. The attacker's block node sends a `BlockEnd` message with `blockNumber = N + 1` (or any value ≠ N).
4. `onEndOfBlock()` is called. `pending` is non-empty, so the first guard passes. The mismatch check fires `handleRecoverableError`.
   - **Path A (`HALT_ON_ERROR=true`):** `ParserException` is thrown, caught by `catch (Exception ex)`, `onError()` is called, session terminates. Block N transactions are dropped.
   - **Path B (default):** Execution falls through. `BlockFile.getFilename(N+1, false)` produces filename `"0000000000000000001.blk"` (for N=0). `BlockStreamVerifier.verifyBlockNumber()` parses `1` from the filename but reads `0` from `blockFile.getIndex()`, throws `InvalidStreamFileException`, caught by `catch (Exception ex)`, `onError()` is called, session terminates. Block N transactions are dropped.
5. Repeat on every reconnection to keep the mirror node stalled at block N indefinitely.

### Citations

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

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockNode.java (L239-272)
```java
        void onEndOfBlock(final BlockEnd blockEnd) {
            final long blockNumber = blockEnd.getBlockNumber();
            if (pending.isEmpty()) {
                Utility.handleRecoverableError(
                        "Received end-of-block message for block {} while there's no pending block items", blockNumber);
                return;
            }

            final var blockHeader = pending.getFirst().getFirst().getBlockHeader();
            if (blockHeader.getNumber() != blockNumber) {
                Utility.handleRecoverableError(
                        "Block number mismatch in BlockHeader({}) and EndOfBlock({})",
                        blockHeader.getNumber(),
                        blockNumber);
            }

            final List<BlockItem> block;
            if (pending.size() == 1) {
                block = pending.getFirst();
            } else {
                // assemble when there are more than one BlockItemSet
                block = new ArrayList<>();
                for (final var items : pending) {
                    block.addAll(items);
                }
            }

            pending.clear();
            pendingCount = 0;
            stopwatch.reset();

            final var filename = BlockFile.getFilename(blockNumber, false);
            blockStreamConsumer.accept(new BlockStream(block, null, filename, loadStart));
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L220-231)
```java
    public static void handleRecoverableError(String message, Object... args) {
        var haltOnError = Boolean.parseBoolean(System.getProperty(HALT_ON_ERROR_PROPERTY));

        if (haltOnError) {
            var formattingTuple = MessageFormatter.arrayFormat(message, args);
            var throwable = formattingTuple.getThrowable();
            var formattedMessage = formattingTuple.getMessage();
            throw new ParserException(formattedMessage, throwable);
        } else {
            log.error(RECOVERABLE_ERROR + message, args);
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/BlockStreamVerifier.java (L169-179)
```java
        try {
            final var filename = blockFile.getName();
            final int endIndex = filename.indexOf(FilenameUtils.EXTENSION_SEPARATOR);
            final long actual = Long.parseLong(endIndex != -1 ? filename.substring(0, endIndex) : filename);
            if (actual != blockNumber) {
                throw new InvalidStreamFileException(String.format(
                        "Block number mismatch, from filename = %d, from content = %d", actual, blockNumber));
            }
        } catch (final NumberFormatException _) {
            throw new InvalidStreamFileException("Failed to parse block number from filename " + blockFile.getName());
        }
```

**File:** SECURITY.md (L1-65)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities

The following activities are prohibited by default on bug bounty programs on Immunefi. Projects may add further restrictions to their own program.

- Any testing on mainnet or public testnet deployed code; all testing should be done on local forks of either public testnet or mainnet.
- Any testing with pricing oracles or third-party smart contracts.
- Attempting phishing or other social engineering attacks against employees and/or customers.
- Any testing with third-party systems and applications (e.g. browser extensions), as well as websites (e.g. SSO providers, advertising networks).
- Any denial-of-service attacks that are executed against project assets.
- Automated testing of services that generates significant amounts of traffic.
- Public disclosure of an unpatched vulnerability in an embargoed bounty.
```
