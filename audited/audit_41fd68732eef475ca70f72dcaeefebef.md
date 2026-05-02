### Title
`BlockViewModel` Returns `null` for `logs_bloom` Instead of EVM-Spec Zero-Filled Bloom Filter

### Summary
In `rest/viewmodel/blockViewModel.js`, the `BlockViewModel` constructor uses a falsy check on `recordFile.logsBloom` and returns `null` when the database column is null. The Ethereum JSON-RPC specification mandates that `logsBloom` always be a 256-byte (512 hex char) DATA field — returning `null` violates this contract. Any unprivileged user can trigger this by requesting a block whose `logs_bloom` is null in the database, causing EVM-compatible clients that rely on the bloom filter for event-log filtering to malfunction.

### Finding Description
**Exact code location:** `rest/viewmodel/blockViewModel.js`, line 27:
```js
this.logs_bloom = recordFile.logsBloom ? toHexString(recordFile.logsBloom, true, 512) : null;
```
The ternary short-circuits on any falsy value (null, undefined, empty Buffer) and emits `null`. The unit test at `rest/__tests__/viewmodel/blockViewModel.test.js` line 47 explicitly asserts and accepts this behavior:
```js
test('nullable logs_bloom', () => {
  expect(new BlockViewModel(new RecordFile({logs_bloom: null})).logs_bloom).toStrictEqual(null);
});
```

**Root cause / failed assumption:** The code assumes that a `null` bloom is an acceptable API response. It is not — the Ethereum JSON-RPC spec requires `logsBloom` to be `DATA, 256 Bytes`. The sibling `ContractResultViewModel` (`rest/viewmodel/contractResultViewModel.js`, lines 16–17, 50–52) correctly handles this case with an explicit `EMPTY_BLOOM` constant:
```js
static #EMPTY_BLOOM = `0x${'00'.repeat(ContractResultViewModel.#BLOOM_SIZE)}`;
#encodeBloom(bloom) {
  return bloom?.length === 0 ? ContractResultViewModel.#EMPTY_BLOOM : toHexString(bloom, true);
}
```
`BlockViewModel` has no equivalent guard.

**When is `logs_bloom` null in the DB?** The `BackfillBlockMigration` (`importer/src/main/java/org/hiero/mirror/importer/migration/BackfillBlockMigration.java`) is an *async* background migration that backfills `logs_bloom` for older record files. Until it completes, any block that predates the migration or that had no contract transactions may have a null `logs_bloom` column. These blocks are permanently queryable via the public REST API.

**Exploit flow:**
1. Attacker (no credentials required) queries `GET /api/v1/blocks/{number}` for any block with a null `logs_bloom` in the database.
2. `BlockController.getByHashOrNumber` fetches the `RecordFile`, constructs a `BlockViewModel`, and serializes it.
3. The JSON response contains `"logs_bloom": null`.
4. An EVM-compatible client (ethers.js, web3.js, viem, or a custom contract event listener) receives `null` where it expects a 512-character hex string.
5. The client either throws a parse error, skips bloom-filter pre-screening entirely, or silently drops the block from its event scan — causing missed or incorrectly filtered contract events.

### Impact Explanation
EVM clients use the block-level bloom filter as a fast pre-filter before fetching full transaction receipts to find contract events. Receiving `null` instead of a valid 256-byte filter breaks this pipeline. Depending on client implementation, the result is one of: (a) unhandled exception / crash of the event listener, (b) silent skipping of the block (missed events), or (c) treating null as "no events" and never fetching receipts. All three outcomes constitute unintended smart contract behavior — event-driven contract logic (e.g., oracle callbacks, bridge relayers, DEX indexers) may fail to react to on-chain events from affected blocks. No funds are directly at risk, consistent with the Medium severity classification.

### Likelihood Explanation
The precondition (a block with null `logs_bloom`) is realistic and persistent: the async backfill migration may not have completed on all deployments, and any deployment that ingested blocks before the migration was introduced will have affected rows. The trigger requires zero privileges — a single unauthenticated HTTP GET. The behavior is deterministic and repeatable for every affected block number. Any EVM tooling pointed at the mirror node's REST/JSON-RPC layer is exposed.

### Recommendation
Apply the same pattern used in `ContractResultViewModel`. In `rest/viewmodel/blockViewModel.js`, replace line 27 with an explicit null-vs-empty distinction:
```js
const EMPTY_BLOOM = `0x${'00'.repeat(256)}`;
// in constructor:
this.logs_bloom = recordFile.logsBloom == null
  ? null                                          // truly unknown / pre-migration block
  : (recordFile.logsBloom.length === 0
      ? EMPTY_BLOOM
      : toHexString(recordFile.logsBloom, true, 512));
```
If the product decision is that a null DB value should also be surfaced as the zero bloom (matching Ethereum spec), change the null branch to return `EMPTY_BLOOM` as well. Update the unit test at line 47 of `blockViewModel.test.js` accordingly, and align the `gas_used === -1 → null` sentinel logic so both fields are consistently handled.

### Proof of Concept
1. Identify a block number whose `logs_bloom` column is null in the mirror node database (any block ingested before `BackfillBlockMigration` ran, or any block with no contract transactions on an unpatched deployment).
2. Send an unauthenticated request:
   ```
   GET /api/v1/blocks/16
   ```
3. Observe the response:
   ```json
   {
     "logs_bloom": null,
     ...
   }
   ```
4. In an ethers.js script, call `provider.getBlock(16)` against the mirror node's JSON-RPC endpoint. Attempt to use `block.logsBloom` as a `BloomFilter` object — ethers.js will throw `TypeError: Cannot read properties of null`.
5. Contrast with a block that has a non-null `logs_bloom`: the response correctly contains `"logs_bloom": "0x000...000"` and ethers.js processes it without error.