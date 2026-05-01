### Title
All-Zero Topic Filter Normalization Produces Empty Buffer, Causing False-Negative Log Queries

### Summary
In `extractContractLogsMultiUnionQuery()`, the regex `replace(/^(0x)?0*/, '')` strips all characters from an all-zero topic value (e.g., `0x0000...0000`), producing an empty string. `Buffer.from('', 'hex')` yields a zero-length Buffer, which is used as the SQL parameter. However, the importer stores all-zero topics as a single `\x00` byte (not empty bytea), so the PostgreSQL comparison `'\x00'::bytea = ''::bytea` evaluates to FALSE, and matching log records are silently omitted from results.

### Finding Description

**Code location:** `rest/controllers/contractController.js`, lines 627–635

```js
case filterKeys.TOPIC0:
case filterKeys.TOPIC1:
case filterKeys.TOPIC2:
case filterKeys.TOPIC3:
  let topic = filter.value.replace(/^(0x)?0*/, '');   // line 631
  if (topic.length % 2 !== 0) {
    topic = `0${topic}`;
  }
  filter.value = Buffer.from(topic, 'hex');            // line 635
``` [1](#0-0) 

For any all-zero input (`0x0`, `0x00`, `0x0000`, `0x0000000000000000000000000000000000000000000000000000000000000000`), the regex strips every character, leaving `topic = ''`. `Buffer.from('', 'hex')` is a zero-length Buffer. This becomes the bound parameter in the SQL `cl.topic0 in ($N)` clause.

**How the importer stores all-zero topics:** `Utility.getTopic()` removes leading zeros but preserves the last byte unconditionally:

```java
for (int i = 0; i < topic.length; i++) {
    if (topic[i] != 0 || i == topic.length - 1) {   // last byte always kept
        firstNonZero = i;
        break;
    }
}
return Arrays.copyOfRange(topic, firstNonZero, topic.length);
``` [2](#0-1) 

For a 32-byte all-zero topic, the loop reaches `i = 31` (the last index), sets `firstNonZero = 31`, and returns `[0x00]` — a single zero byte. The DB column `topic0 bytea` therefore holds `\x00` (1 byte), not empty bytea.

**The mismatch:**
- DB value: `\x00` (1 byte)
- Query parameter: `''` (0 bytes, empty bytea)
- PostgreSQL: `'\x00'::bytea = ''::bytea` → `FALSE`

The `contract_log` table schema confirms `topic0` is `bytea null`: [3](#0-2) 

The `ContractLogViewModel` test independently confirms that an empty Buffer is treated as the all-zero topic on output, showing the system expects these to be equivalent — but the query path does not honour this: [4](#0-3) 

**No existing check prevents this.** The `checkTimestampsForTopics` function only validates timestamp range presence, not topic value content: [5](#0-4) 

The test suite for `extractContractLogsMultiUnionQuery` never tests an all-zero topic value, so the bug is undetected: [6](#0-5) 

### Impact Explanation
Any contract log whose `topic0`–`topic3` is the all-zero 32-byte value (`0x0000...0000`) is permanently invisible to REST API consumers who filter by that topic. The mirror node database holds the correct record, but the REST layer silently returns an empty result set. Applications (block explorers, DeFi monitors, event listeners) relying on `GET /api/v1/contracts/{id}/results/logs?topic0=0x0000...0000` receive a false empty response, breaking event-driven logic that depends on zero-valued topics.

### Likelihood Explanation
The all-zero topic (`bytes32(0)`) is a legitimate and commonly used sentinel/default value in Solidity event emissions. Any unprivileged user can trigger the bug with a single HTTP GET request — no authentication, no special role, no rate-limit bypass required. The input passes all existing validation (it is valid hex). The bug is deterministic and 100% reproducible on every affected query.

### Recommendation
Replace the stripping regex with one that preserves at least one zero byte when the entire value is zeros:

```js
let topic = filter.value.replace(/^(0x)?0*/, '');
// Fix: if stripping produced empty string, the canonical stored form is a single 0x00 byte
if (topic === '') {
  filter.value = Buffer.from([0x00]);
} else {
  if (topic.length % 2 !== 0) topic = `0${topic}`;
  filter.value = Buffer.from(topic, 'hex');
}
```

Alternatively, align the importer's `getTopic()` to store a true empty bytea for all-zero topics and update the REST layer to pass an empty Buffer — but this requires a data migration. The simpler fix is the REST-layer correction above.

### Proof of Concept

**Precondition:** A contract log exists in the DB with `topic0 = \x00` (stored by the importer for an all-zero Solidity topic).

**Trigger:**
```
GET /api/v1/contracts/results/logs?topic0=0x0000000000000000000000000000000000000000000000000000000000000000&timestamp=gte:0
```

**Trace:**
1. `filter.value = '0x0000000000000000000000000000000000000000000000000000000000000000'`
2. After `replace(/^(0x)?0*/, '')` → `topic = ''`
3. `topic.length % 2 === 0` → no padding applied
4. `Buffer.from('', 'hex')` → `<Buffer >` (0 bytes)
5. SQL executed: `... WHERE cl.topic0 in ($1)` with `$1 = ''::bytea`
6. DB row has `topic0 = '\x00'::bytea`
7. `'\x00' = ''` → FALSE → row excluded → response: `{"logs": [], "links": {"next": null}}`

**Expected result:** The log record should be returned.
**Actual result:** Empty logs array — the record is silently missing.

### Citations

**File:** rest/controllers/contractController.js (L281-305)
```javascript
const checkTimestampsForTopics = (filters) => {
  let hasTopic = false;
  const timestampFilters = [];
  for (const filter of filters) {
    switch (filter.key) {
      case filterKeys.TOPIC0:
      case filterKeys.TOPIC1:
      case filterKeys.TOPIC2:
      case filterKeys.TOPIC3:
        hasTopic = true;
        break;
      case filterKeys.TIMESTAMP:
        timestampFilters.push(filter);
        break;
      default:
        break;
    }
  }
  if (hasTopic) {
    try {
      utils.parseTimestampFilters(timestampFilters);
    } catch (e) {
      throw new InvalidArgumentError(`Cannot search topics without a valid timestamp range: ${e.message}`);
    }
  }
```

**File:** rest/controllers/contractController.js (L631-635)
```javascript
          let topic = filter.value.replace(/^(0x)?0*/, '');
          if (topic.length % 2 !== 0) {
            topic = `0${topic}`; // Left pad so that Buffer.from parses correctly
          }
          filter.value = Buffer.from(topic, 'hex');
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L174-181)
```java
        int firstNonZero = 0;
        for (int i = 0; i < topic.length; i++) {
            if (topic[i] != 0 || i == topic.length - 1) {
                firstNonZero = i;
                break;
            }
        }
        return Arrays.copyOfRange(topic, firstNonZero, topic.length);
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.0__create_tables.sql (L127-130)
```sql
    topic0              bytea   null,
    topic1              bytea   null,
    topic2              bytea   null,
    topic3              bytea   null,
```

**File:** rest/__tests__/viewmodel/contractLogViewModel.test.js (L84-99)
```javascript
  test('ContractLogViewModel - empty topic buffer is replaced with ZERO_UINT256', () => {
    expect(
      new ContractLogViewModel({
        ...defaultContractLog,
        topic0: Buffer.alloc(0), // empty buffer
        topic1: null,
        topic2: Buffer.alloc(0), // empty buffer
        topic3: null,
      })
    ).toEqual({
      ...defaultExpected,
      topics: [
        '0x0000000000000000000000000000000000000000000000000000000000000000',
        '0x0000000000000000000000000000000000000000000000000000000000000000',
      ],
    });
```

**File:** rest/__tests__/controllers/contractController.test.js (L1373-1415)
```javascript
      name: 'topics',
      input: {
        filter: [
          {
            key: constants.filterKeys.TOPIC0,
            operator: eq,
            value: '0x0011',
          },
          {
            key: constants.filterKeys.TOPIC0,
            operator: eq,
            value: '0x000013',
          },
          {
            key: constants.filterKeys.TOPIC2,
            operator: eq,
            value: '0x140',
          },
          {
            key: constants.filterKeys.TOPIC3,
            operator: eq,
            value: '0000150',
          },
          {
            key: constants.filterKeys.TOPIC3,
            operator: eq,
            value: '0000150',
          },
        ],
        contractId: defaultContractId,
      },
      expected: {
        ...defaultExpected,
        conditions: [defaultContractLogCondition, 'cl.topic0 in ($2,$3)', 'cl.topic2 in ($4)', 'cl.topic3 in ($5,$6)'],
        params: [
          defaultContractId,
          Buffer.from('11', 'hex'),
          Buffer.from('13', 'hex'),
          Buffer.from('0140', 'hex'),
          Buffer.from('0150', 'hex'),
          Buffer.from('0150', 'hex'),
        ],
      },
```
