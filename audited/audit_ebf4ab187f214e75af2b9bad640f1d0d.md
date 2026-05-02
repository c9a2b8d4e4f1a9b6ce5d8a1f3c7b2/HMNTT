### Title
Missing NodeMap Allowlist Validation in `/construction/payloads` Allows Arbitrary Node Routing

### Summary
The `getTransactionNodeAccountId` function in `rosetta/app/services/construction_service.go` parses the user-supplied `node_account_id` metadata field and returns it directly without ever checking it against the operator-configured `NodeMap` allowlist. Any unprivileged external user can supply an arbitrary valid account ID string, which will be embedded verbatim into the constructed transaction, completely bypassing the node allowlist the operator intended to enforce.

### Finding Description
**Code path:**

`ConstructionPayloads` (line 222) → `getTransactionNodeAccountId` (lines 370–391) → `transactionSetNodeAccountId` (line 251)

```
// rosetta/app/services/construction_service.go, lines 370-391
func (c *constructionAPIService) getTransactionNodeAccountId(metadata map[string]any) (
    emptyAccountId hiero.AccountID, nilErr *rTypes.Error,
) {
    value, ok := metadata[metadataKeyNodeAccountId]
    if !ok {
        return emptyAccountId, errors.ErrMissingNodeAccountIdMetadata
    }
    str, ok := value.(string)
    if !ok {
        return emptyAccountId, errors.ErrInvalidArgument
    }
    nodeAccountId, err := hiero.AccountIDFromString(str)
    if err != nil {
        ...
        return emptyAccountId, errors.ErrInvalidAccount
    }
    return nodeAccountId, nilErr   // ← returned with NO allowlist check
}
```

The `NodeMap` (`config.Rosetta.Nodes`, type `map[string]hiero.AccountID`) is consumed **only** in `NewConstructionAPIService` (lines 613–614) to initialize the SDK client via `hiero.ClientForNetworkV2(config.Rosetta.Nodes)`. It is never consulted again during request handling.

`getRandomNodeAccountId` (lines 511–538) uses `sdkClient.GetNetwork()` to suggest a valid node in the `/construction/metadata` response, but the user is free to ignore that suggestion and supply any string in the subsequent `/construction/payloads` call.

**Root cause / failed assumption:** The code assumes the client will echo back the `node_account_id` that was suggested by `/construction/metadata`. There is no enforcement of this assumption; the user-supplied value is accepted after only a syntactic parse check.

**Checksum dimension:** `hiero.AccountIDFromString` stores the checksum field inside the returned `hiero.AccountID` struct. Even if a map lookup against `NodeMap` were added naively (e.g., iterating and comparing structs), an ID submitted as `"0.0.3-abcde"` (non-zero checksum) would not equal the stored `hiero.AccountID{Account: 3}` (zero checksum), so the check would fail and the attacker could still bypass it by appending any checksum suffix to a real node ID. The primary issue, however, is that no such lookup exists at all.

### Impact Explanation
The operator configures `NodeMap` to restrict which Hiero network nodes the rosetta service will route transactions to (e.g., for compliance, reliability, or network segmentation). Because `getTransactionNodeAccountId` performs no allowlist check, an attacker can embed any `shard.realm.num` account ID into the frozen transaction body. The resulting signed transaction, when submitted via `/construction/submit`, will be directed to a node of the attacker's choosing rather than one from the operator's approved set. This defeats the purpose of the `NodeMap` configuration entirely and can be used to route transactions to untrusted, unreliable, or attacker-controlled nodes.

### Likelihood Explanation
No authentication or privilege is required. The `/construction/payloads` endpoint is publicly reachable. The exploit requires only a standard HTTP POST with a crafted JSON body. It is trivially repeatable and requires no special tooling beyond a basic HTTP client. Any user who has observed a normal `/construction/metadata` → `/construction/payloads` flow can replicate the attack by simply substituting a different `node_account_id` value.

### Recommendation
In `getTransactionNodeAccountId`, after parsing the account ID, validate it against the operator's configured node set. The SDK client's current network map (populated from `NodeMap`) is already available via `c.sdkClient.GetNetwork()`:

```go
// After parsing nodeAccountId, add:
allowed := false
for _, allowedId := range c.sdkClient.GetNetwork() {
    if allowedId.Account == nodeAccountId.Account &&
       allowedId.Shard == nodeAccountId.Shard &&
       allowedId.Realm == nodeAccountId.Realm {
        allowed = true
        break
    }
}
if !allowed {
    return emptyAccountId, errors.ErrInvalidAccount
}
```

Compare only the `Shard`/`Realm`/`Account` numeric fields, not the full struct, to avoid the checksum-mismatch bypass described above.

### Proof of Concept
**Preconditions:** Operator has configured `NodeMap` with only `{"34.94.106.61:50211": "0.0.3"}`. The `/construction/metadata` endpoint returns `node_account_id: "0.0.3"`.

**Trigger:**
```bash
curl -X POST http://<rosetta-host>/construction/payloads \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {"blockchain":"Hiero","network":"mainnet"},
    "operations": [...],
    "metadata": {
      "node_account_id": "0.0.999",
      "valid_until_nanos": "<valid_future_nanos>"
    }
  }'
```

**Result:** The endpoint returns HTTP 200 with an `unsigned_transaction` whose protobuf body encodes `nodeAccountID = 0.0.999` — a node not in the operator's `NodeMap`. The transaction, once signed and submitted via `/construction/submit`, will be routed to node `0.0.999` rather than the operator-approved `0.0.3`.

**Checksum variant (secondary):** Even if a naive struct-equality check against `NodeMap` were added, submitting `"node_account_id": "0.0.3-xxxx"` (any non-empty checksum suffix) would produce a `hiero.AccountID` whose checksum field differs from the stored `hiero.AccountID{Account:3}`, causing the check to incorrectly reject a legitimate node or, conversely, accept an illegitimate one depending on implementation, confirming the need for field-by-field numeric comparison.