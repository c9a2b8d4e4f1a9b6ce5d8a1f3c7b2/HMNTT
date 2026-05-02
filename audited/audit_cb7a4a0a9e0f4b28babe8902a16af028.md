### Title
Unauthenticated Full EVM Execution Trace Disclosure via Opcodes Endpoint

### Summary
The `getContractOpcodes()` endpoint in `OpcodesController` is publicly accessible with zero authentication or authorization controls. Any anonymous external user can request a full EVM execution trace — including stack, memory, and storage at every opcode step — for any historical contract transaction, enabling reconstruction of proprietary contract algorithms and extraction of private in-memory data.

### Finding Description
**Exact code path:** `web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java`, `getContractOpcodes()`, lines 52–68.

The handler is a plain `@GetMapping` with no Spring Security annotations (`@PreAuthorize`, `@Secured`, `@RolesAllowed`). No `SecurityFilterChain` or `WebSecurityConfigurerAdapter` exists anywhere in the `web3` module (confirmed by exhaustive search). The three checks that do exist are:

1. `properties.isEnabled()` (line 59) — a feature flag (`hiero.mirror.web3.opcode.tracer.enabled`, default `false`). When the feature is live/enabled, this is not an access control gate.
2. `throttleManager.throttleOpcodeRequest()` (line 61) — a rate limiter, not an identity or authorization check.
3. `validateAcceptEncodingHeader()` (lines 75–86) — enforces `Accept-Encoding: gzip`, not authentication.

When the feature flag is enabled, the call chain is:
```
Anonymous HTTP GET
  → getContractOpcodes()
  → OpcodeService.processOpcodeCall(OpcodeRequest(stack=true, memory=true, storage=true))
  → ContractDebugService.processOpcodeCall(params, opcodeContext)
  → Full EVM replay → OpcodesResponse with every opcode + stack + memory + storage
```

The `OpcodeRequest` constructor accepts all three boolean flags directly from query parameters with no privilege check:
```java
final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
return opcodeService.processOpcodeCall(request);
```

**Root cause:** The design assumption that this debugging endpoint would be protected by network-level controls (e.g., only exposed internally) is not enforced in code. The feature flag is an on/off switch, not an access control mechanism.

### Impact Explanation
When `stack=true&memory=true&storage=true` is requested:
- **Algorithm reconstruction:** The full ordered opcode sequence reveals the contract's control flow, branching logic, and business rules — effectively decompiling proprietary bytecode at runtime with concrete execution paths.
- **Private data extraction:** EVM `memory` contains ABI-decoded function arguments, intermediate computation results, and return values. EVM `storage` snapshots expose every slot read or written during execution, including values that are never emitted as events and are not otherwise observable on-chain.
- **Cross-transaction enumeration:** An attacker can enumerate all historical transactions against a target contract (transaction hashes are public on Hedera) and replay each one to build a complete picture of the contract's state history and internal logic.

Severity: **High**. The data exposed (full execution trace with memory/storage) goes far beyond what is available from normal on-chain data (events, return values).

### Likelihood Explanation
- **Precondition:** The operator has set `hiero.mirror.web3.opcode.tracer.enabled=true`. This is the only prerequisite; no credentials, API keys, or special network position are required.
- **Attacker capability:** Any internet user who can reach the mirror node's HTTP port. Transaction hashes are publicly visible on Hedera's ledger and mirror node REST API.
- **Repeatability:** Fully automatable. An attacker can script enumeration of all contract transactions and replay each with full trace options.
- **Rate limiting:** `throttleManager.throttleOpcodeRequest()` slows but does not prevent the attack; an attacker can distribute requests or wait between calls.

### Recommendation
1. **Add authentication/authorization at the controller layer.** Apply a Spring Security `@PreAuthorize` annotation (e.g., `@PreAuthorize("hasRole('ADMIN')")`) to `getContractOpcodes()`, or configure a `SecurityFilterChain` bean that requires authentication for the `/api/v1/contracts/results/*/opcodes` path pattern.
2. **Restrict by network policy as a defense-in-depth measure** (e.g., only expose the endpoint on a non-public interface), but do not rely on this alone.
3. **Consider whether `memory=true` and `storage=true` should require elevated privilege** even among authenticated users, given the sensitivity of the data they expose.

### Proof of Concept
**Precondition:** Mirror node is running with `hiero.mirror.web3.opcode.tracer.enabled=true` and is reachable at `<HOST>`.

**Step 1:** Obtain any historical contract transaction hash from the public mirror node REST API:
```
GET https://<HOST>/api/v1/contracts/results?limit=1
```
Extract `hash` from the response, e.g. `0xabc123...`.

**Step 2:** Request the full execution trace with no credentials:
```
curl -H "Accept-Encoding: gzip" \
  "https://<HOST>/api/v1/contracts/results/0xabc123.../opcodes?stack=true&memory=true&storage=true" \
  --compressed
```

**Result:** HTTP 200 with a JSON body containing the complete opcode-by-opcode execution trace, including the full EVM stack, memory contents, and storage slot values at every step of the transaction — with no authentication required.