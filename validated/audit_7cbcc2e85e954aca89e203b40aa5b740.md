The code matches the claims exactly. Let me verify the key facts:

1. `scaleGas()` at [1](#0-0)  uses `Math.floorDiv`, confirmed.
2. `ThrottleManagerImpl.throttle()` at [2](#0-1)  passes `scaleGas(request.getGas())` directly to `gasLimitBucket.tryConsume()`, confirmed.
3. `ContractCallRequest.gas` has only `@Min(21_000)` at [3](#0-2) , no upper-band constraint, confirmed.
4. `validateContractMaxGasLimit` at [4](#0-3)  only checks a ceiling, not intra-band abuse, confirmed.
5. SECURITY.md at [5](#0-4)  does not exclude throttle-bypass findings; the closest exclusions ("Best practice recommendations", "Impacts that only require DDoS") do not apply here — this is a specific exploitable design flaw, not a general recommendation, and the attack is not a volumetric DDoS but a per-request gas amplification.

---

Audit Report

## Title
Gas Throttle Bypass via Integer Division Truncation in `scaleGas()`

## Summary
`ThrottleProperties.scaleGas()` uses `Math.floorDiv` with a scale factor of 10,000, creating 9,999-unit bands where any gas value within a band consumes the same number of bucket tokens. An unprivileged attacker can submit requests with `gas=29999` and consume only 2 tokens — identical to a `gas=21000` request — obtaining approximately 43% more EVM gas per throttle token than the operator configured.

## Finding Description
**File:** `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, lines 42–47

```java
private static final long GAS_SCALE_FACTOR = 10_000L;

public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {
        return 0L;
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);  // floor truncation
}
```

`Math.floorDiv` truncates, so every gas value in `[N×10000, (N+1)×10000 − 1]` maps to the same token count `N`:

| Gas value | `scaleGas()` result | Tokens consumed |
|-----------|---------------------|-----------------|
| 21,000    | 2 | 2 |
| 25,000    | 2 | 2 |
| 29,999    | 2 | 2 |
| 30,000    | 3 | 3 |

**Exploit flow:**

In `ThrottleManagerImpl.throttle()` (line 40 of `ThrottleManagerImpl.java`):
```java
gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))
```
An attacker sets `"gas": 29999` in the `ContractCallRequest` JSON body. The `@Min(21_000)` constraint on `ContractCallRequest.gas` (line 36–37 of `ContractCallRequest.java`) is satisfied. `validateContractMaxGasLimit` (line 92–96 of `ContractController.java`) only checks an upper ceiling. The bucket deducts 2 tokens — identical to a `gas=21000` request — but the EVM executes with 29,999 gas units.

**Why existing checks fail:**
- `@Min(21_000)` enforces only a lower bound; it does not prevent intra-band exploitation.
- `validateContractMaxGasLimit` checks only an upper ceiling, not intra-band abuse.
- No ceiling division or rounding-up is applied in `scaleGas`.

## Impact Explanation
An attacker can consistently obtain `29999 / 21000 ≈ 1.428×` more EVM gas per throttle token than the operator configured — a ~43% gas throughput surplus per request. At scale (e.g., the default 500 req/s rate limit), this translates to the attacker driving ~43% more EVM computation through the node than intended, potentially exhausting node resources, degrading service for legitimate users, or enabling denial-of-service at lower cost than anticipated.

## Likelihood Explanation
No authentication or special privilege is required. Any external user can craft a JSON body with `"gas": 29999`. The attack is trivially repeatable, stateless, and requires no on-chain assets. It is exploitable by any party who can reach the `/api/v1/contracts/call` endpoint.

## Recommendation
Replace `Math.floorDiv` with ceiling division in `scaleGas()` so that the bucket always deducts at least as many tokens as the gas value warrants:

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {
        return 0L;
    }
    // Ceiling division: (gas + GAS_SCALE_FACTOR - 1) / GAS_SCALE_FACTOR
    return Math.ceilDiv(gas, GAS_SCALE_FACTOR);
}
```

This ensures `scaleGas(29999)` returns 3 (same as `scaleGas(30000)`), eliminating the intra-band free-gas window. The `getGasPerSecond()` bucket capacity should be recalculated accordingly to account for the slightly higher token costs.

## Proof of Concept
```
POST /api/v1/contracts/call
Content-Type: application/json

{
  "to": "0x<valid_contract_address>",
  "gas": 29999
}
```
Repeat this request. Each call deducts 2 tokens from `gasLimitBucket` — the same as a `gas=21000` request — while the EVM is given 29,999 gas units. Compare with `"gas": 21000` to confirm identical token consumption via throttle metrics or by observing that both requests succeed at the same rate under a tight gas-per-second limit.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L40-40)
```java
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-37)
```java
    @Min(21_000)
    private long gas = 15_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L92-96)
```java
    private void validateContractMaxGasLimit(ContractCallRequest request) {
        if (request.getGas() > evmProperties.getMaxGasLimit()) {
            throw new InvalidParametersException(
                    "gas field must be less than or equal to %d".formatted(evmProperties.getMaxGasLimit()));
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
