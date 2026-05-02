### Title
Unauthenticated `from` Field in `ContractCallRequest` Allows Bypass of `RequestFilter` Address-Based Access Controls

### Summary
The `from` field in `ContractCallRequest` is entirely user-supplied with no cryptographic authentication or ownership verification. The `RequestFilter` system reads this field directly via `FilterField.FROM` to make throttle/block decisions, meaning any unprivileged caller can set `from` to any Ethereum address — including whitelisted or blocked ones — trivially defeating operator-configured address-based access controls.

### Finding Description

**Root cause — unauthenticated `from` field:**

`ContractCallRequest.from` carries only a hex-format annotation; there is no signature, proof-of-ownership, or session binding: [1](#0-0) 

`ContractController.call()` accepts the field at face value and passes it directly into EVM execution as the sender: [2](#0-1) [3](#0-2) 

**Root cause — filter reads the unauthenticated value:**

`RequestFilter.test()` extracts the `from` value with `ContractCallRequest::getFrom` and compares it against the operator-configured expression: [4](#0-3) [5](#0-4) 

`FilterType.EQUALS` uses `String::equalsIgnoreCase` — a pure string comparison against the attacker-controlled value: [6](#0-5) 

**Exploit flow — bypassing a BLOCK rule:**

An operator configures:
```yaml
field: FROM
type: EQUALS
expression: "0x000000000000000000000000000000000000dead"
action: BLOCK
```
An attacker who would normally be blocked simply omits `from` or supplies any other address. The filter never matches; the block is completely ineffective.

**Exploit flow — impersonating a whitelisted address:**

An operator configures a rule that gives address `0xTRUSTED` a privileged action (e.g., bypass throttle, elevated gas limit). An attacker sets `"from": "0xTRUSTED"` in the JSON body. The `FilterField.FROM` extractor returns the attacker-supplied string, the `EQUALS` predicate matches, and the attacker receives the privileged treatment.

The global `rateLimitBucket` defined in `ThrottleConfiguration.rateLimitBucket()` is the shared token bucket that throttle decisions feed into: [7](#0-6) 

Any per-address exemption from consuming tokens from this bucket can be claimed by any caller.

### Impact Explanation

Address-based `RequestFilter` rules using `FilterField.FROM` provide zero security guarantee. An operator who configures such rules to block abusive addresses or to grant trusted addresses special throttle treatment is operating under a false assumption. Attackers can freely impersonate any Ethereum address, bypass rate-limit enforcement, or evade block rules with a trivial one-field change in the JSON body. This undermines the entire operator-facing access-control surface of the throttle system.

### Likelihood Explanation

Exploitation requires no privileges, no credentials, no special tooling — only the ability to send an HTTP POST to `/api/v1/contracts/call` with an arbitrary JSON body. The attack is repeatable, stateless, and requires no prior knowledge beyond the target address to impersonate. Any public deployment that relies on `FilterField.FROM` rules for security is immediately exploitable.

### Recommendation

1. **Do not use `FilterField.FROM` for security-sensitive block/allow decisions** — document clearly that `from` is an unauthenticated simulation hint, not an identity claim.
2. If address-based rate limiting is required, key it on the **authenticated network identity** of the caller (e.g., IP address, API key, mTLS client certificate) rather than the user-supplied `from` field.
3. Add a warning in `RequestFilter` or its configuration schema that `FilterField.FROM` matching is advisory/logging-only and must not be used as an access-control gate.
4. If `from`-based blocking is kept, enforce it only in combination with a verified caller identity (e.g., require an API key that is bound to the claimed address).

### Proof of Concept

**Setup:** Operator has configured a `RequestFilter` with `field=FROM`, `type=EQUALS`, `expression=0x000000000000000000000000000000000000dead`, `action=BLOCK`.

**Step 1 — confirm block works for the exact address:**
```bash
curl -X POST https://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"from":"0x000000000000000000000000000000000000dead","to":"0x...","data":"0x","gas":50000}'
# Expected: 429 / blocked
```

**Step 2 — bypass by supplying any other address:**
```bash
curl -X POST https://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"from":"0x000000000000000000000000000000000000beef","to":"0x...","data":"0x","gas":50000}'
# Result: 200 OK — block rule completely bypassed
```

**Step 3 — impersonate a whitelisted address (if a whitelist/bypass rule exists for `0xTRUSTED`):**
```bash
curl -X POST https://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"from":"0x<TRUSTED_ADDRESS>","to":"0x...","data":"0x","gas":15000000}'
# Result: request treated as coming from the trusted address, throttle bypass granted
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L33-34)
```java
    @Hex(minLength = ADDRESS_LENGTH, maxLength = ADDRESS_LENGTH)
    private String from;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-51)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L53-54)
```java
    private ContractExecutionParameters constructServiceParameters(ContractCallRequest request) {
        final var fromAddress = request.getFrom() != null ? Address.fromHexString(request.getFrom()) : Address.ZERO;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L31-35)
```java
    public boolean test(ContractCallRequest request) {
        var value = field.getExtractor().apply(request);
        var stringValue = value instanceof String s ? s : String.valueOf(value);
        return type.getPredicate().test(stringValue, expression);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L43-43)
```java
        FROM(ContractCallRequest::getFrom),
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L53-55)
```java
    enum FilterType {
        CONTAINS(Strings.CI::contains),
        EQUALS(String::equalsIgnoreCase);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
