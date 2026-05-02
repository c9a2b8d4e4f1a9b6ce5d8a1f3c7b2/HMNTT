Based on my investigation of the relevant files, here is my assessment: [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
CPU Exhaustion via Unbounded `data` Field in `ContractCallRequest` Matched Against `FilterType.CONTAINS`

### Summary
The `data` field in `ContractCallRequest` carries no `maxLength` constraint in its `@Hex` annotation, allowing arbitrarily large hex strings to pass validation. When a `RequestFilter` with `FilterField.DATA` and `FilterType.CONTAINS` is configured, `Strings.CI::contains` — an O(n×m) case-insensitive substring scan — is executed against the full, unbounded data string for every request that passes the upstream rate/gas bucket checks. An unprivileged attacker can exploit this to saturate CPU, degrading throttle enforcement for all users.

### Finding Description
**Code path:**

1. `ThrottleManagerImpl.throttle()` (lines 37–48) first consumes from `rateLimitBucket` and `gasLimitBucket`, then iterates over every configured `RequestFilter` and calls `requestFilter.test(request)`.
2. `RequestFilter.test()` (lines 31–35) extracts the field value via `field.getExtractor().apply(request)` — for `FilterField.DATA` this is `ContractCallRequest::getData` — and then calls `type.getPredicate().test(stringValue, expression)`.
3. `FilterType.CONTAINS` binds `Strings.CI::contains` (line 54 of `RequestFilter.java`), Apache Commons Lang's case-insensitive contains, which is an O(n×m) scan (n = data length, m = expression length).
4. `ContractCallRequest.data` is annotated `@Hex` (line 28–29 of `ContractCallRequest.java`) **without** a `maxLength` parameter. The `from` and `to` fields both carry explicit `maxLength = ADDRESS_LENGTH` constraints; `data` does not. This means arbitrarily large hex strings pass bean validation and reach `throttle()`.

**Root cause / failed assumption:** The design assumes the `data` field is bounded by some upstream constraint (HTTP body limit or `@Hex` maxLength). No such bound is enforced in the application layer, so the string comparison cost scales linearly with attacker-controlled input.

**Exploit flow:**
- Attacker sends requests with a `data` value at the HTTP body size limit (Spring Boot default: 1 MB → ~1,000,000 hex characters).
- Each request passes `rateLimitBucket` (up to 500/s) and `gasLimitBucket` (gas field is independent of data size).
- For each request, `Strings.CI::contains(~1_000_000_char_string, expression)` executes on the server thread.
- At 500 req/s × 1 MB data, the server performs ~500 MB/s of case-insensitive character scanning, saturating CPU cores handling request threads.
- If multiple `DATA`/`CONTAINS` filters are configured, the cost multiplies per filter.

### Impact Explanation
CPU exhaustion degrades or halts throttle enforcement for all users of the node. Legitimate `eth_call` and `eth_estimateGas` requests are delayed or dropped. Because the rate limit bucket is consumed before the expensive filter evaluation, the attacker simultaneously exhausts the rate limit for other users **and** burns CPU, creating a compounded denial-of-service. Severity: **High**.

### Likelihood Explanation
No authentication or special privilege is required — any caller with network access to the JSON-RPC endpoint can submit a `ContractCallRequest`. The exploit is trivially repeatable with a simple HTTP client loop. The only prerequisite is that at least one `RequestFilter` with `FilterField.DATA` and `FilterType.CONTAINS` is configured by the operator, which is the documented and intended use case for this feature.

### Recommendation
1. **Add `maxLength` to the `@Hex` annotation on `data`** in `ContractCallRequest.java`, matching the maximum EVM calldata size (e.g., 24 KB for contract bytecode, or the network's configured limit):
   ```java
   @Hex(maxLength = 49_152) // 24 KB in hex chars
   private String data;
   ```
2. **Move filter evaluation before gas consumption** or, better, **enforce a hard cap on `data` length** at the HTTP layer (Spring's `spring.servlet.multipart.max-request-size` / `server.tomcat.max-http-form-post-size`) so oversized payloads are rejected before deserialization.
3. Consider replacing `Strings.CI::contains` with a length-gated check that short-circuits if the data exceeds a configured threshold.

### Proof of Concept
```bash
# Generate a 1 MB hex string (no 0x prefix needed if validator accepts it)
DATA=$(python3 -c "print('ab' * 500000)")

# Flood the endpoint at the rate limit
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>:8545 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x${DATA}\",\"gas\":\"0x16E360\"},\"latest\"],\"id\":1}" &
done
wait
# Observe CPU spike on the mirror node and increased latency/rejection for concurrent legitimate users
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L28-29)
```java
    @Hex
    private String data;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L51-58)
```java
    @Getter
    @RequiredArgsConstructor
    enum FilterType {
        CONTAINS(Strings.CI::contains),
        EQUALS(String::equalsIgnoreCase);

        private final BiPredicate<String, String> predicate;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```
