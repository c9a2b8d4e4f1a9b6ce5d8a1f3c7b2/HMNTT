### Title
Global Rate Limit Bucket Starvation — Single Unprivileged Client Can Exhaust All Tokens and Block All Other Users

### Summary
The `rateLimitBucket` in `ThrottleConfiguration.java` is a single global Spring singleton with no per-IP or per-client partitioning. Any unauthenticated external caller can burst 500 requests at second-boundary to drain all tokens, then sustain 1 request every 2 ms to match the `refillGreedy` refill rate, holding the bucket at zero and causing every other client to receive HTTP 429 for the entire attack duration.

### Finding Description
**Code path:**

- `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `rateLimitBucket()`, lines 24–32: a single `Bucket` bean is created with `capacity(500)` and `refillGreedy(500, Duration.ofSeconds(1))`. This is a JVM-level singleton — one shared token pool for all incoming clients.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, line 35: default `requestsPerSecond = 500`.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42: `throttle()` calls `rateLimitBucket.tryConsume(1)` with no source-IP context, no per-client bucket, and no fairness mechanism.

**Root cause:** The failed assumption is that 500 req/s is a safe aggregate limit that no single client will fully consume. In reality, because the bucket is global and unauthenticated, a single attacker can claim the entire capacity.

**`refillGreedy` mechanics:** With `capacity=500` and `refillGreedy(500, 1s)`, the bucket starts full and refills at exactly 1 token per 2 ms. An attacker who:
1. Bursts 500 requests at t=0 → bucket reaches 0.
2. Sends exactly 1 request every 2 ms thereafter → consumes each token as soon as it is minted.

…keeps the bucket perpetually at 0. Every concurrent legitimate request hits `tryConsume(1) == false` and receives `ThrottleException("Requests per second rate limit exceeded")` → HTTP 429.

**Why existing checks fail:** There is no per-IP bucket, no connection-level admission control, no IP blocklist, and no authentication requirement anywhere in the throttle path. The `RequestProperties` filter mechanism (`ThrottleManagerImpl.java:44–48`) is only evaluated *after* the global bucket check passes, so it cannot compensate.

### Impact Explanation
A single unprivileged attacker with a commodity internet connection can render the web3 JSON-RPC endpoint completely unavailable to all other users for as long as the attack is sustained. All contract-call and opcode-trace requests are gated through this same bucket. The node continues running but processes zero legitimate traffic, satisfying the "≥30% processing shutdown without brute force" criterion — the attacker needs only 500 req/s, well within reach of a single host.

### Likelihood Explanation
No credentials, API keys, or special network position are required. The attack requires only an HTTP client capable of 500 req/s (achievable with a single `wrk` or `ab` invocation). It is trivially repeatable and can be sustained indefinitely. The attacker receives 429 responses for their own overflow requests but that does not deter the attack — the cost to the attacker is negligible.

### Recommendation
1. **Per-IP rate limiting:** Maintain a `ConcurrentHashMap<String, Bucket>` keyed on client IP (extracted from `X-Forwarded-For` or `RemoteAddr`) and apply a per-client bucket in addition to the global one.
2. **Reduce burst capacity:** Use `refillIntervally` instead of `refillGreedy`, or set `initialTokens(0)` to eliminate the cold-start burst window.
3. **Reverse-proxy enforcement:** Place an nginx/HAProxy rate-limit rule (`limit_req_zone`) in front of the service to enforce per-IP limits before requests reach the JVM.
4. **Connection-level throttling:** Apply Spring's `server.tomcat.max-connections` and `server.tomcat.accept-count` to bound the number of concurrent connections per remote address at the TCP layer.

### Proof of Concept
```bash
# Step 1: Drain the bucket (burst 500 requests)
seq 1 500 | xargs -P 500 -I{} curl -s -o /dev/null \
  -X POST http://<node>:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000167","data":"0x"},"latest"],"id":1}'

# Step 2: Sustain at refill rate (1 req / 2ms) to keep bucket at 0
while true; do
  curl -s -o /dev/null \
    -X POST http://<node>:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000167","data":"0x"},"latest"],"id":1}'
  sleep 0.002
done &

# Step 3: Verify legitimate users are blocked
curl -v -X POST http://<node>:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000167","data":"0x"},"latest"],"id":2}'
# Expected: HTTP 429 Too Many Requests
# Body: {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```