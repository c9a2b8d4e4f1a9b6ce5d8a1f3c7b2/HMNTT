### Title
Unbounded Header Value in `getClientIpAddress` Causes Log I/O Amplification via `fmt.Sprintf`

### Summary
`getClientIpAddress` in `rosetta/app/middleware/trace.go` reads `X-Real-IP` and `X-Forwarded-For` headers with no length validation. The raw, potentially megabyte-sized value is passed directly into `fmt.Sprintf` and then `log.Info`, causing proportional heap allocation and stdout I/O per request. Because the `http.Server` in `rosetta/main.go` sets no `MaxHeaderBytes`, Go's default 1 MiB header limit applies, allowing any unauthenticated caller to amplify per-request server work by up to ~20,000x compared to a normal log line.

### Finding Description

**Code path:**

- `rosetta/main.go` lines 220–227: `http.Server` is constructed with timeout fields but **no `MaxHeaderBytes`**, leaving Go's default of 1,048,576 bytes in effect.
- `rosetta/app/middleware/trace.go` lines 63–74 (`getClientIpAddress`): reads `r.Header.Get(xRealIpHeader)` and, if empty, `r.Header.Get(xForwardedForHeader)`. The only guard is `len(ipAddress) == 0` — there is no upper-bound check.
- Line 52: `fmt.Sprintf("%s %s %s (%d) in %s", clientIpAddress, ...)` — allocates a new string whose size is dominated by `clientIpAddress`.
- Lines 55–59: the formatted string is passed to `log.Info` / `log.Debug`, which serialises and writes it to stdout.

**Root cause:** The code assumes IP header values are short (≤45 bytes for IPv6). No `net.ParseIP` validation, no `len` upper-bound, and no server-level `MaxHeaderBytes` override exist to enforce this assumption.

**Why existing checks fail:** The sole check `if len(ipAddress) == 0` only handles the absent-header case; it does nothing to bound a present but oversized value.

### Impact Explanation

A normal access-log line is ~60–80 bytes. With a 1 MiB `X-Real-IP` value, each request forces:
- ~1 MiB heap allocation in `fmt.Sprintf` (plus GC pressure).
- ~1 MiB write to stdout by `log.Info`.

At 10 requests/second this produces ~10 MiB/s of log I/O and ~10 MiB/s of short-lived heap churn — easily exceeding a 30% increase in CPU and I/O on a lightly or moderately loaded node. The Rosetta API is a public-facing HTTP service with no authentication on most endpoints (e.g., `/network/list`), so the attack surface is fully exposed.

### Likelihood Explanation

- **No privileges required.** Any network-reachable client can set arbitrary HTTP headers.
- **No brute force required.** A single connection sending ~10 req/s with 1 MiB headers is sufficient.
- **Trivially repeatable** with `curl`, `ab`, or any HTTP client.
- The Rosetta spec explicitly expects public, unauthenticated access, so no firewall or auth layer is assumed to block this.

### Recommendation

1. **Validate header length in `getClientIpAddress`** — truncate or reject values longer than 45 characters (max IPv6 length):
   ```go
   const maxIPLength = 45
   if len(ipAddress) > maxIPLength {
       ipAddress = r.RemoteAddr // fall back to trusted source
   }
   ```
2. **Set `MaxHeaderBytes` on the server** in `rosetta/main.go`:
   ```go
   httpServer := &http.Server{
       MaxHeaderBytes: 8 << 10, // 8 KiB
       ...
   }
   ```
3. **Optionally validate with `net.ParseIP`** to ensure the value is a syntactically valid IP address before using it in the log message.

### Proof of Concept

```bash
# Generate a 1 MiB X-Real-IP header value
PAYLOAD=$(python3 -c "print('A' * 1048000)")

# Send 20 requests/second to the public /network/list endpoint
for i in $(seq 1 200); do
  curl -s -o /dev/null -X POST http://<rosetta-host>:8082/network/list \
    -H "Content-Type: application/json" \
    -H "X-Real-IP: $PAYLOAD" \
    -d '{"metadata":{}}' &
done
wait
```

**Expected result:** Each request causes `log.Info` to write ~1 MiB to stdout. Monitor with `iostat` or `top` — stdout I/O and heap GC frequency increase proportionally, demonstrating >30% resource consumption growth relative to the same request rate without the oversized header.