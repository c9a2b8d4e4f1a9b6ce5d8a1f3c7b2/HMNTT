### Title
Log Injection via Unsanitized Exception Message and URI in LoggingFilter

### Summary
The `LoggingFilter` in `graphql/src/main/java/org/hiero/mirror/graphql/config/LoggingFilter.java` logs the raw exception message and raw request URI without stripping newline characters (`\n`, `\r`). An unprivileged external user can craft a GraphQL request whose processing produces an exception message containing attacker-controlled newlines, injecting arbitrary fake log lines into the application log stream. No authentication is required.

### Finding Description
**Exact code path:**

`doFilterInternal()` (line 27–38) catches any exception and passes it to `logRequest()` (line 40–60), which calls `getMessage()` (line 62–72):

```java
// LoggingFilter.java line 62-72
private String getMessage(HttpServletRequest request, Exception e) {
    if (e != null) {
        return e.getMessage();          // ← raw, unsanitized
    }
    if (request.getAttribute(ERROR_EXCEPTION_ATTRIBUTE) instanceof Exception ex) {
        return ex.getMessage();         // ← raw, unsanitized
    }
    return SUCCESS;
}
```

The returned `message` is placed directly into the log params array at line 51:

```java
var params = new Object[] {request.getRemoteAddr(), request.getMethod(), uri, elapsed, status, message};
```

and emitted via SLF4J at lines 54–58 with format `"{} {} {} in {} ms: {} {}"`. SLF4J/Logback does **not** strip embedded newlines from `{}` arguments; they are written verbatim to the log sink.

**Root cause:** Neither `getMessage()` nor `logRequest()` applies any newline/CRLF stripping. The only sanitization utility in the codebase (`DomainUtils.sanitize()`, line 239–241) only replaces null bytes (`\0`), not `\n`/`\r`. No Logback configuration was found that would encode or strip control characters. The `web3` module's `LoggingFilter` calls `StringUtils.deleteWhitespace()` on the request *body* content, but the graphql module's `LoggingFilter` does not even do that.

**URI vector (secondary):** Line 41 `String uri = request.getRequestURI()` is also logged raw. Tomcat's default configuration rejects `%0a`/`%0d` in the URI path (returning 400 before the filter runs), so this vector is largely mitigated by the container. The exception-message vector is not mitigated by any layer.

**Exception-message vector (primary):** GraphQL-Java includes the offending input token in many parse/validation error messages (e.g., `"Invalid syntax with offending token '<attacker string>' at line 1 column N"`). A POST body containing a string literal with embedded `\n` characters will produce an exception whose `.getMessage()` contains those newlines verbatim.

### Impact Explanation
An attacker can inject arbitrary text as additional log lines, for example:

```
INFO  ... 127.0.0.1 POST /graphql in 3 ms: 400 Invalid syntax ... 'foo
INFO  ... 10.0.0.1 GET /admin/secret in 0 ms: 200 Success
```

This allows: (1) forging successful-access or privileged-path entries to mislead SIEM/SOC analysts; (2) hiding real attack traffic by flooding logs with noise; (3) corrupting structured log parsers (e.g., JSON log pipelines) that split on newlines. Severity is **Medium** — no direct data exfiltration, but meaningful damage to log integrity and security monitoring.

### Likelihood Explanation
Preconditions: none beyond network access to the GraphQL endpoint (unauthenticated). The GraphQL endpoint is publicly reachable by design. Crafting a POST body with embedded newlines in a string literal is trivial. The attack is repeatable at will and leaves no trace distinguishable from legitimate traffic in the HTTP layer.

### Recommendation
In `getMessage()`, strip or encode CR/LF before returning:

```java
private String getMessage(HttpServletRequest request, Exception e) {
    if (e != null) {
        return sanitizeForLog(e.getMessage());
    }
    if (request.getAttribute(ERROR_EXCEPTION_ATTRIBUTE) instanceof Exception ex) {
        return sanitizeForLog(ex.getMessage());
    }
    return SUCCESS;
}

private static String sanitizeForLog(String s) {
    return s == null ? null : s.replace('\n', '_').replace('\r', '_');
}
```

Apply the same sanitization to `uri` in `logRequest()`. Alternatively, configure Logback with a `replace` conversion pattern or a `PatternLayoutEncoder` that encodes control characters globally, which would protect all log statements in the application.

### Proof of Concept

```bash
# Send a GraphQL request whose string literal contains an embedded newline
curl -s -X POST http://<host>/graphql \
  -H 'Content-Type: application/json' \
  -d $'{"query":"{ __typename @foo(x: \\"bar\\nINFO  10.0.0.1 GET /admin in 0 ms: 200 Success\\") }"}'
```

Expected log output (two apparent log lines from one request):

```
INFO  o.h.m.g.config.LoggingFilter - 127.0.0.1 POST /graphql in 4 ms: 400 Invalid syntax ... 'bar
INFO  o.h.m.g.config.LoggingFilter - 10.0.0.1 GET /admin in 0 ms: 200 Success'
```

The second line is entirely attacker-controlled and indistinguishable from a genuine log entry.