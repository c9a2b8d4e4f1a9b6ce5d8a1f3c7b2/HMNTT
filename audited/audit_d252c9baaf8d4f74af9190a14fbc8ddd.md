### Title
Missing HTTP 429 Retry in `shouldRetry()` Causes Monitoring Blackout Under Rate-Limiting

### Summary
The `shouldRetry()` method in `RestSubscriber.java` only retries on `HTTP 404 (Not Found)`, explicitly excluding `HTTP 429 (Too Many Requests)`. When the mirror node REST API rate-limits the monitor, all in-flight transaction lookups are immediately dropped without retry, and the error is swallowed via `onErrorResume(e -> Mono.empty())`. An unprivileged external attacker who can flood the public REST API endpoint can trigger this condition, causing the monitor to silently lose transaction confirmations for the duration of the rate-limit event.

### Finding Description

**Exact code location:**

`monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriber.java`, lines 144–147 (`shouldRetry`) and lines 91–115 (`clientSubscribe`).

The retry filter is wired at line 95:
```java
.filter(this::shouldRetry)
```

The predicate at lines 144–147 only passes `404`:
```java
protected boolean shouldRetry(Throwable t) {
    return t instanceof WebClientResponseException webClientResponseException
            && webClientResponseException.getStatusCode() == HttpStatus.NOT_FOUND;
}
```

When the REST API returns `429`, `shouldRetry()` returns `false`. Reactor's `RetryBackoffSpec` treats a `false` filter result as a non-retryable error and immediately propagates a `RetryExhaustedException`. The error path at lines 114–115 then records the error counter and swallows the exception:
```java
.doOnError(t -> subscription.onError(t))
.onErrorResume(e -> Mono.empty())
```

The transaction lookup is permanently abandoned — no retry, no re-queue, no alert beyond an incremented error counter.

**Root cause / failed assumption:** The design assumes only `404` requires retry (transaction not yet indexed). It fails to account for `429`, which is a transient, server-side throttle that is explicitly designed to be retried after a backoff — exactly what the already-configured `RetryBackoffSpec` with `minBackoff`/`maxBackoff` is built to handle.

**Why existing checks are insufficient:**
- `onErrorResume(e -> Mono.empty())` at line 115 ensures the stream continues but the individual transaction is permanently lost.
- `subscription.onError(t)` at line 114 only increments an error counter; it does not re-queue or alert operators in real time.
- The `RetryBackoffSpec` has backoff parameters configured but they are never applied to `429` because the filter rejects it before any retry attempt.
- The test suite (`RestSubscriberTest.java`, line 347 `nonRetryableError`) confirms that any non-404 HTTP error (including `500`) is treated identically — no retry, error counted, transaction dropped — validating this behavior for `429` as well.

### Impact Explanation
During a rate-limit event, every transaction the monitor attempts to verify receives a `429` response. None are retried. The monitor's `count` metric stalls and its `errors` map accumulates `429` entries, but no transaction is ever confirmed as received. This constitutes a complete monitoring blackout: the monitor cannot detect missing or delayed transactions, defeating its core purpose. If an attacker deliberately induces rate-limiting to coincide with a network anomaly or attack, the monitoring system will fail to raise any alert about the anomaly.

### Likelihood Explanation
The mirror node REST API is a public endpoint. Any unauthenticated user can send high-volume requests to it. If the API enforces per-IP or global rate limits (standard practice), an attacker co-located on the same network segment as the monitor, or simply flooding the same public endpoint, can exhaust the monitor's request quota. No credentials, no special access, and no insider knowledge are required. The attack is repeatable and can be sustained indefinitely at low cost.

### Recommendation
Add `HttpStatus.TOO_MANY_REQUESTS` (429) to the `shouldRetry()` predicate:

```java
protected boolean shouldRetry(Throwable t) {
    if (!(t instanceof WebClientResponseException e)) return false;
    HttpStatusCode status = e.getStatusCode();
    return status == HttpStatus.NOT_FOUND
        || status == HttpStatus.TOO_MANY_REQUESTS;
}
```

Additionally, for `429` responses, honour the `Retry-After` or `x-retry-in` response headers (as the JS monitoring utility in `rest/monitoring/utils.js` already does at lines 44–53) to set the backoff duration dynamically rather than relying solely on the configured `maxBackoff`.

### Proof of Concept

1. Deploy the monitor against a mirror node REST API that enforces rate limits.
2. From any external host, flood `GET /api/v1/transactions/{anyId}` at a rate exceeding the API's per-IP or global threshold.
3. Observe that the monitor's REST API client begins receiving `429` responses.
4. Confirm via the monitor's `/api/v1/subscriber` endpoint that `errors` accumulates `{"429": N}` while `count` stops incrementing — no transactions are confirmed.
5. Stop the flood; the monitor resumes normal operation, but all transactions submitted during the flood window are permanently unverified. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriber.java (L91-99)
```java
        RetryBackoffSpec retrySpec = Retry.backoff(
                        properties.getRetry().getMaxAttempts(),
                        properties.getRetry().getMinBackoff())
                .maxBackoff(properties.getRetry().getMaxBackoff())
                .filter(this::shouldRetry)
                .doBeforeRetry(r -> log.debug(
                        "Retry attempt #{} after failure: {}",
                        r.totalRetries() + 1,
                        r.failure().getMessage()));
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriber.java (L113-115)
```java
                        .retryWhen(retrySpec)
                        .doOnError(t -> subscription.onError(t))
                        .onErrorResume(e -> Mono.empty())
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriber.java (L144-147)
```java
    protected boolean shouldRetry(Throwable t) {
        return t instanceof WebClientResponseException webClientResponseException
                && webClientResponseException.getStatusCode() == HttpStatus.NOT_FOUND;
    }
```

**File:** monitor/src/test/java/org/hiero/mirror/monitor/subscribe/rest/RestSubscriberTest.java (L347-363)
```java
    void nonRetryableError() {
        Mockito.when(exchangeFunction.exchange(Mockito.any(ClientRequest.class)))
                .thenReturn(response(HttpStatus.INTERNAL_SERVER_ERROR));

        StepVerifier.withVirtualTime(() -> restSubscriber.subscribe())
                .then(() -> restSubscriber.onPublish(publishResponse()))
                .thenAwait(Duration.ofSeconds(10L))
                .expectNextCount(0L)
                .thenCancel()
                .verify(Duration.ofSeconds(1L));

        verify(exchangeFunction).exchange(Mockito.isA(ClientRequest.class));
        assertThat(restSubscriber.getSubscriptions().blockFirst())
                .isNotNull()
                .returns(0L, Scenario::getCount)
                .returns(Map.of("500", 1), Scenario::getErrors);
    }
```

**File:** rest/monitoring/utils.js (L44-53)
```javascript
const getBackoff = (retryAfter, xRetryIn) => {
  const backoffSeconds = Number.parseInt(retryAfter);
  let backoffMillis = Number.isNaN(backoffSeconds) ? 0 : backoffSeconds * 1000;
  if (backoffMillis === 0) {
    backoffMillis = parseDuration(xRetryIn || '0ms');
    backoffMillis = Math.ceil(backoffMillis);
  }

  return Math.max(config.retry.minBackoff, backoffMillis);
};
```
