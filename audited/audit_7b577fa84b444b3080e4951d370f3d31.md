### Title
Unauthenticated 5xx Flood via Rosetta Protocol Semantics Triggers False-Positive `RosettaApiErrors` Alert

### Summary
The Rosetta API specification mandates HTTP 500 for all protocol-level errors, including malformed client requests. `MetricsMiddleware` unconditionally records every response's `status_code` label into `requestDurationHistogram`. With no application-level rate limiting deployed by default (`global.middleware: false`), an unprivileged attacker can flood the endpoint with malformed requests, drive the 5xx ratio above the 5% threshold, and continuously fire the `RosettaApiErrors` Prometheus alert, disrupting operator response workflows.

### Finding Description

**Code path — metric recording:**

`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` (lines 76–83) wraps every inbound HTTP request with `middleware.Instrument`, which records the final HTTP status code as the `status_code` label on `requestDurationHistogram`:

```go
func MetricsMiddleware(next http.Handler) http.Handler {
    return middleware.Instrument{
        Duration:         requestDurationHistogram,   // label: status_code
        ...
    }.Wrap(next)
}
``` [1](#0-0) 

The histogram is declared with `status_code` as a label dimension: [2](#0-1) 

**Alert rule:**

`RosettaApiErrors` fires when the 5-minute rate of `status_code=~"^5.."` samples exceeds 5% of all samples:

```yaml
expr: sum(rate(hiero_mirror_rosetta_request_duration_count{...,status_code=~"^5.."}[5m])) by (namespace, pod)
    / sum(rate(hiero_mirror_rosetta_request_duration_count{...}[5m])) by (namespace, pod) > 0.05
for: 1m
``` [3](#0-2) 

**Root cause — Rosetta protocol returns 500 for all errors:**

The `coinbase/rosetta-sdk-go` framework returns HTTP 500 for every Rosetta-level error, including invalid network identifiers, malformed JSON bodies, and unsupported operations. This is mandated by the Rosetta specification. Therefore, any syntactically or semantically invalid request from an unauthenticated client produces a 500 response that is faithfully recorded by `MetricsMiddleware`.

**Failed assumption — rate limiting is disabled by default:**

The Traefik middleware chain (including `inFlightReq`, `rateLimit`, and `circuitBreaker`) is only deployed when `global.middleware: true`. The default value is `false`: [4](#0-3) 

The middleware template enforces this gate:

```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
``` [5](#0-4) 

In a default deployment, no rate limiting exists between the public internet and the Rosetta backend.

**Additional amplification when middleware IS enabled:**

When `global.middleware: true`, the `retry: attempts: 3` setting causes Traefik to replay each failing request up to 3 additional times, multiplying the 5xx count in `requestDurationHistogram` by up to 4× per attacker request: [6](#0-5) 

### Impact Explanation

An attacker sustaining a 5xx rate above 5% of total traffic for 60 seconds triggers a `severity: critical` alert. In low-traffic environments (e.g., testnet or staging), even a handful of malformed requests per second can exceed the threshold. Operators receive continuous false-positive pages, leading to alert fatigue, delayed response to genuine incidents, and potential suppression of real alerts.

### Likelihood Explanation

No credentials, API keys, or network privileges are required. The Rosetta endpoint is publicly reachable (ingress enabled by default). Sending malformed POST bodies (e.g., `{}` or wrong `network_identifier`) is trivial and requires no knowledge of the internal system. The attack is repeatable, cheap, and fully automated with a single `curl` loop or any HTTP load tool.

### Recommendation

1. **Enable rate limiting by default**: Set `global.middleware: true` in the default `values.yaml`, or move the `inFlightReq`/`rateLimit` middleware to be unconditionally deployed.
2. **Raise or adjust the alert threshold**: The 5% threshold over 1 minute is too sensitive for a public API that returns 500 for client errors. Consider filtering out known client-induced 500s or raising the threshold.
3. **Separate client vs. server 5xx**: Instrument Rosetta error codes from the response body to distinguish client-caused 500s (Rosetta error codes) from genuine server failures, and exclude client-caused ones from the alert expression.
4. **Remove the `retry` amplification for 5xx**: Configure Traefik's retry middleware to not retry on 500 responses that originate from client errors.

### Proof of Concept

```bash
# No authentication required. Send malformed Rosetta requests at low rate.
# In a low-traffic environment, ~1 req/s is sufficient to exceed 5% of total traffic.

while true; do
  curl -s -o /dev/null -X POST https://<rosetta-host>/network/status \
    -H "Content-Type: application/json" \
    -d '{"network_identifier": {"blockchain": "INVALID", "network": "INVALID"}}'
  sleep 0.1
done

# After ~60 seconds, observe Prometheus:
# sum(rate(hiero_mirror_rosetta_request_duration_count{status_code=~"^5.."}[5m]))
# / sum(rate(hiero_mirror_rosetta_request_duration_count[5m])) > 0.05
# → RosettaApiErrors alert fires with severity: critical
```

### Citations

**File:** rosetta/app/middleware/metrics.go (L28-32)
```go
	requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_request_duration",
		Buckets: []float64{.1, .25, .5, 1, 2.5, 5},
		Help:    "Time (in seconds) spent serving HTTP requests.",
	}, []string{"method", "route", "status_code", "ws"})
```

**File:** rosetta/app/middleware/metrics.go (L76-83)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L161-163)
```yaml
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L191-200)
```yaml
  RosettaApiErrors:
    annotations:
      description: "Rosetta API 5xx error rate for {{ $labels.namespace }}/{{ $labels.pod }} is {{ $value | humanizePercentage }}"
      summary: "Mirror Rosetta API error rate exceeds 5%"
    enabled: true
    expr: sum(rate(hiero_mirror_rosetta_request_duration_count{application="rosetta",status_code=~"^5.."}[5m])) by (namespace, pod) / sum(rate(hiero_mirror_rosetta_request_duration_count{application="rosetta"}[5m])) by (namespace, pod) > 0.05
    for: 1m
    labels:
      application: rosetta
      severity: critical
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```
