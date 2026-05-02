### Title
Mirror-Node-Poisoned Network Map Causes Permanent Transfer Denial-of-Service in Pinger

### Summary
When `network=other`, `newClient()` builds the Hiero SDK network map by fetching node endpoints from an unauthenticated, plain-HTTP mirror REST URL. An attacker who can intercept or spoof that HTTP response can inject a single node entry pointing to a malicious gRPC server. Because the network map is built once at startup and never refreshed, every subsequent `submitWithRetry` tick exhausts all retries against the attacker-controlled server and permanently fails to transfer funds.

### Finding Description

**Code path:**

`pinger/sdk_client.go` `newClient()` (lines 17–22) calls `buildNetworkFromMirrorNodes()` exactly once at process startup: [1](#0-0) 

`pinger/mirror_node_client.go` `fetchMirrorNodeNetwork()` (lines 74–131) issues a plain `http.GET` with no TLS certificate pinning, no HMAC/signature verification, and no allowlist of trusted node addresses. The only guard is that the returned `network` map must be non-empty (line 127): [2](#0-1) 

A single node entry with a syntactically valid `node_account_id` (e.g. `"0.0.3"`) and one `service_endpoint` pointing to an attacker-controlled host satisfies every check and is inserted into the map: [3](#0-2) 

The resulting `netmap` is passed directly to `hiero.ClientForNetwork(netmap)` and the client is never rebuilt: [4](#0-3) 

`pinger/transfer.go` `submitWithRetry()` retries up to `maxRetries+1` times (default 11). With only one node in the SDK client, every `Execute(client)` call goes to the attacker's gRPC server. When that server returns `INVALID_NODE_ACCOUNT`, the SDK has no alternative node to route to, so all attempts fail: [5](#0-4) 

On the next ticker tick the same client is reused, the same single poisoned node is tried, and the same exhaustion occurs — indefinitely.

**Root cause:** Blind trust in an unauthenticated HTTP response to construct a permanent, never-refreshed network map, combined with no minimum-node-count or node-identity validation.

### Impact Explanation
The pinger's sole purpose is to submit periodic crypto-transfers as a liveness/health signal. Permanent failure of `submitWithRetry` on every tick means the pinger silently stops producing successful transfers. Any monitoring or alerting system that depends on those transfers will either raise false alarms or, if the pinger's own error logging is suppressed, produce false negatives about network health. The operator's funds are not directly stolen, but the health-monitoring capability is completely neutralised for the lifetime of the process.

### Likelihood Explanation
The default mirror REST URL shown in the config is `http://mirror-rest:5551` — plain HTTP: [6](#0-5) 

In a Kubernetes cluster, an attacker with access to the same network namespace (e.g. a compromised sidecar, ARP/DNS spoofing within the pod network, or a rogue DNS resolver) can intercept this unencrypted HTTP request at pinger startup. The attack is a single-shot, one-time poisoning at process start; no ongoing access is required after the initial response is forged. The attacker needs no credentials and no knowledge of the operator key.

### Recommendation
1. **Enforce HTTPS** for `cfg.mirrorRest` and validate the server certificate; reject plain-HTTP URLs at config load time.
2. **Validate returned node account IDs** against a locally configured allowlist of known-good node account IDs before inserting them into the network map.
3. **Enforce a minimum node count** (e.g. ≥ 3) before accepting the response, making single-node poisoning impossible.
4. **Periodically refresh** the network map (e.g. on each tick or on consecutive failures) so a poisoned startup state can self-heal.
5. **Detect and circuit-break** on `INVALID_NODE_ACCOUNT` responses: if all nodes in the map return this status, treat it as a configuration error and restart/re-fetch rather than silently looping.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plain HTTP).
- Attacker can intercept or spoof HTTP responses from `mirror-rest:5551` (e.g. via DNS poisoning or ARP spoofing within the cluster network).

**Steps:**

1. Attacker stands up a malicious gRPC server on `attacker-host:50211` that accepts any `CryptoTransfer` and returns a receipt with status `INVALID_NODE_ACCOUNT`.

2. When the pinger starts and calls `GET http://mirror-rest:5551/api/v1/network/nodes`, the attacker intercepts the request and returns:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{"ip_address_v4": "attacker-host", "port": 50211}]
     }],
     "links": {"next": null}
   }
   ```

3. `fetchMirrorNodeNetwork` accepts this (one valid entry, `len(network)==1 > 0`), returns `{"attacker-host:50211": AccountID{0,0,3}}`.

4. `hiero.ClientForNetwork(netmap)` creates a client with only this one node.

5. On every ticker tick, `submitWithRetry` calls `Execute(client)`, which sends the transaction to `attacker-host:50211`. The server returns `INVALID_NODE_ACCOUNT`. All 11 attempts fail. The function returns `"all attempts failed: ..."`.

6. The next tick repeats step 5. This continues for the entire lifetime of the pinger process — no successful transfer is ever submitted.

### Citations

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/mirror_node_client.go (L84-129)
```go
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}

	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}

	network := make(map[string]hiero.AccountID)

	for _, n := range payload.Nodes {
		if n.NodeAccountID == "" {
			continue
		}

		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
		}

		// Use service_endpoints for node gRPC (what the SDK wants)
		for _, ep := range n.ServiceEndpoints {
			host := strings.TrimSpace(ep.DomainName)
			if host == "" {
				host = strings.TrimSpace(ep.IPAddressV4)
			}
			if host == "" || ep.Port == 0 {
				continue
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
		}
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/transfer.go (L21-59)
```go
	attempts := cfg.maxRetries + 1

	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := time.Now()
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
		if err == nil {
			receipt, rerr := resp.GetReceipt(client)
			if rerr == nil {
				log.Printf("transfer success: status=%s txID=%s elapsed=%s",
					receipt.Status.String(), resp.TransactionID.String(), time.Since(start))
				return nil
			}
			err = rerr
		}

		lastErr = err
		log.Printf("attempt %d/%d failed: %v", i, attempts, err)

		if i < attempts {
			sleep := backoff(cfg.baseBackoff, i)
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	return fmt.Errorf("all attempts failed: %w", lastErr)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
