[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** pinger/mirror_node_client.go (L48-69)
```go
	attempts := max(cfg.mirrorNodeClientMaxRetries + 1, 1)

	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
		if err == nil {
			return network, nil
		}

		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}

		backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
```

**File:** pinger/mirror_node_client.go (L90-92)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
```

**File:** pinger/config.go (L72-95)
```go
	mirrorNodeClientMaxRetriesStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_MAX_RETRIES", "10")
	flag.Func("mirror-node-client-max-retries", "max retries for mirror node client requests", func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		cfg.mirrorNodeClientMaxRetries = v
		return nil
	})
	_ = flag.CommandLine.Set("mirror-node-client-max-retries", mirrorNodeClientMaxRetriesStr)

	mirrorNodeClientBaseBackoffStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_BASE_BACKOFF", "500ms")
	flag.DurationVar(
		&cfg.mirrorNodeClientBaseBackoff,
		"mirror-node-client-base-backoff",
		toDuration(mirrorNodeClientBaseBackoffStr),
		"base backoff for mirror node client retries (e.g. 500ms, 1s)")

	mirrorNodeClientTimeoutStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_TIMEOUT", "10s")
	flag.DurationVar(
		&cfg.mirrorNodeClientTimeout,
		"mirror-node-client-retry-timeout",
		toDuration(mirrorNodeClientTimeoutStr),
		"HTTP timeout for mirror node client requests (e.g. 2s, 10s)")
```

**File:** pinger/sdk_client.go (L17-19)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
```

**File:** pinger/main.go (L28-39)
```go
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
			}
		}
	}()
```

**File:** pinger/main.go (L41-49)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
