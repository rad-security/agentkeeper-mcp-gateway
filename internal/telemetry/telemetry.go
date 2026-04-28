package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
)

// ServerInfo describes a connected MCP server for sync registration.
type ServerInfo struct {
	Name      string     `json:"name"`
	Transport string     `json:"transport,omitempty"`
	Tools     []ToolInfo `json:"tools,omitempty"`
}

// ToolInfo describes a tool exposed by an MCP server.
type ToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// SyncPolicy holds the org policy returned by /api/v1/mcp/sync.
type SyncPolicy struct {
	Mode           string              `json:"mode"`
	Detection      DetectionConfig     `json:"detection"`
	BlockedServers []string            `json:"blocked_servers"`
	BlockedTools   map[string][]string `json:"blocked_tools"`
	CustomKeywords []string            `json:"custom_keywords"`
	SecurityLevel  string              `json:"security_level"`
}

// DetectionConfig controls detection behavior from the dashboard.
type DetectionConfig struct {
	Threat        string `json:"threat"`         // "warn", "block", "monitor"
	SensitiveData string `json:"sensitive_data"`  // "warn", "block", "monitor"
}

// EvaluateResult holds the server-side detection verdict from /api/v1/mcp/evaluate.
type EvaluateResult struct {
	Verdict     string `json:"verdict"`      // "pass", "warn", "block"
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Client handles batch event upload and gateway registration with the AgentKeeper API.
type Client struct {
	apiURL         string
	apiKey         string
	hostname       string
	mode           string
	gatewayVersion string
	servers        []ServerInfo
	gatewayID      string
	logger         *logging.Logger
	done           chan struct{}
	cachedPolicy   SyncPolicy
	policyMu       sync.RWMutex
}

// StableHostname returns a stable machine hostname. On macOS, os.Hostname()
// returns the network-assigned name which changes per Wi-Fi network. We use
// scutil --get LocalHostName instead, falling back to os.Hostname().
func StableHostname() string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("scutil", "--get", "LocalHostName").Output()
		if err == nil {
			if h := strings.TrimSpace(string(out)); h != "" {
				return h
			}
		}
	}
	h, _ := os.Hostname()
	return h
}

// NewClient creates a telemetry client.
func NewClient(apiURL, apiKey string, logger *logging.Logger) *Client {
	hostname := StableHostname()
	return &Client{
		apiURL:   apiURL,
		apiKey:   apiKey,
		hostname: hostname,
		mode:     "audit",
		logger:   logger,
		done:     make(chan struct{}),
	}
}

// SetMode sets the gateway mode for sync registration.
func (c *Client) SetMode(mode string) {
	c.mode = mode
}

// SetVersion sets the gateway version for sync registration.
func (c *Client) SetVersion(version string) {
	c.gatewayVersion = version
}

// SetServers sets the connected servers for sync registration.
func (c *Client) SetServers(servers []ServerInfo) {
	c.servers = servers
}

// Start registers the gateway and begins background flush/heartbeat loops.
func (c *Client) Start() {
	// Register immediately on startup
	c.sync()

	go func() {
		flushTicker := time.NewTicker(5 * time.Second)
		syncTicker := time.NewTicker(30 * time.Second)
		defer flushTicker.Stop()
		defer syncTicker.Stop()
		for {
			select {
			case <-flushTicker.C:
				c.flush()
			case <-syncTicker.C:
				c.sync()
			case <-c.done:
				c.flush() // Final flush
				return
			}
		}
	}()
}

// Stop signals the flush loop to stop.
func (c *Client) Stop() {
	close(c.done)
}

// Policy returns the cached dashboard policy. Returns zero-value SyncPolicy
// if no policy has been synced (local-only mode or first boot).
func (c *Client) Policy() SyncPolicy {
	c.policyMu.RLock()
	defer c.policyMu.RUnlock()
	return c.cachedPolicy
}

// Evaluate sends a tool call to the server-side detection engine.
// Returns nil on timeout, network error, or non-200 response (caller
// should fall back to embedded detection).
func (c *Client) Evaluate(serverName, toolName string, params map[string]interface{}) *EvaluateResult {
	payload := map[string]interface{}{
		"server_name": serverName,
		"tool_name":   toolName,
		"params":      params,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	req, err := http.NewRequest("POST", c.apiURL+"/api/v1/mcp/evaluate", bytes.NewReader(data))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Warn("connected detection failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var result EvaluateResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	return &result
}

// sync registers or heartbeats the gateway via /api/v1/mcp/sync.
func (c *Client) sync() {
	payload := map[string]interface{}{
		"hostname":          c.hostname,
		"os":                runtime.GOOS,
		"os_version":        runtime.GOARCH,
		"gateway_version":   c.gatewayVersion,
		"mode":              c.mode,
		"connected_clients": []string{},
		"connected_servers": c.servers,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", c.apiURL+"/api/v1/mcp/sync", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] sync failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		OK        bool       `json:"ok"`
		GatewayID string     `json:"gateway_id"`
		Policy    SyncPolicy `json:"policy"`
		Error     string     `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if result.GatewayID != "" {
			c.gatewayID = result.GatewayID
		}
		if result.OK {
			c.policyMu.Lock()
			c.cachedPolicy = result.Policy
			c.policyMu.Unlock()
		}
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "[agentkeeper] sync error (HTTP %d): %s\n", resp.StatusCode, result.Error)
	}
}

func (c *Client) flush() {
	events := c.logger.FlushBuffer()
	if len(events) == 0 {
		return
	}

	payload := map[string]interface{}{
		"events":   events,
		"hostname": c.hostname,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", c.apiURL+"/api/v1/mcp/events", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload failed: %v\n", err)
		return
	}
	resp.Body.Close()
}
