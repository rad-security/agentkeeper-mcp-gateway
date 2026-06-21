package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/hostidentity"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/machineid"
)

// ServerInfo describes a connected MCP server for sync registration.
type ServerInfo struct {
	Name      string     `json:"name"`
	Transport string     `json:"transport,omitempty"`
	Tools     []ToolInfo `json:"tools,omitempty"`
}

// DiscoveredServerInfo describes a local MCP server discovered outside the
// gateway config. It is redacted: only key names are sent for env/headers.
type DiscoveredServerInfo struct {
	Name           string   `json:"name"`
	Client         string   `json:"client,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	SourceKind     string   `json:"source_kind,omitempty"`
	SourcePath     string   `json:"source_path,omitempty"`
	SourceHash     string   `json:"source_hash,omitempty"`
	Transport      string   `json:"transport,omitempty"`
	RouteState     string   `json:"route_state,omitempty"`
	Routeability   string   `json:"routeability,omitempty"`
	Routable       bool     `json:"routable,omitempty"`
	GatewayCovered bool     `json:"gateway_covered,omitempty"`
	GatewayName    string   `json:"gateway_name,omitempty"`
	EnvKeys        []string `json:"env_keys,omitempty"`
	HeaderKeys     []string `json:"header_keys,omitempty"`
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
	SensitiveData string `json:"sensitive_data"` // "warn", "block", "monitor"
}

// EvaluateResult holds the server-side detection verdict from /api/v1/mcp/evaluate.
type EvaluateResult struct {
	Verdict     string `json:"verdict"` // "pass", "warn", "block"
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Client handles batch event upload and gateway registration with the AgentKeeper API.
type Client struct {
	apiURL         string
	apiKey         string
	hostname       string
	machineID      string
	mode           string
	gatewayVersion string
	servers        []ServerInfo
	discovered     []DiscoveredServerInfo
	discover       func() []DiscoveredServerInfo
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
	return hostidentity.StableHostname()
}

// NewClient creates a telemetry client.
func NewClient(apiURL, apiKey string, logger *logging.Logger) *Client {
	hostname := StableHostname()
	machineID := machineid.Detect()
	return &Client{
		apiURL:    apiURL,
		apiKey:    apiKey,
		hostname:  hostname,
		machineID: machineID,
		mode:      "audit",
		logger:    logger,
		done:      make(chan struct{}),
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

// SetDiscoveredServers sets a static discovered-server snapshot.
func (c *Client) SetDiscoveredServers(servers []DiscoveredServerInfo) {
	c.discovered = servers
}

// SetDiscoveryProvider sets a callback used on every sync heartbeat. This lets
// the gateway report newly-added local MCP configs without requiring a restart.
func (c *Client) SetDiscoveryProvider(discover func() []DiscoveredServerInfo) {
	c.discover = discover
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
		"hostname":    c.hostname,
		"machine_id":  c.machineID,
		"gateway_id":  c.gatewayID,
		"source":      "agentkeeper-mcp-gateway",
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
		"hostname":           c.hostname,
		"machine_id":         c.machineID,
		"os":                 runtime.GOOS,
		"os_version":         runtime.GOARCH,
		"gateway_version":    c.gatewayVersion,
		"mode":               c.mode,
		"connected_clients":  []string{},
		"connected_servers":  c.servers,
		"discovered_servers": c.discoveredServers(),
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

func (c *Client) discoveredServers() []DiscoveredServerInfo {
	if c.discover != nil {
		return c.discover()
	}
	return c.discovered
}

func (c *Client) flush() {
	if c.logger == nil {
		return
	}
	events := c.logger.FlushBuffer()
	if len(events) == 0 {
		return
	}

	payload := map[string]interface{}{
		"events":     events,
		"hostname":   c.hostname,
		"machine_id": c.machineID,
		"gateway_id": c.gatewayID,
		"source":     "agentkeeper-mcp-gateway",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		c.logger.RequeueFront(events)
		return
	}

	req, err := http.NewRequest("POST", c.apiURL+"/api/v1/mcp/events", bytes.NewReader(data))
	if err != nil {
		c.logger.RequeueFront(events)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.logger.RequeueFront(events)
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		OK       bool   `json:"ok"`
		Inserted int    `json:"inserted"`
		Received *int   `json:"received"`
		Disabled bool   `json:"disabled"`
		Error    string `json:"error"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.logger.RequeueFront(events)
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload error (HTTP %d)\n", resp.StatusCode)
		return
	}
	if decodeErr != nil {
		c.logger.RequeueFront(events)
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload ack invalid: %v\n", decodeErr)
		return
	}
	if result.Disabled {
		c.logger.Info("telemetry upload skipped: connector disabled")
		return
	}
	if !result.OK || result.Error != "" || (result.Received != nil && *result.Received < len(events)) {
		c.logger.RequeueFront(events)
		if result.Error != "" {
			fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload not acknowledged: %s\n", result.Error)
		} else {
			fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload not acknowledged\n")
		}
		return
	}
	received := len(events)
	if result.Received != nil {
		received = *result.Received
	}
	c.logger.Info("telemetry upload acknowledged: sent=%d received=%d inserted=%d", len(events), received, result.Inserted)
}
