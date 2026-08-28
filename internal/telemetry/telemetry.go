package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/hostidentity"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/machineid"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/runtimebroker"
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
	Verdict             string `json:"verdict"` // "pass", "warn", "block"
	DecisionID          string `json:"decision_id"`
	PolicyDecision      string `json:"policy_decision"`
	EvaluationStatus    string `json:"evaluation_status"`
	RequiredDisposition string `json:"required_disposition"`
	PatternName         string `json:"pattern_name"`
	Severity            string `json:"severity"`
	Description         string `json:"description"`
}

// Client handles batch event upload and gateway registration with the AgentKeeper API.
type Client struct {
	apiURL           string
	apiKey           string
	runtimeSocket    string
	hostname         string
	machineID        string
	mode             string
	modeRevision     int64
	modeMu           sync.RWMutex
	modeChange       func(mode string, revision int64)
	gatewayVersion   string
	servers          []ServerInfo
	discovered       []DiscoveredServerInfo
	discover         func() []DiscoveredServerInfo
	gatewayID        string
	logger           *logging.Logger
	done             chan struct{}
	cachedPolicy     SyncPolicy
	policyMu         sync.RWMutex
	receiptStore     *receipt.Store
	clientName       string
	configSourceHash string
	routeRevision    string
}

// NewRuntimeClient uses the local machine broker for all connected telemetry.
// The gateway never receives or stores the machine device credential.
func NewRuntimeClient(socketPath string, logger *logging.Logger) *Client {
	client := NewClient("", "", logger)
	client.runtimeSocket = socketPath
	return client
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
	c.modeMu.Lock()
	defer c.modeMu.Unlock()
	c.mode = mode
}

// SetModeChangeHandler applies a control-plane assignment to the live proxy.
// The handler is invoked only for an explicit valid Observe/Enforce assignment.
func (c *Client) SetModeChangeHandler(handler func(mode string, revision int64)) {
	c.modeMu.Lock()
	defer c.modeMu.Unlock()
	c.modeChange = handler
}

func (c *Client) currentMode() (string, int64) {
	c.modeMu.RLock()
	defer c.modeMu.RUnlock()
	return c.mode, c.modeRevision
}

func (c *Client) applyAssignedMode(mode string, revision int64) {
	if mode != "observe" && mode != "enforce" || revision <= 0 {
		return
	}
	c.modeMu.Lock()
	handler := c.modeChange
	if mode == "observe" {
		c.mode = "audit"
	} else {
		c.mode = "enforce"
	}
	c.modeRevision = revision
	c.modeMu.Unlock()
	if handler != nil {
		handler(mode, revision)
	}
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

func (c *Client) SetReceiptStore(store *receipt.Store) {
	c.receiptStore = store
}

func (c *Client) SetRouteContext(clientName, configSourceHash, routeRevision string) {
	c.clientName = strings.TrimSpace(clientName)
	c.configSourceHash = strings.TrimSpace(configSourceHash)
	c.routeRevision = strings.TrimSpace(routeRevision)
}

func (c *Client) RouteContext() (clientName, configSourceHash, routeRevision string) {
	return c.clientName, c.configSourceHash, c.routeRevision
}

func (c *Client) RecordReceipt(input receipt.Input) {
	if c.receiptStore == nil {
		return
	}
	if _, err := c.receiptStore.Enqueue(input); err != nil && c.logger != nil {
		c.logger.Warn("could not persist signed application receipt: %v", err)
	}
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
				c.flushReceipts()
			case <-syncTicker.C:
				c.sync()
			case <-c.done:
				c.flush() // Final flush
				c.flushReceipts()
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
func (c *Client) Evaluate(serverName, toolName string, params map[string]interface{}, callID, attemptID string) *EvaluateResult {
	currentMode, _ := c.currentMode()
	payload := map[string]interface{}{
		"server_name":    serverName,
		"tool_name":      toolName,
		"params":         params,
		"hostname":       c.hostname,
		"machine_id":     c.machineID,
		"gateway_id":     c.gatewayID,
		"source":         "agentkeeper-mcp-gateway",
		"call_id":        callID,
		"attempt_id":     attemptID,
		"effective_mode": modeLabel(currentMode),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	var result EvaluateResult
	endpoint := "/api/v1/mcp/evaluate"
	operation := "evaluate"
	if c.receiptStore != nil {
		endpoint = "/api/v2/mcp/evaluate"
		operation = "evaluate_v2"
	}
	status, err := c.postJSON(operation, endpoint, data, &result)
	if endpoint != "/api/v1/mcp/evaluate" && shouldUseLegacyEvaluate(err, status) {
		status, err = c.postJSON("evaluate", "/api/v1/mcp/evaluate", data, &result)
	}
	if err != nil || status != http.StatusOK {
		if err != nil && c.logger != nil {
			c.logger.Warn("connected detection failed: %v", err)
		}
		return nil
	}

	return &result
}

func shouldUseLegacyEvaluate(err error, status int) bool {
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		return true
	}
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unsupported operation") || strings.Contains(message, "unknown operation")
}

// sync registers or heartbeats the gateway via /api/v1/mcp/sync.
func (c *Client) sync() {
	if c.receiptStore != nil {
		c.syncV2()
	}
	currentMode, _ := c.currentMode()
	payload := map[string]interface{}{
		"hostname":           c.hostname,
		"machine_id":         c.machineID,
		"os":                 runtime.GOOS,
		"os_version":         runtime.GOARCH,
		"gateway_version":    c.gatewayVersion,
		"mode":               currentMode,
		"connected_clients":  nonEmptyStrings(c.clientName),
		"connected_servers":  c.servers,
		"discovered_servers": c.discoveredServers(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	var result struct {
		OK        bool       `json:"ok"`
		GatewayID string     `json:"gateway_id"`
		Policy    SyncPolicy `json:"policy"`
		Error     string     `json:"error"`
	}
	status, err := c.postJSON("sync", "/api/v1/mcp/sync", data, &result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] sync failed: %v\n", err)
		return
	}
	if err == nil {
		if result.GatewayID != "" {
			c.gatewayID = result.GatewayID
		}
		if result.OK {
			c.policyMu.Lock()
			c.cachedPolicy = result.Policy
			c.policyMu.Unlock()
		}
	}
	if status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[agentkeeper] sync error (HTTP %d): %s\n", status, result.Error)
	}
}

func (c *Client) syncV2() bool {
	currentMode, currentRevision := c.currentMode()
	payload := map[string]interface{}{
		"hostname":                      c.hostname,
		"machine_id":                    c.machineID,
		"os":                            runtime.GOOS,
		"os_version":                    runtime.GOARCH,
		"gateway_version":               c.gatewayVersion,
		"effective_mode":                modeLabel(currentMode),
		"effective_assignment_revision": currentRevision,
		"connected_clients":             nonEmptyStrings(c.clientName),
		"connected_servers":             c.servers,
		"discovered_servers":            c.discoveredServers(),
		"signer_key_id":                 c.receiptStore.SignerKeyID(),
		"public_key_base64":             c.receiptStore.PublicKeyBase64(),
		"signing_algorithm":             "ed25519",
		"config_source_hash":            c.configSourceHash,
		"route_revision":                c.routeRevision,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	var result struct {
		OK              bool   `json:"ok"`
		GatewayID       string `json:"gateway_id"`
		Error           string `json:"error"`
		RouteAssignment *struct {
			DesiredMode     string `json:"desired_mode"`
			DesiredRevision int64  `json:"desired_revision"`
		} `json:"route_assignment"`
	}
	status, err := c.postJSON("register", "/api/v2/mcp/gateways/register", data, &result)
	if err != nil || status < 200 || status >= 300 || !result.OK {
		if c.logger != nil && status != http.StatusNotFound {
			c.logger.Warn("signed Gateway registration unavailable; using compatibility sync")
		}
		return false
	}
	if result.GatewayID != "" {
		c.gatewayID = result.GatewayID
	}
	if result.RouteAssignment != nil {
		c.applyAssignedMode(result.RouteAssignment.DesiredMode, result.RouteAssignment.DesiredRevision)
	}
	return true
}

func modeLabel(mode string) string {
	if strings.EqualFold(mode, "enforce") {
		return "enforce"
	}
	return "observe"
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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

	var result struct {
		OK       bool   `json:"ok"`
		Inserted int    `json:"inserted"`
		Received *int   `json:"received"`
		Disabled bool   `json:"disabled"`
		Error    string `json:"error"`
	}
	status, postErr := c.postJSON("events", "/api/v1/mcp/events", data, &result)
	if postErr != nil {
		c.logger.RequeueFront(events)
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload failed: %v\n", postErr)
		return
	}
	if status < 200 || status >= 300 {
		c.logger.RequeueFront(events)
		fmt.Fprintf(os.Stderr, "[agentkeeper] telemetry upload error (HTTP %d)\n", status)
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

func (c *Client) flushReceipts() {
	if c.receiptStore == nil || c.gatewayID == "" {
		return
	}
	receipts, err := c.receiptStore.Peek(100)
	if err != nil || len(receipts) == 0 {
		return
	}
	payload := map[string]interface{}{
		"gateway_id": c.gatewayID,
		"receipts":   receipts,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	var result struct {
		OK   bool `json:"ok"`
		Acks []struct {
			ReceiptID string `json:"receipt_id"`
			Status    string `json:"status"`
		} `json:"acks"`
	}
	status, postErr := c.postJSON("receipts", "/api/v2/mcp/receipts", data, &result)
	if postErr != nil || status < 200 || status >= 300 || !result.OK {
		if postErr != nil && c.logger != nil {
			c.logger.Warn("signed receipt upload failed: %v", postErr)
		}
		return
	}
	statuses := make(map[string]string, len(result.Acks))
	for _, ack := range result.Acks {
		if ack.ReceiptID != "" {
			statuses[ack.ReceiptID] = ack.Status
		}
	}
	if err := c.receiptStore.Resolve(statuses); err != nil && c.logger != nil {
		c.logger.Warn("could not resolve signed receipt acknowledgments: %v", err)
	}
}

func (c *Client) postJSON(operation, endpoint string, data []byte, out any) (int, error) {
	if c.runtimeSocket != "" {
		var payload any
		if err := json.Unmarshal(data, &payload); err != nil {
			return 0, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1900*time.Millisecond)
		defer cancel()
		return runtimebroker.Post(ctx, c.runtimeSocket, operation, payload, out)
	}
	req, err := http.NewRequest(http.MethodPost, c.apiURL+endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	client := &http.Client{Timeout: 4 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if out != nil {
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}
