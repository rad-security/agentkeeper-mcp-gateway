// Package proxy implements the MCP stdio proxy that sits between
// AI clients and MCP servers, forwarding JSON-RPC messages while
// allowing inspection and modification by the detection engine.
package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/policy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

const (
	backendToolListWarmupDeadline = 2 * time.Second
)

// JSONRPCMessage represents a JSON-RPC 2.0 message.
type JSONRPCMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`     // request ID (null for notifications)
	Method  string           `json:"method,omitempty"` // request method
	Params  json.RawMessage  `json:"params,omitempty"` // request params
	Result  json.RawMessage  `json:"result,omitempty"` // response result
	Error   *JSONRPCError    `json:"error,omitempty"`  // response error
}

// JSONRPCError represents a JSON-RPC error.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Config holds proxy configuration.
type Config struct {
	EnforceMode     bool
	GatewayVersion  string
	DetectionEngine *detection.Engine
	Logger          *logging.Logger
}

// Proxy manages the MCP protocol proxy.
type Proxy struct {
	config    Config
	manager   *server.Manager
	telemetry *telemetry.Client
	mu        sync.Mutex
	// Map from namespaced tool name to server name
	toolMap         map[string]string
	toolCache       map[string][]interface{}
	toolStatus      map[string]toolRefreshStatus
	toolRefreshMu   sync.Mutex
	toolRefreshDone chan struct{}
	clientReady     bool
	writeMu         sync.Mutex
}

type toolRefreshStatus struct {
	Status    string
	LastError string
	UpdatedAt string
}

type persistentToolCache struct {
	Version int                          `json:"version"`
	Servers map[string]persistentToolSet `json:"servers"`
}

type persistentToolSet struct {
	UpdatedAt string        `json:"updated_at"`
	Tools     []interface{} `json:"tools"`
}

// NewProxy creates a new MCP proxy.
func NewProxy(cfg Config, mgr *server.Manager, tc *telemetry.Client) *Proxy {
	p := &Proxy{
		config:     cfg,
		manager:    mgr,
		telemetry:  tc,
		toolMap:    make(map[string]string),
		toolCache:  make(map[string][]interface{}),
		toolStatus: make(map[string]toolRefreshStatus),
	}
	p.loadPersistentToolCache()
	return p
}

// verdictRank maps verdict strings to numeric severity for comparison.
func verdictRank(v string) int {
	switch v {
	case "block":
		return 3
	case "warn":
		return 2
	default: // "pass", "allow", ""
		return 1
	}
}

// Run starts the proxy, reading from stdin and writing to stdout.
func (p *Proxy) Run() error {
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		// Skip empty lines
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}

		var msg JSONRPCMessage
		if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
			// Not valid JSON-RPC — pass through
			p.writeRaw(writer, line)
			continue
		}

		response, err := p.handleMessage(msg)
		if err != nil {
			// Send JSON-RPC error response
			if msg.ID != nil {
				errResp := JSONRPCMessage{
					JSONRPC: "2.0",
					ID:      msg.ID,
					Error: &JSONRPCError{
						Code:    -32603,
						Message: err.Error(),
					},
				}
				p.writeJSONLine(writer, errResp)
			}
			continue
		}

		if response != nil {
			p.writeJSONLine(writer, response)
		}
	}
}

func (p *Proxy) writeRaw(writer io.Writer, data []byte) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, _ = writer.Write(data)
}

func (p *Proxy) writeJSONLine(writer io.Writer, value interface{}) {
	data, _ := json.Marshal(value)
	data = append(data, '\n')
	p.writeRaw(writer, data)
}

func (p *Proxy) handleMessage(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	switch msg.Method {
	case "initialize":
		return p.handleInitialize(msg)
	case "initialized", "notifications/initialized":
		// Notification — no response needed
		p.markClientReady()
		return nil, nil
	case "tools/list":
		return p.handleToolsList(msg)
	case "tools/call":
		return p.handleToolsCall(msg)
	case "resources/list":
		return p.handleResourcesList(msg)
	case "resources/read":
		return p.handleResourcesRead(msg)
	case "prompts/list":
		return p.handlePromptsList(msg)
	case "prompts/get":
		return p.handlePromptsGet(msg)
	default:
		// Unknown method — could be a notification or custom method
		return nil, nil
	}
}

func (p *Proxy) handleInitialize(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	// Start all backend servers
	if err := p.manager.StartAll(); err != nil {
		return nil, fmt.Errorf("starting servers: %w", err)
	}

	// Keep the gateway MCP server fast to attach. Backend MCP servers are
	// refreshed out-of-band so one slow or broken upstream cannot make Claude
	// Desktop mark the gateway itself as disconnected.
	p.startToolRefresh()

	// Return gateway's own capabilities
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{"listChanged": true},
			"resources": map[string]interface{}{},
			"prompts":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": p.gatewayVersion(),
		},
	}

	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  resultJSON,
	}, nil
}

func (p *Proxy) gatewayVersion() string {
	if strings.TrimSpace(p.config.GatewayVersion) != "" {
		return p.config.GatewayVersion
	}
	return "dev"
}

func (p *Proxy) handleToolsList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	done := p.startToolRefresh()

	cachedTools, nextToolMap := p.cachedNamespacedTools()
	if len(nextToolMap) == 0 && len(p.manager.ServerNames()) > 0 {
		select {
		case <-done:
			cachedTools, nextToolMap = p.cachedNamespacedTools()
		case <-time.After(backendToolListWarmupDeadline):
			p.warn("returning gateway tools while backend tool refresh continues")
		}
	}

	p.setToolMap(nextToolMap)

	allTools := p.getBuiltinTools()
	allTools = append(allTools, cachedTools...)

	result := map[string]interface{}{
		"tools": allTools,
	}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  resultJSON,
	}, nil
}

func (p *Proxy) startToolRefresh() <-chan struct{} {
	p.toolRefreshMu.Lock()
	if p.toolRefreshDone != nil {
		done := p.toolRefreshDone
		p.toolRefreshMu.Unlock()
		return done
	}

	done := make(chan struct{})
	p.toolRefreshDone = done
	p.toolRefreshMu.Unlock()

	go func() {
		defer close(done)
		p.refreshTools()

		p.toolRefreshMu.Lock()
		if p.toolRefreshDone == done {
			p.toolRefreshDone = nil
		}
		p.toolRefreshMu.Unlock()
	}()

	return done
}

func (p *Proxy) refreshTools() {
	type listResult struct {
		name  string
		tools []interface{}
		err   error
	}
	names := p.manager.ServerNames()
	sort.Strings(names)
	results := make(chan listResult, len(names))
	for _, name := range names {
		go func(name string) {
			srv := p.manager.Get(name)
			if srv == nil {
				results <- listResult{name: name}
				return
			}
			tools, err := srv.ListTools()
			results <- listResult{name: name, tools: tools, err: err}
		}(name)
	}

	for remaining := len(names); remaining > 0; remaining-- {
		result := <-results
		if result.err != nil {
			p.warn("failed to list tools from %s: %v", result.name, result.err)
			p.setToolStatus(result.name, toolRefreshStatus{
				Status:    "degraded",
				LastError: result.err.Error(),
				UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
			continue
		}
		changed := p.setCachedTools(result.name, result.tools)
		p.setToolStatus(result.name, toolRefreshStatus{
			Status:    "ready",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
		p.logToolDescriptionDetections(result.name, result.tools)
		p.rebuildToolMapFromCache()
		if changed {
			p.emitToolsListChanged()
		}
	}
}

func (p *Proxy) warn(format string, args ...interface{}) {
	if p.config.Logger == nil {
		return
	}
	p.config.Logger.Warn(format, args...)
}

func (p *Proxy) logToolDescriptionDetections(serverName string, tools []interface{}) {
	if p.config.DetectionEngine == nil {
		return
	}
	var descs []detection.ToolDescription
	for _, t := range tools {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		desc := detection.ToolDescription{
			Name:        fmt.Sprintf("%v", tm["name"]),
			Description: fmt.Sprintf("%v", tm["description"]),
		}
		if inputSchema, ok := tm["inputSchema"].(map[string]interface{}); ok {
			if props, ok := inputSchema["properties"].(map[string]interface{}); ok {
				for pName, pVal := range props {
					if pm, ok := pVal.(map[string]interface{}); ok {
						desc.Parameters = append(desc.Parameters, detection.ToolParam{
							Name:        pName,
							Description: fmt.Sprintf("%v", pm["description"]),
						})
					}
				}
			}
		}
		descs = append(descs, desc)
	}

	results := p.config.DetectionEngine.EvaluateToolDescriptions(descs)
	for _, r := range results {
		p.config.Logger.LogDetection(serverName, "", r)
	}
}

func (p *Proxy) cachedNamespacedTools() ([]interface{}, map[string]string) {
	var allTools []interface{}
	nextToolMap := make(map[string]string)
	names := p.manager.ServerNames()
	sort.Strings(names)
	for _, name := range names {
		appendNamespacedTools(&allTools, nextToolMap, name, p.cachedTools(name))
	}
	return allTools, nextToolMap
}

func (p *Proxy) rebuildToolMapFromCache() {
	_, nextToolMap := p.cachedNamespacedTools()
	p.setToolMap(nextToolMap)
}

func (p *Proxy) setToolMap(nextToolMap map[string]string) {
	p.mu.Lock()
	p.toolMap = nextToolMap
	p.mu.Unlock()
}

func (p *Proxy) setToolStatus(serverName string, status toolRefreshStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.toolStatus == nil {
		p.toolStatus = make(map[string]toolRefreshStatus)
	}
	p.toolStatus[serverName] = status
}

func (p *Proxy) getToolStatus(serverName string) toolRefreshStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.toolStatus[serverName]
}

func (p *Proxy) markClientReady() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clientReady = true
}

func (p *Proxy) isClientReady() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientReady
}

func (p *Proxy) emitToolsListChanged() {
	if !p.isClientReady() {
		return
	}
	p.writeJSONLine(os.Stdout, JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  "notifications/tools/list_changed",
	})
}

func (p *Proxy) cachedTools(serverName string) []interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneTools(p.toolCache[serverName])
}

func (p *Proxy) setCachedTools(serverName string, tools []interface{}) bool {
	if len(tools) == 0 {
		return false
	}
	cloned := cloneTools(tools)
	p.mu.Lock()
	defer p.mu.Unlock()
	if reflect.DeepEqual(p.toolCache[serverName], cloned) {
		return false
	}
	p.toolCache[serverName] = cloned
	p.savePersistentToolCacheLocked()
	return true
}

func (p *Proxy) loadPersistentToolCache() {
	path := defaultToolCachePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cache persistentToolCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return
	}
	if cache.Servers == nil {
		return
	}
	for name, entry := range cache.Servers {
		if len(entry.Tools) == 0 {
			continue
		}
		p.toolCache[name] = cloneTools(entry.Tools)
	}
}

func (p *Proxy) savePersistentToolCacheLocked() {
	path := defaultToolCachePath()
	if path == "" {
		return
	}
	cache := persistentToolCache{
		Version: 1,
		Servers: make(map[string]persistentToolSet, len(p.toolCache)),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for name, tools := range p.toolCache {
		if len(tools) == 0 {
			continue
		}
		cache.Servers[name] = persistentToolSet{
			UpdatedAt: now,
			Tools:     cloneTools(tools),
		}
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func defaultToolCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "tool-cache.json")
}

func appendNamespacedTools(allTools *[]interface{}, toolMap map[string]string, serverName string, tools []interface{}) {
	for _, t := range cloneTools(tools) {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		originalName := fmt.Sprintf("%v", tm["name"])
		namespacedName := serverName + "__" + originalName
		tm["name"] = namespacedName
		toolMap[namespacedName] = serverName
		*allTools = append(*allTools, tm)
	}
}

func cloneTools(tools []interface{}) []interface{} {
	if len(tools) == 0 {
		return nil
	}
	out := make([]interface{}, 0, len(tools))
	for _, tool := range tools {
		if tm, ok := tool.(map[string]interface{}); ok {
			copied := make(map[string]interface{}, len(tm))
			for key, value := range tm {
				copied[key] = value
			}
			out = append(out, copied)
			continue
		}
		out = append(out, tool)
	}
	return out
}

func (p *Proxy) handleToolsCall(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	// Parse the tool call params
	var callParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &callParams); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}

	// Check for built-in tools
	if strings.HasPrefix(callParams.Name, "agentkeeper_") {
		return p.handleBuiltinToolCall(msg.ID, callParams.Name, callParams.Arguments)
	}

	// Find the target server
	p.mu.Lock()
	serverName, ok := p.toolMap[callParams.Name]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", callParams.Name)
	}

	// Strip the namespace prefix to get the original tool name
	originalName := strings.TrimPrefix(callParams.Name, serverName+"__")

	// --- 1. Policy check ---
	var finalVerdict string = "pass"
	var finalResult detection.Result

	if p.telemetry != nil {
		syncPolicy := p.telemetry.Policy()
		policyResult := policy.Evaluate(syncPolicy, serverName, originalName, callParams.Arguments)

		if policyResult.Verdict == "block" {
			if p.config.EnforceMode {
				// Enforce: block immediately, log, and return error
				p.config.Logger.LogToolCall(serverName, originalName, callParams.Arguments, detection.Result{
					Verdict:     detection.VerdictBlock,
					PatternName: policyResult.Rule,
					Severity:    "high",
					Description: policyResult.Reason,
					Category:    "policy",
				})
				errResult := map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": fmt.Sprintf("Blocked by AgentKeeper: %s. Try an alternative approach.", policyResult.Reason),
						},
					},
					"isError": true,
				}
				resultJSON, _ := json.Marshal(errResult)
				return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
			}
			// Audit mode: seed the merged verdict so it propagates
			finalVerdict = "block"
			finalResult = detection.Result{
				Verdict:     detection.VerdictBlock,
				PatternName: policyResult.Rule,
				Severity:    "high",
				Description: policyResult.Reason,
				Category:    "policy",
			}
		} else if policyResult.Verdict == "warn" {
			finalVerdict = "warn"
			finalResult = detection.Result{
				Verdict:     detection.VerdictWarn,
				PatternName: policyResult.Rule,
				Severity:    "medium",
				Description: policyResult.Reason,
				Category:    "policy",
			}
		}
	}

	// --- 2. Embedded detection ---

	if p.config.DetectionEngine != nil {
		embeddedResult := p.config.DetectionEngine.EvaluateToolCall(serverName, originalName, callParams.Arguments)
		if verdictRank(string(embeddedResult.Verdict)) > verdictRank(finalVerdict) {
			finalVerdict = string(embeddedResult.Verdict)
			finalResult = embeddedResult
		}
	}

	// --- 3. Connected detection (API, 4s timeout) ---
	if p.telemetry != nil {
		apiResult := p.telemetry.Evaluate(serverName, originalName, callParams.Arguments)
		if apiResult != nil && verdictRank(apiResult.Verdict) > verdictRank(finalVerdict) {
			finalVerdict = apiResult.Verdict
			finalResult = detection.Result{
				Verdict:     detection.Verdict(apiResult.Verdict),
				PatternName: apiResult.PatternName,
				Severity:    apiResult.Severity,
				Description: apiResult.Description,
				Category:    "api_detection",
			}
		}
	}

	// --- 4. Log merged result ---
	p.config.Logger.LogToolCall(serverName, originalName, callParams.Arguments, finalResult)

	// --- 5. Enforce merged verdict ---
	if finalVerdict == "block" && p.config.EnforceMode {
		errResult := map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Blocked by AgentKeeper: %s — %s. Try an alternative approach.", finalResult.PatternName, finalResult.Description),
				},
			},
			"isError": true,
		}
		resultJSON, _ := json.Marshal(errResult)
		return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
	}

	// --- 6. Forward to backend server ---
	srv := p.manager.Get(serverName)
	if srv == nil {
		return nil, fmt.Errorf("server not available: %s", serverName)
	}
	if err := srv.Initialize(); err != nil {
		return nil, fmt.Errorf("initializing %s: %w", serverName, err)
	}

	forwardParams := map[string]interface{}{
		"name":      originalName,
		"arguments": callParams.Arguments,
	}
	forwardJSON, _ := json.Marshal(forwardParams)

	response, err := srv.Call("tools/call", forwardJSON)
	if err != nil {
		return nil, fmt.Errorf("calling %s/%s: %w", serverName, originalName, err)
	}

	// --- 7. Post-execution response scan ---
	if p.config.DetectionEngine != nil {
		respStr := string(response)
		result := p.config.DetectionEngine.EvaluateToolResponse(serverName, originalName, respStr)
		if result.Verdict != detection.VerdictPass {
			p.config.Logger.LogDetection(serverName, originalName, result)
		}
	}

	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: response}, nil
}

func (p *Proxy) handleResourcesList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	p.startToolRefresh()
	result := map[string]interface{}{"resources": []interface{}{}}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
}

func (p *Proxy) handleResourcesRead(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	// Forward to appropriate server based on resource URI
	// For now, try all servers
	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		response, err := srv.Call("resources/read", msg.Params)
		if err == nil {
			return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: response}, nil
		}
	}
	return nil, fmt.Errorf("no server could handle resources/read")
}

func (p *Proxy) handlePromptsList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	p.startToolRefresh()
	result := map[string]interface{}{"prompts": []interface{}{}}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
}

func (p *Proxy) handlePromptsGet(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		response, err := srv.Call("prompts/get", msg.Params)
		if err == nil {
			return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: response}, nil
		}
	}
	return nil, fmt.Errorf("no server could handle prompts/get")
}

func (p *Proxy) getBuiltinTools() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"name":        "agentkeeper_status",
			"description": "Returns AgentKeeper MCP Gateway status including connected servers, detection mode, and policy summary",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		map[string]interface{}{
			"name":        "agentkeeper_audit",
			"description": "Security audit of the MCP environment — server inventory, access controls, tool poisoning scan",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

func (p *Proxy) handleBuiltinToolCall(id *json.RawMessage, name string, args map[string]interface{}) (*JSONRPCMessage, error) {
	var text string
	switch name {
	case "agentkeeper_status":
		mode := "audit"
		if p.config.EnforceMode {
			mode = "enforce"
		}
		servers := p.manager.ServerNames()
		cachedBackendCount, cachedToolCount, degradedBackendCount := p.cachedToolSummary()
		text = fmt.Sprintf("AgentKeeper MCP Gateway\nMode: %s\nServers: %d configured (%s)\nTools: %d cached from %d backend(s); %d backend(s) degraded; refreshing in background\nDetection: active",
			mode, len(servers), strings.Join(servers, ", "), cachedToolCount, cachedBackendCount, degradedBackendCount)
	case "agentkeeper_audit":
		p.startToolRefresh()
		servers := p.manager.ServerNames()
		sort.Strings(servers)
		text = fmt.Sprintf("MCP Security Audit\nServers: %d\n", len(servers))
		for _, s := range servers {
			tools := p.cachedTools(s)
			status := p.getToolStatus(s)
			state := status.Status
			if state == "" {
				state = "refreshing"
			}
			if status.LastError != "" {
				text += fmt.Sprintf("  %s: %d cached tools (%s: %s)\n", s, len(tools), state, status.LastError)
				continue
			}
			text += fmt.Sprintf("  %s: %d cached tools (%s)\n", s, len(tools), state)
		}
	default:
		text = "Unknown built-in tool: " + name
	}

	result := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
	}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Result: resultJSON}, nil
}

func (p *Proxy) cachedToolSummary() (backendCount int, toolCount int, degradedBackendCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tools := range p.toolCache {
		if len(tools) == 0 {
			continue
		}
		backendCount++
		toolCount += len(tools)
	}
	for _, status := range p.toolStatus {
		if status.Status == "degraded" {
			degradedBackendCount++
		}
	}
	return backendCount, toolCount, degradedBackendCount
}
