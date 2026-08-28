// Package proxy implements the MCP stdio proxy that sits between
// AI clients and MCP servers, forwarding JSON-RPC messages while
// allowing inspection and modification by the detection engine.
package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
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
	EnforceMode      bool
	GatewayVersion   string
	Detection        telemetry.DetectionConfig
	DetectionEngine  *detection.Engine
	Logger           *logging.Logger
	ReceiptStore     *receipt.Store
	ClientName       string
	ConfigSourceHash string
	RouteRevision    string
}

// Proxy manages the MCP protocol proxy.
type Proxy struct {
	config    Config
	manager   *server.Manager
	telemetry *telemetry.Client
	mu        sync.Mutex
	modeMu    sync.RWMutex
	// Map from namespaced tool name to server name
	toolMap         map[string]string
	poisonedTools   map[string]detection.Result
	resourceMap     map[string]resourceRoute
	promptMap       map[string]string
	toolCache       map[string][]interface{}
	emptyToolLists  map[string]int
	toolStatus      map[string]toolRefreshStatus
	toolRefreshMu   sync.Mutex
	toolRefreshDone chan struct{}
	clientReady     bool
	activeToolsList int
	pendingListNote bool
	writeMu         sync.Mutex
}

type toolRefreshStatus struct {
	Status    string
	LastError string
	UpdatedAt string
}

type resourceRoute struct {
	ServerName  string
	OriginalURI string
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
		config:         cfg,
		manager:        mgr,
		telemetry:      tc,
		toolMap:        make(map[string]string),
		poisonedTools:  make(map[string]detection.Result),
		resourceMap:    make(map[string]resourceRoute),
		promptMap:      make(map[string]string),
		toolCache:      make(map[string][]interface{}),
		emptyToolLists: make(map[string]int),
		toolStatus:     make(map[string]toolRefreshStatus),
	}
	p.loadPersistentToolCache()
	return p
}

// SetEnforceMode changes the live data-plane mode after an acknowledged
// per-route control-plane assignment. New processes still begin from their
// local config, whose default is Observe.
func (p *Proxy) SetEnforceMode(enforce bool) {
	p.modeMu.Lock()
	p.config.EnforceMode = enforce
	p.modeMu.Unlock()
}

func (p *Proxy) enforceMode() bool {
	p.modeMu.RLock()
	defer p.modeMu.RUnlock()
	return p.config.EnforceMode
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
	return p.run(os.Stdin, os.Stdout)
}

func (p *Proxy) run(input io.Reader, writer io.Writer) error {
	reader := bufio.NewReader(input)

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
			// Never echo malformed bytes onto the protocol stream. Clients expect
			// every Gateway response to remain valid JSON-RPC and may terminate if
			// invalid input is reflected back verbatim.
			nullID := json.RawMessage(`null`)
			p.writeJSONLine(writer, JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      &nullID,
				Error: &JSONRPCError{
					Code:    -32700,
					Message: "Parse error",
				},
			})
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
	case "ping":
		resultJSON := json.RawMessage(`{}`)
		return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
	default:
		if msg.ID == nil {
			p.forwardNotification(msg.Method, msg.Params)
			return nil, nil
		}
		return &JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &JSONRPCError{Code: -32601, Message: "method not supported by AgentKeeper MCP Gateway"},
		}, nil
	}
}

func (p *Proxy) forwardNotification(method string, params json.RawMessage) {
	for _, name := range p.manager.ServerNames() {
		if srv := p.manager.Get(name); srv != nil {
			srv.Notify(method, params)
		}
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

	protocolVersion := negotiateProtocolVersion(msg.Params)
	// Return gateway's own capabilities
	result := map[string]interface{}{
		"protocolVersion": protocolVersion,
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

func negotiateProtocolVersion(params json.RawMessage) string {
	const fallback = "2024-11-05"
	var request struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(params, &request); err != nil {
		return fallback
	}
	switch request.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18":
		return request.ProtocolVersion
	default:
		return fallback
	}
}

func (p *Proxy) gatewayVersion() string {
	if strings.TrimSpace(p.config.GatewayVersion) != "" {
		return p.config.GatewayVersion
	}
	return "dev"
}

func (p *Proxy) handleToolsList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	finishToolsList := p.beginToolsList()
	defer finishToolsList()

	done := p.startToolRefresh()

	cachedTools, nextToolMap := p.cachedNamespacedTools()
	if len(nextToolMap) == 0 && len(p.manager.ServerNames()) > 0 {
		select {
		case <-done:
		case <-time.After(backendToolListWarmupDeadline):
			p.warn("returning gateway tools while backend tool refresh continues")
		}
	}
	cachedTools, nextToolMap = p.cachedNamespacedTools()

	p.setToolMap(nextToolMap)
	if p.enforceMode() && p.telemetry != nil {
		cachedTools = filterToolsForPolicy(cachedTools, nextToolMap, p.telemetry.Policy())
	}
	if p.enforceMode() {
		cachedTools = p.filterPoisonedTools(cachedTools)
	}

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

// filterToolsForPolicy enforces list/call parity without mutating the raw
// manifest cache. Observe mode deliberately skips this function so users see
// their normal tool catalog while the dashboard reports would-block impact.
func filterToolsForPolicy(tools []interface{}, toolMap map[string]string, synced telemetry.SyncPolicy) []interface{} {
	filtered := make([]interface{}, 0, len(tools))
	for _, tool := range tools {
		tm, ok := tool.(map[string]interface{})
		if !ok {
			continue
		}
		namespacedName, _ := tm["name"].(string)
		serverName := toolMap[namespacedName]
		originalName := strings.TrimPrefix(namespacedName, serverName+"__")
		if policy.Evaluate(synced, serverName, originalName, nil).Verdict == "block" {
			continue
		}
		filtered = append(filtered, tool)
	}
	return filtered
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
	found := make(map[string]detection.Result)
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
		results := p.config.DetectionEngine.EvaluateToolDescriptions([]detection.ToolDescription{desc})
		for _, r := range results {
			found[serverName+"__"+desc.Name] = r
			if p.config.Logger != nil {
				p.config.Logger.LogDetection(serverName, desc.Name, r)
			}
		}
	}
	p.mu.Lock()
	for name := range p.poisonedTools {
		if strings.HasPrefix(name, serverName+"__") {
			delete(p.poisonedTools, name)
		}
	}
	for name, result := range found {
		p.poisonedTools[name] = result
	}
	p.mu.Unlock()
}

func (p *Proxy) filterPoisonedTools(tools []interface{}) []interface{} {
	var synced telemetry.SyncPolicy
	if p.telemetry != nil {
		synced = p.telemetry.Policy()
	}
	filtered := make([]interface{}, 0, len(tools))
	for _, value := range tools {
		tool, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		if result, found := p.poisonedTool(name); found {
			result = applyDetectionPolicy(result, synced, p.config.Detection)
			if result.Verdict == detection.VerdictBlock {
				continue
			}
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func (p *Proxy) poisonedTool(name string) (detection.Result, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.poisonedTools[name]
	return result, ok
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

func (p *Proxy) beginToolsList() func() {
	p.mu.Lock()
	p.activeToolsList++
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		p.activeToolsList--
		shouldNotify := p.activeToolsList == 0 && p.pendingListNote
		if shouldNotify {
			p.pendingListNote = false
		}
		p.mu.Unlock()
		if shouldNotify {
			time.AfterFunc(50*time.Millisecond, p.emitToolsListChanged)
		}
	}
}

func (p *Proxy) emitToolsListChanged() {
	p.mu.Lock()
	if !p.clientReady {
		p.mu.Unlock()
		return
	}
	if p.activeToolsList > 0 {
		p.pendingListNote = true
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

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
	cloned := cloneTools(tools)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.emptyToolLists == nil {
		p.emptyToolLists = make(map[string]int)
	}
	if len(cloned) == 0 {
		p.emptyToolLists[serverName]++
		// One empty list can be a backend startup race. Two consecutive
		// successful empty manifests are treated as an intentional full removal.
		if p.emptyToolLists[serverName] < 2 {
			return false
		}
		if _, existed := p.toolCache[serverName]; !existed {
			return false
		}
		delete(p.toolCache, serverName)
		p.savePersistentToolCacheLocked()
		return true
	}
	p.emptyToolLists[serverName] = 0
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
		done := p.startToolRefresh()
		select {
		case <-done:
		case <-time.After(backendToolListWarmupDeadline):
		}
		p.rebuildToolMapFromCache()
		p.mu.Lock()
		serverName, ok = p.toolMap[callParams.Name]
		p.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("unknown tool: %s", callParams.Name)
		}
	}

	// Strip the namespace prefix to get the original tool name
	originalName := strings.TrimPrefix(callParams.Name, serverName+"__")
	callID := newEvidenceID("call")
	attemptID := newEvidenceID("attempt")
	enforceThisCall := p.enforceMode()
	effectiveMode := "observe"
	if enforceThisCall {
		effectiveMode = "enforce"
	}

	// --- 1. Policy check ---
	var finalVerdict string = "pass"
	var finalResult detection.Result
	var syncPolicy telemetry.SyncPolicy
	evaluationStatus := "evaluated"
	decisionID := ""

	if p.telemetry != nil {
		syncPolicy = p.telemetry.Policy()
		policyResult := policy.Evaluate(syncPolicy, serverName, originalName, callParams.Arguments)

		if policyResult.Verdict == "block" {
			if enforceThisCall {
				// Enforce: block immediately, log, and return error
				blockedResult := detection.Result{
					Verdict:     detection.VerdictBlock,
					PatternName: policyResult.Rule,
					Severity:    "high",
					Description: policyResult.Reason,
					Category:    "policy",
				}
				p.logToolOutcome(serverName, originalName, callParams.Arguments, blockedResult, logging.ToolCallOutcome{
					CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
					PolicyDecision: "block", EvaluationStatus: evaluationStatus,
					RequiredDisposition: "deny_before_dispatch", AppliedDisposition: "denied_before_dispatch",
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

	if poisoned, found := p.poisonedTool(callParams.Name); found {
		poisoned = applyDetectionPolicy(poisoned, syncPolicy, p.config.Detection)
		if verdictRank(string(poisoned.Verdict)) > verdictRank(finalVerdict) {
			finalVerdict = string(poisoned.Verdict)
			finalResult = poisoned
		}
	}

	// --- 2. Embedded detection ---

	if p.config.DetectionEngine != nil {
		embeddedResult := p.config.DetectionEngine.EvaluateToolCall(serverName, originalName, callParams.Arguments)
		embeddedResult = applyDetectionPolicy(embeddedResult, syncPolicy, p.config.Detection)
		if verdictRank(string(embeddedResult.Verdict)) > verdictRank(finalVerdict) {
			finalVerdict = string(embeddedResult.Verdict)
			finalResult = embeddedResult
		}
	}

	// --- 3. Connected detection (API, 4s timeout) ---
	if p.telemetry != nil {
		apiResult := p.telemetry.Evaluate(serverName, originalName, callParams.Arguments, callID, attemptID)
		if apiResult == nil {
			evaluationStatus = "degraded_local"
		} else {
			decisionID = apiResult.DecisionID
			if apiResult.EvaluationStatus != "" {
				evaluationStatus = apiResult.EvaluationStatus
			}
		}
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

	// --- 4. Enforce merged verdict ---
	if finalVerdict == "block" && enforceThisCall {
		p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
			CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
			PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
			DecisionID:          decisionID,
			RequiredDisposition: "deny_before_dispatch", AppliedDisposition: "denied_before_dispatch",
		})
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

	// --- 5. Forward to backend server ---
	srv := p.manager.Get(serverName)
	if srv == nil {
		p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
			CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
			PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
			DecisionID:          decisionID,
			RequiredDisposition: "forward", AppliedDisposition: "dispatch_failed",
			FailureReason: "server_not_available",
		})
		return nil, fmt.Errorf("server not available: %s", serverName)
	}
	if err := srv.Initialize(); err != nil {
		p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
			CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
			PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
			DecisionID:          decisionID,
			RequiredDisposition: "forward", AppliedDisposition: "dispatch_failed",
			FailureReason: "server_initialize_failed",
		})
		return nil, fmt.Errorf("initializing %s: %w", serverName, err)
	}

	forwardParams := map[string]interface{}{
		"name":      originalName,
		"arguments": callParams.Arguments,
	}
	forwardJSON, _ := json.Marshal(forwardParams)

	response, err := srv.Call("tools/call", forwardJSON)
	if err != nil {
		p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
			CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
			PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
			DecisionID:          decisionID,
			RequiredDisposition: "forward", AppliedDisposition: "dispatch_failed",
			Dispatched: true, FailureReason: "upstream_call_failed",
		})
		return nil, fmt.Errorf("calling %s/%s: %w", serverName, originalName, err)
	}

	// --- 6. Post-execution response scan ---
	if p.config.DetectionEngine != nil {
		respStr := string(response)
		result := p.config.DetectionEngine.EvaluateToolResponse(serverName, originalName, respStr)
		result = applyDetectionPolicy(result, syncPolicy, p.config.Detection)
		if result.Verdict != detection.VerdictPass {
			if verdictRank(string(result.Verdict)) > verdictRank(finalVerdict) {
				finalVerdict = string(result.Verdict)
				finalResult = result
			}
			if result.Verdict == detection.VerdictBlock && enforceThisCall {
				p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
					CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
					PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
					DecisionID:          decisionID,
					RequiredDisposition: "withhold_result", AppliedDisposition: "result_withheld",
					Dispatched: true, ResultReceived: true, ResponseWithheld: true,
				})
				errResult := map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": fmt.Sprintf("Blocked by AgentKeeper: %s — %s. Upstream response was withheld.", result.PatternName, result.Description),
						},
					},
					"isError": true,
				}
				resultJSON, _ := json.Marshal(errResult)
				return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
			}
		}
	}

	p.logToolOutcome(serverName, originalName, callParams.Arguments, finalResult, logging.ToolCallOutcome{
		CallID: callID, AttemptID: attemptID, Mode: effectiveMode,
		PolicyDecision: finalVerdict, EvaluationStatus: evaluationStatus,
		DecisionID:          decisionID,
		RequiredDisposition: "forward", AppliedDisposition: "result_returned",
		Dispatched: true, ResultReceived: true, ResultReturned: true,
	})

	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: response}, nil
}

func (p *Proxy) logToolOutcome(serverName, toolName string, params map[string]interface{}, result detection.Result, outcome logging.ToolCallOutcome) {
	outcome.ClientName = p.config.ClientName
	outcome.ConfigSourceHash = p.config.ConfigSourceHash
	outcome.RouteRevision = p.config.RouteRevision
	if p.config.Logger != nil {
		p.config.Logger.LogToolCallOutcome(serverName, toolName, params, result, outcome)
	}
	if p.config.ReceiptStore == nil {
		return
	}
	syncedPolicy := telemetry.SyncPolicy{}
	if p.telemetry != nil {
		syncedPolicy = p.telemetry.Policy()
	}
	rawSnapshotID, effectiveViewHash := p.manifestEvidence(serverName, syncedPolicy)
	if _, err := p.config.ReceiptStore.Enqueue(receipt.Input{
		CallID:              outcome.CallID,
		AttemptID:           outcome.AttemptID,
		DecisionID:          outcome.DecisionID,
		ClientName:          p.config.ClientName,
		ConfigSourceHash:    p.config.ConfigSourceHash,
		Phase:               "terminal",
		ServerName:          serverName,
		ToolName:            toolName,
		PolicyDecision:      outcome.PolicyDecision,
		EvaluationStatus:    outcome.EvaluationStatus,
		RequiredDisposition: outcome.RequiredDisposition,
		AppliedDisposition:  outcome.AppliedDisposition,
		EffectiveMode:       outcome.Mode,
		PolicyHash:          hashJSON(syncedPolicy),
		RouteRevision:       p.config.RouteRevision,
		RawSnapshotID:       rawSnapshotID,
		EffectiveViewHash:   effectiveViewHash,
		Dispatched:          outcome.Dispatched,
		ResultReceived:      outcome.ResultReceived,
		ResultReturned:      outcome.ResultReturned,
		ResponseWithheld:    outcome.ResponseWithheld,
		Terminal:            true,
		FailureReason:       outcome.FailureReason,
	}); err != nil && p.config.Logger != nil {
		p.config.Logger.Warn("could not persist signed application receipt: %v", err)
	}
}

func (p *Proxy) manifestEvidence(serverName string, syncedPolicy telemetry.SyncPolicy) (string, string) {
	rawTools := p.cachedTools(serverName)
	rawSnapshotID := hashJSON(rawTools)
	if !p.enforceMode() {
		return rawSnapshotID, rawSnapshotID
	}
	namespacedTools := make([]interface{}, 0, len(rawTools))
	toolMap := make(map[string]string, len(rawTools))
	appendNamespacedTools(&namespacedTools, toolMap, serverName, rawTools)
	effectiveTools := filterToolsForPolicy(namespacedTools, toolMap, syncedPolicy)
	effectiveTools = p.filterPoisonedTools(effectiveTools)
	return rawSnapshotID, hashJSON(effectiveTools)
}

func hashJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newEvidenceID(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}

func applyDetectionPolicy(result detection.Result, p telemetry.SyncPolicy, local telemetry.DetectionConfig) detection.Result {
	if result.Verdict == detection.VerdictPass || result.Verdict == "" {
		return result
	}
	switch result.Category {
	case "sensitive_data":
		if strings.EqualFold(p.Detection.SensitiveData, "block") || strings.EqualFold(local.SensitiveData, "block") {
			result.Verdict = detection.VerdictBlock
		}
	case "threat", "tool_poisoning":
		if strings.EqualFold(p.Detection.Threat, "block") || strings.EqualFold(local.Threat, "block") {
			result.Verdict = detection.VerdictBlock
		}
	}
	return result
}

func (p *Proxy) handleResourcesList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	resources, routes := p.loadResources()
	p.mu.Lock()
	p.resourceMap = routes
	p.mu.Unlock()
	result := map[string]interface{}{"resources": resources}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
}

func (p *Proxy) handleResourcesRead(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.URI == "" {
		return nil, fmt.Errorf("invalid resources/read params")
	}
	p.mu.Lock()
	route, ok := p.resourceMap[params.URI]
	p.mu.Unlock()
	if !ok {
		_, routes := p.loadResources()
		p.mu.Lock()
		p.resourceMap = routes
		route, ok = routes[params.URI]
		p.mu.Unlock()
	}
	if !ok {
		return nil, fmt.Errorf("unknown resource URI")
	}
	srv := p.manager.Get(route.ServerName)
	if srv == nil {
		return nil, fmt.Errorf("server not available: %s", route.ServerName)
	}
	forwardParams, _ := json.Marshal(map[string]interface{}{"uri": route.OriginalURI})
	response, err := srv.Call("resources/read", forwardParams)
	if err != nil {
		return nil, fmt.Errorf("reading resource from %s: %w", route.ServerName, err)
	}
	return p.inspectContentResult(msg.ID, route.ServerName, "resources/read", response)
}

func (p *Proxy) loadResources() ([]interface{}, map[string]resourceRoute) {
	all := make([]interface{}, 0)
	routes := make(map[string]resourceRoute)
	names := p.manager.ServerNames()
	sort.Strings(names)
	for _, name := range names {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		resources, err := srv.ListResources()
		if err != nil {
			p.warn("failed to list resources from %s: %v", name, err)
			continue
		}
		for _, value := range resources {
			resource, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			originalURI, _ := resource["uri"].(string)
			if originalURI == "" {
				continue
			}
			virtualURI := "agentkeeper://resource/" + base64.RawURLEncoding.EncodeToString([]byte(name)) + "/" + base64.RawURLEncoding.EncodeToString([]byte(originalURI))
			copy := make(map[string]interface{}, len(resource)+1)
			for key, entry := range resource {
				copy[key] = entry
			}
			copy["uri"] = virtualURI
			copy["_meta"] = map[string]interface{}{"agentkeeper": map[string]interface{}{"server": name, "original_uri": originalURI}}
			all = append(all, copy)
			routes[virtualURI] = resourceRoute{ServerName: name, OriginalURI: originalURI}
		}
	}
	return all, routes
}

func (p *Proxy) handlePromptsList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	prompts, routes := p.loadPrompts()
	p.mu.Lock()
	p.promptMap = routes
	p.mu.Unlock()
	result := map[string]interface{}{"prompts": prompts}
	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultJSON}, nil
}

func (p *Proxy) handlePromptsGet(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	var params map[string]interface{}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid prompts/get params")
	}
	namespacedName, _ := params["name"].(string)
	p.mu.Lock()
	serverName, ok := p.promptMap[namespacedName]
	p.mu.Unlock()
	if !ok {
		_, routes := p.loadPrompts()
		p.mu.Lock()
		p.promptMap = routes
		serverName, ok = routes[namespacedName]
		p.mu.Unlock()
	}
	if !ok {
		return nil, fmt.Errorf("unknown prompt: %s", namespacedName)
	}
	params["name"] = strings.TrimPrefix(namespacedName, serverName+"__")
	forwardParams, _ := json.Marshal(params)
	srv := p.manager.Get(serverName)
	if srv == nil {
		return nil, fmt.Errorf("server not available: %s", serverName)
	}
	response, err := srv.Call("prompts/get", forwardParams)
	if err != nil {
		return nil, fmt.Errorf("getting prompt from %s: %w", serverName, err)
	}
	return p.inspectContentResult(msg.ID, serverName, "prompts/get", response)
}

func (p *Proxy) loadPrompts() ([]interface{}, map[string]string) {
	all := make([]interface{}, 0)
	routes := make(map[string]string)
	names := p.manager.ServerNames()
	sort.Strings(names)
	for _, name := range names {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		prompts, err := srv.ListPrompts()
		if err != nil {
			p.warn("failed to list prompts from %s: %v", name, err)
			continue
		}
		for _, value := range prompts {
			prompt, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			originalName, _ := prompt["name"].(string)
			if originalName == "" {
				continue
			}
			namespacedName := name + "__" + originalName
			copy := make(map[string]interface{}, len(prompt))
			for key, entry := range prompt {
				copy[key] = entry
			}
			copy["name"] = namespacedName
			all = append(all, copy)
			routes[namespacedName] = name
		}
	}
	return all, routes
}

func (p *Proxy) inspectContentResult(id *json.RawMessage, serverName, method string, response json.RawMessage) (*JSONRPCMessage, error) {
	enforceThisCall := p.enforceMode()
	result := detection.Result{Verdict: detection.VerdictPass}
	if p.config.DetectionEngine != nil {
		result = p.config.DetectionEngine.EvaluateToolResponse(serverName, method, string(response))
		syncedPolicy := telemetry.SyncPolicy{}
		if p.telemetry != nil {
			syncedPolicy = p.telemetry.Policy()
		}
		// Local detection policy is authoritative even when the Gateway is
		// offline or intentionally deployed without cloud telemetry. Resources
		// and prompts must honor the same Observe/Enforce contract as tool
		// results; cloud policy augments that contract but is not a prerequisite.
		result = applyDetectionPolicy(result, syncedPolicy, p.config.Detection)
	}
	decision := string(result.Verdict)
	if decision == "" {
		decision = "pass"
	}
	outcome := logging.ToolCallOutcome{
		CallID: newEvidenceID("call"), AttemptID: newEvidenceID("attempt"),
		Mode: "observe", PolicyDecision: decision, EvaluationStatus: "evaluated",
		RequiredDisposition: "forward", AppliedDisposition: "result_returned",
		Dispatched: true, ResultReceived: true, ResultReturned: true,
	}
	if enforceThisCall {
		outcome.Mode = "enforce"
	}
	if result.Verdict == detection.VerdictBlock && enforceThisCall {
		outcome.RequiredDisposition = "withhold_result"
		outcome.AppliedDisposition = "result_withheld"
		outcome.ResultReturned = false
		outcome.ResponseWithheld = true
		p.logToolOutcome(serverName, method, nil, result, outcome)
		blocked := map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": "Blocked by AgentKeeper: upstream content was withheld."}},
			"isError": true,
		}
		blockedJSON, _ := json.Marshal(blocked)
		return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Result: blockedJSON}, nil
	}
	p.logToolOutcome(serverName, method, nil, result, outcome)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Result: response}, nil
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
		if p.enforceMode() {
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
	names := []string(nil)
	if p.manager != nil {
		names = p.manager.ServerNames()
	}
	if len(names) == 0 {
		for name := range p.toolCache {
			names = append(names, name)
		}
	}
	for _, name := range names {
		tools := p.toolCache[name]
		if len(tools) == 0 {
			continue
		}
		backendCount++
		toolCount += len(tools)
	}
	for _, name := range names {
		status := p.toolStatus[name]
		if status.Status == "degraded" {
			degradedBackendCount++
		}
	}
	return backendCount, toolCount, degradedBackendCount
}
