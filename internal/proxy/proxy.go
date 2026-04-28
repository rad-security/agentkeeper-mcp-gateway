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
	"strings"
	"sync"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/policy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// JSONRPCMessage represents a JSON-RPC 2.0 message.
type JSONRPCMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`    // request ID (null for notifications)
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
	toolMap map[string]string
}

// NewProxy creates a new MCP proxy.
func NewProxy(cfg Config, mgr *server.Manager, tc *telemetry.Client) *Proxy {
	return &Proxy{
		config:    cfg,
		manager:   mgr,
		telemetry: tc,
		toolMap:   make(map[string]string),
	}
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
			writer.Write(line)
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
				data, _ := json.Marshal(errResp)
				writer.Write(data)
				writer.Write([]byte("\n"))
			}
			continue
		}

		if response != nil {
			data, _ := json.Marshal(response)
			writer.Write(data)
			writer.Write([]byte("\n"))
		}
	}
}

func (p *Proxy) handleMessage(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	switch msg.Method {
	case "initialize":
		return p.handleInitialize(msg)
	case "initialized":
		// Notification — no response needed
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

	// Initialize each backend server
	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		// Forward initialize to each server
		if err := srv.Initialize(); err != nil {
			p.config.Logger.Warn("failed to initialize server %s: %v", name, err)
		}
	}

	// Return gateway's own capabilities
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
			"prompts":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": "0.1.0",
		},
	}

	resultJSON, _ := json.Marshal(result)
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  resultJSON,
	}, nil
}

func (p *Proxy) handleToolsList(msg JSONRPCMessage) (*JSONRPCMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var allTools []interface{}
	p.toolMap = make(map[string]string)

	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}

		tools, err := srv.ListTools()
		if err != nil {
			p.config.Logger.Warn("failed to list tools from %s: %v", name, err)
			continue
		}

		// Check for tool poisoning
		if p.config.DetectionEngine != nil {
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
				// Extract parameter descriptions
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
				p.config.Logger.LogDetection(name, "", r)
			}
		}

		// Namespace tool names and build toolMap
		for _, t := range tools {
			tm, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			originalName := fmt.Sprintf("%v", tm["name"])
			namespacedName := name + "__" + originalName
			tm["name"] = namespacedName
			p.toolMap[namespacedName] = name
			allTools = append(allTools, tm)
		}
	}

	// Add built-in gateway tools
	builtinTools := p.getBuiltinTools()
	allTools = append(allTools, builtinTools...)

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
	// Aggregate resources from all servers (with namespacing)
	var allResources []interface{}
	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		resources, err := srv.ListResources()
		if err != nil {
			continue
		}
		allResources = append(allResources, resources...)
	}
	result := map[string]interface{}{"resources": allResources}
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
	var allPrompts []interface{}
	for _, name := range p.manager.ServerNames() {
		srv := p.manager.Get(name)
		if srv == nil {
			continue
		}
		prompts, err := srv.ListPrompts()
		if err != nil {
			continue
		}
		allPrompts = append(allPrompts, prompts...)
	}
	result := map[string]interface{}{"prompts": allPrompts}
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
		text = fmt.Sprintf("AgentKeeper MCP Gateway\nMode: %s\nServers: %d connected (%s)\nDetection: active",
			mode, len(servers), strings.Join(servers, ", "))
	case "agentkeeper_audit":
		servers := p.manager.ServerNames()
		text = fmt.Sprintf("MCP Security Audit\nServers: %d\n", len(servers))
		for _, s := range servers {
			srv := p.manager.Get(s)
			if srv != nil {
				tools, _ := srv.ListTools()
				text += fmt.Sprintf("  %s: %d tools\n", s, len(tools))
			}
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
