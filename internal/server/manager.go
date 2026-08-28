// Package server manages the lifecycle of registered MCP servers,
// including process spawning, health checking, and graceful shutdown.
package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	latestProtocolVersion   = "2025-11-25"
	backendDiscoveryTimeout = 20 * time.Second
	backendCallTimeout      = 60 * time.Second
	backendDefaultTimeout   = 8 * time.Second
	backendStopGracePeriod  = 2 * time.Second
)

// ServerConfig defines a backend MCP server.
type ServerConfig struct {
	Name      string            `json:"name"`
	Command   string            `json:"command"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Transport string            `json:"transport,omitempty"` // "stdio" (default) or "http"
	URL       string            `json:"url,omitempty"`       // for HTTP transport
	Headers   map[string]string `json:"headers,omitempty"`   // for HTTP transport
}

// Server represents a running MCP server process.
type Server struct {
	config          ServerConfig
	cmd             *exec.Cmd
	stdin           io.WriteCloser
	stdout          *bufio.Reader
	mu              sync.Mutex
	initMu          sync.Mutex
	initialized     bool
	capMu           sync.RWMutex
	capKnown        bool
	capabilities    map[string]bool
	protocolVersion string
	sessionID       string
	nextID          atomic.Int64
	pending         map[int64]chan rpcResponse
	pendMu          sync.Mutex
}

type rpcResponse struct {
	result json.RawMessage
	err    error
}

// Manager manages multiple MCP server processes.
type Manager struct {
	servers map[string]*Server
	configs []ServerConfig
	mu      sync.RWMutex
	startMu sync.Mutex
}

// NewManager creates a server manager from configs.
func NewManager(configs []ServerConfig) *Manager {
	return &Manager{
		servers: make(map[string]*Server),
		configs: configs,
	}
}

// StartAll starts all configured servers.
func (m *Manager) StartAll() error {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	m.mu.RLock()
	configs := append([]ServerConfig(nil), m.configs...)
	m.mu.RUnlock()

	for _, cfg := range configs {
		if cfg.Name == "" {
			fmt.Fprintln(os.Stderr, "[agentkeeper] skipping MCP server with empty name")
			continue
		}
		if m.Get(cfg.Name) != nil {
			continue
		}
		transport := normalizeTransport(cfg)
		if transport == "http" {
			if strings.TrimSpace(cfg.URL) == "" {
				fmt.Fprintf(os.Stderr, "[agentkeeper] skipping MCP server %s: empty URL for HTTP transport\n", cfg.Name)
				continue
			}
			cfg.Transport = "http"
			// HTTP servers don't need to be spawned — they're remote
			m.mu.Lock()
			m.servers[cfg.Name] = &Server{
				config:  cfg,
				pending: make(map[int64]chan rpcResponse),
			}
			m.mu.Unlock()
			continue
		}
		if strings.TrimSpace(cfg.Command) == "" {
			fmt.Fprintf(os.Stderr, "[agentkeeper] skipping MCP server %s: empty command\n", cfg.Name)
			continue
		}
		if err := m.startServer(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[agentkeeper] skipping MCP server %s: %v\n", cfg.Name, err)
			continue
		}
	}
	return nil
}

// UpdateConfigs replaces the desired backend set. Existing live servers are
// retained; StartAll will attach any newly discovered backends.
func (m *Manager) UpdateConfigs(configs []ServerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs = append([]ServerConfig(nil), configs...)
}

func (m *Manager) startServer(cfg ServerConfig) error {
	command, args, err := resolveCommand(cfg)
	if err != nil {
		return err
	}
	cmd := exec.Command(command, args...)

	// Set environment
	if len(cfg.Env) > 0 {
		env := cmd.Environ()
		for k, v := range cfg.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", cfg.Name, err)
	}

	srv := &Server{
		config:  cfg,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  bufio.NewReader(stdout),
		pending: make(map[int64]chan rpcResponse),
	}

	// Read responses in background
	go srv.readResponses()

	m.mu.Lock()
	m.servers[cfg.Name] = srv
	m.mu.Unlock()

	return nil
}

// resolveCommand treats command and args as structured fields. Existing
// executable paths are always used byte-for-byte, including paths containing
// spaces. A narrow compatibility fallback retains historical command strings
// such as "npx -y package" only when their first token resolves on PATH.
func resolveCommand(cfg ServerConfig) (string, []string, error) {
	command := strings.TrimSpace(cfg.Command)
	if command == "" {
		return "", nil, fmt.Errorf("empty command for server %s", cfg.Name)
	}
	args := append([]string(nil), cfg.Args...)
	if info, err := os.Stat(command); err == nil && !info.IsDir() {
		return command, args, nil
	}
	if _, err := exec.LookPath(command); err == nil {
		return command, args, nil
	}
	parts := strings.Fields(command)
	if len(parts) > 1 {
		firstIsExecutable := false
		if info, err := os.Stat(parts[0]); err == nil && !info.IsDir() {
			firstIsExecutable = true
		} else if _, err := exec.LookPath(parts[0]); err == nil {
			firstIsExecutable = true
		}
		if firstIsExecutable {
			return parts[0], append(parts[1:], args...), nil
		}
	}
	// Paths must remain atomic even when they do not exist so the resulting
	// error names the real configured path instead of a truncated first token.
	if filepath.IsAbs(command) || strings.ContainsAny(command, `/\\`) {
		return command, args, nil
	}
	return command, args, nil
}

// ServerNames returns the names of all configured servers.
func (m *Manager) ServerNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.servers))
	for name := range m.servers {
		names = append(names, name)
	}
	return names
}

// Get returns a server by name.
func (m *Manager) Get(name string) *Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.servers[name]
}

// StopAll stops all servers.
func (m *Manager) StopAll() {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, srv := range m.servers {
		if srv.cmd != nil && srv.cmd.Process != nil {
			_ = srv.stdin.Close()
			done := make(chan struct{})
			go func(cmd *exec.Cmd) {
				_ = cmd.Wait()
				close(done)
			}(srv.cmd)
			select {
			case <-done:
			case <-time.After(backendStopGracePeriod):
				_ = srv.cmd.Process.Kill()
				<-done
			}
		}
	}
	m.servers = make(map[string]*Server)
}

// Initialize sends the initialize handshake to a server.
func (s *Server) Initialize() error {
	return s.InitializeContext(context.Background())
}

// InitializeContext performs the MCP handshake with cancellation support.
func (s *Server) InitializeContext(ctx context.Context) error {
	if s.IsHTTP() {
		return s.ensureHTTPInitializedContext(ctx)
	}

	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return nil
	}

	params := map[string]interface{}{
		"protocolVersion": latestProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": "0.1.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)
	result, err := s.CallContext(ctx, "initialize", paramsJSON)
	if err != nil {
		return err
	}
	if err := s.recordInitializeResult(result); err != nil {
		return err
	}
	// Send initialized notification
	s.sendNotification("notifications/initialized", nil)
	s.initialized = true
	return nil
}

// ListTools calls tools/list on the server.
func (s *Server) ListTools() ([]interface{}, error) {
	return s.ListToolsContext(context.Background())
}

func (s *Server) ListToolsContext(ctx context.Context) ([]interface{}, error) {
	if err := s.InitializeContext(ctx); err != nil {
		return nil, err
	}
	if !s.SupportsCapability("tools") {
		return []interface{}{}, nil
	}
	resp, err := s.CallContext(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Tools []interface{} `json:"tools"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ListResources calls resources/list on the server.
func (s *Server) ListResources() ([]interface{}, error) {
	return s.ListResourcesContext(context.Background())
}

func (s *Server) ListResourcesContext(ctx context.Context) ([]interface{}, error) {
	if err := s.InitializeContext(ctx); err != nil {
		return nil, err
	}
	if !s.SupportsCapability("resources") {
		return []interface{}{}, nil
	}
	resp, err := s.CallContext(ctx, "resources/list", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Resources []interface{} `json:"resources"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	return result.Resources, nil
}

// ListResourceTemplates calls resources/templates/list only for backends that
// declared the resources capability during initialization.
func (s *Server) ListResourceTemplates() ([]interface{}, error) {
	return s.ListResourceTemplatesContext(context.Background())
}

func (s *Server) ListResourceTemplatesContext(ctx context.Context) ([]interface{}, error) {
	if err := s.InitializeContext(ctx); err != nil {
		return nil, err
	}
	if !s.SupportsCapability("resources") {
		return []interface{}{}, nil
	}
	resp, err := s.CallContext(ctx, "resources/templates/list", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		ResourceTemplates []interface{} `json:"resourceTemplates"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	return result.ResourceTemplates, nil
}

// ListPrompts calls prompts/list on the server.
func (s *Server) ListPrompts() ([]interface{}, error) {
	return s.ListPromptsContext(context.Background())
}

func (s *Server) ListPromptsContext(ctx context.Context) ([]interface{}, error) {
	if err := s.InitializeContext(ctx); err != nil {
		return nil, err
	}
	if !s.SupportsCapability("prompts") {
		return []interface{}{}, nil
	}
	resp, err := s.CallContext(ctx, "prompts/list", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Prompts []interface{} `json:"prompts"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	return result.Prompts, nil
}

// Call sends a JSON-RPC request and waits for the response.
func (s *Server) Call(method string, params json.RawMessage) (json.RawMessage, error) {
	return s.CallContext(context.Background(), method, params)
}

// CallContext sends a JSON-RPC request and lets proxy shutdown cancel pending
// discovery work instead of racing a closed backend pipe.
func (s *Server) CallContext(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if s.IsHTTP() {
		if method != "initialize" && !strings.HasPrefix(method, "notifications/") {
			if err := s.ensureHTTPInitializedContext(ctx); err != nil {
				return nil, err
			}
		}
		return s.callHTTPContext(ctx, method, params)
	}

	s.mu.Lock()
	id := s.nextID.Add(1)

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}

	ch := make(chan rpcResponse, 1)
	s.pendMu.Lock()
	s.pending[id] = ch
	s.pendMu.Unlock()

	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	_, err := s.stdin.Write(data)
	s.mu.Unlock()

	if err != nil {
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		return nil, err
	}

	timer := time.NewTimer(timeoutForMethod(method))
	defer timer.Stop()
	select {
	case resp := <-ch:
		if resp.err != nil {
			return nil, resp.err
		}
		return resp.result, nil
	case <-ctx.Done():
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		return nil, ctx.Err()
	case <-timer.C:
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		return nil, fmt.Errorf("%s timed out after %s", method, timeoutForMethod(method))
	}
}

func (s *Server) sendNotification(method string, params json.RawMessage) {
	if s.IsHTTP() {
		s.sendHTTPNotification(method, params)
		return
	}

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}
	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	s.mu.Lock()
	s.stdin.Write(data)
	s.mu.Unlock()
}

// Notify forwards a client notification to this upstream MCP server.
func (s *Server) Notify(method string, params json.RawMessage) {
	s.sendNotification(method, params)
}

func (s *Server) IsHTTP() bool {
	return normalizeTransport(s.config) == "http"
}

func (s *Server) ensureHTTPInitialized() error {
	return s.ensureHTTPInitializedContext(context.Background())
}

func (s *Server) ensureHTTPInitializedContext(ctx context.Context) error {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return nil
	}
	params := map[string]interface{}{
		"protocolVersion": latestProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": "0.1.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)
	result, err := s.callHTTPContext(ctx, "initialize", paramsJSON)
	if err != nil {
		return err
	}
	if err := s.recordInitializeResult(result); err != nil {
		return err
	}
	s.sendHTTPNotification("notifications/initialized", nil)
	s.initialized = true
	return nil
}

func (s *Server) callHTTP(method string, params json.RawMessage) (json.RawMessage, error) {
	return s.callHTTPContext(context.Background(), method, params)
}

func (s *Server) callHTTPContext(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	id := s.nextID.Add(1)
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}

	return s.postHTTPContext(ctx, msg, id, true, timeoutForMethod(method))
}

func (s *Server) sendHTTPNotification(method string, params json.RawMessage) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}
	_, _ = s.postHTTP(msg, 0, false, 2*time.Second)
}

func (s *Server) postHTTP(msg map[string]interface{}, id int64, expectResult bool, timeout time.Duration) (json.RawMessage, error) {
	return s.postHTTPContext(context.Background(), msg, id, expectResult, timeout)
}

func (s *Server) postHTTPContext(ctx context.Context, msg map[string]interface{}, id int64, expectResult bool, timeout time.Duration) (json.RawMessage, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	if protocolVersion := s.negotiatedProtocolVersion(); protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", protocolVersion)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		s.sessionID = sid
	}
	if !expectResult || resp.StatusCode == http.StatusAccepted {
		return json.RawMessage(`{}`), nil
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if strings.Contains(contentType, "application/json") {
			if result, err := readJSONRPCResult(resp.Body, id); err == nil {
				return result, nil
			}
		}
		if challenge := strings.TrimSpace(resp.Header.Get("WWW-Authenticate")); challenge != "" {
			return nil, fmt.Errorf("HTTP %d from %s (%s)", resp.StatusCode, s.config.URL, challenge)
		}
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, s.config.URL)
	}
	if strings.Contains(contentType, "text/event-stream") {
		return readSSEResult(resp.Body, id)
	}
	return readJSONRPCResult(resp.Body, id)
}

// SupportsCapability reports the upstream capability observed during the
// initialize handshake. Missing capability metadata remains compatible with
// legacy backends; an explicit capabilities object is authoritative.
func (s *Server) SupportsCapability(name string) bool {
	s.capMu.RLock()
	defer s.capMu.RUnlock()
	if !s.capKnown {
		return true
	}
	return s.capabilities[name]
}

func (s *Server) negotiatedProtocolVersion() string {
	s.capMu.RLock()
	defer s.capMu.RUnlock()
	return s.protocolVersion
}

func (s *Server) recordInitializeResult(result json.RawMessage) error {
	var initialized struct {
		ProtocolVersion string                      `json:"protocolVersion"`
		Capabilities    *map[string]json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(result, &initialized); err != nil {
		return fmt.Errorf("decoding initialize result: %w", err)
	}
	capabilities := make(map[string]bool)
	known := initialized.Capabilities != nil
	if initialized.Capabilities != nil {
		for name, raw := range *initialized.Capabilities {
			if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
				capabilities[name] = true
			}
		}
	}
	s.capMu.Lock()
	s.capKnown = known
	s.capabilities = capabilities
	s.protocolVersion = strings.TrimSpace(initialized.ProtocolVersion)
	s.capMu.Unlock()
	return nil
}

func timeoutForMethod(method string) time.Duration {
	switch method {
	case "initialize", "tools/list", "resources/list", "prompts/list":
		return backendDiscoveryTimeout
	case "tools/call":
		return backendCallTimeout
	default:
		return backendDefaultTimeout
	}
}

func readJSONRPCResult(r io.Reader, id int64) (json.RawMessage, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return parseJSONRPCResult(data, id)
}

func readSSEResult(r io.Reader, id int64) (json.RawMessage, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		result, err := parseJSONRPCResult([]byte(payload), id)
		if err == nil {
			return result, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no JSON-RPC response for id %d in SSE stream", id)
}

func parseJSONRPCResult(data []byte, id int64) (json.RawMessage, error) {
	var msg struct {
		ID     *int64          `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg.ID != nil && *msg.ID != id {
		return nil, fmt.Errorf("unexpected JSON-RPC response id %d, want %d", *msg.ID, id)
	}
	if msg.Error != nil {
		return nil, fmt.Errorf("%s", msg.Error.Message)
	}
	if msg.Result == nil {
		return json.RawMessage(`{}`), nil
	}
	return msg.Result, nil
}

func normalizeTransport(cfg ServerConfig) string {
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	switch transport {
	case "http", "sse", "streamable-http":
		return "http"
	case "":
		if strings.TrimSpace(cfg.URL) != "" {
			return "http"
		}
		return "stdio"
	default:
		return transport
	}
}

func (s *Server) readResponses() {
	defer s.failPending(io.EOF)
	for {
		line, err := s.stdout.ReadBytes('\n')
		if err != nil {
			return
		}

		var msg struct {
			ID     *int64          `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		if msg.ID == nil {
			// Notification from server — ignore for now
			continue
		}

		s.pendMu.Lock()
		ch, ok := s.pending[*msg.ID]
		if ok {
			delete(s.pending, *msg.ID)
		}
		s.pendMu.Unlock()

		if ok {
			if msg.Error != nil {
				ch <- rpcResponse{err: fmt.Errorf("%s", msg.Error.Message)}
			} else {
				if msg.Result == nil {
					msg.Result = json.RawMessage(`{}`)
				}
				ch <- rpcResponse{result: msg.Result}
			}
		}
	}
}

func (s *Server) failPending(err error) {
	s.pendMu.Lock()
	pending := s.pending
	s.pending = make(map[int64]chan rpcResponse)
	s.pendMu.Unlock()
	for _, ch := range pending {
		ch <- rpcResponse{err: err}
	}
}
