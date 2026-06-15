// Package server manages the lifecycle of registered MCP servers,
// including process spawning, health checking, and graceful shutdown.
package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
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
	config      ServerConfig
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      *bufio.Reader
	mu          sync.Mutex
	initMu      sync.Mutex
	initialized bool
	sessionID   string
	nextID      atomic.Int64
	pending     map[int64]chan rpcResponse
	pendMu      sync.Mutex
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
	// Parse command — could be "npx -y @modelcontextprotocol/server-github"
	parts := strings.Fields(cfg.Command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command for server %s", cfg.Name)
	}

	args := append(parts[1:], cfg.Args...)
	cmd := exec.Command(parts[0], args...)

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
	if s.IsHTTP() {
		return s.ensureHTTPInitialized()
	}

	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return nil
	}

	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": "0.1.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)
	_, err := s.Call("initialize", paramsJSON)
	if err != nil {
		return err
	}
	// Send initialized notification
	s.sendNotification("notifications/initialized", nil)
	s.initialized = true
	return nil
}

// ListTools calls tools/list on the server.
func (s *Server) ListTools() ([]interface{}, error) {
	if err := s.Initialize(); err != nil {
		return nil, err
	}
	resp, err := s.Call("tools/list", nil)
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
	if err := s.Initialize(); err != nil {
		return nil, err
	}
	resp, err := s.Call("resources/list", nil)
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

// ListPrompts calls prompts/list on the server.
func (s *Server) ListPrompts() ([]interface{}, error) {
	if err := s.Initialize(); err != nil {
		return nil, err
	}
	resp, err := s.Call("prompts/list", nil)
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
	if s.IsHTTP() {
		if method != "initialize" && !strings.HasPrefix(method, "notifications/") {
			if err := s.ensureHTTPInitialized(); err != nil {
				return nil, err
			}
		}
		return s.callHTTP(method, params)
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

	select {
	case resp := <-ch:
		if resp.err != nil {
			return nil, resp.err
		}
		return resp.result, nil
	case <-time.After(timeoutForMethod(method)):
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

func (s *Server) IsHTTP() bool {
	return normalizeTransport(s.config) == "http"
}

func (s *Server) ensureHTTPInitialized() error {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return nil
	}
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "agentkeeper-mcp-gateway",
			"version": "0.1.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)
	if _, err := s.callHTTP("initialize", paramsJSON); err != nil {
		return err
	}
	s.sendHTTPNotification("notifications/initialized", nil)
	s.initialized = true
	return nil
}

func (s *Server) callHTTP(method string, params json.RawMessage) (json.RawMessage, error) {
	id := s.nextID.Add(1)
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}

	return s.postHTTP(msg, id, true, timeoutForMethod(method))
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
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, s.config.URL, bytes.NewReader(data))
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
