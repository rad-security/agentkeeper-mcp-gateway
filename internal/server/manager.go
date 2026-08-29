// Package server manages the lifecycle of registered MCP servers,
// including process spawning, health checking, and graceful shutdown.
package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	sessionMu       sync.RWMutex
	nextID          atomic.Int64
	pending         map[int64]chan rpcResponse
	pendMu          sync.Mutex
	notify          func(method string, params json.RawMessage)
	done            chan struct{}
	sseMu           sync.Mutex
	sseEndpoint     string
	sseBody         io.ReadCloser
	sseCancel       context.CancelFunc
	sseEndpointCh   chan string
	sseErrCh        chan error
}

type rpcResponse struct {
	result json.RawMessage
	err    error
}

// Manager manages multiple MCP server processes.
type Manager struct {
	servers             map[string]*Server
	configs             []ServerConfig
	mu                  sync.RWMutex
	startMu             sync.Mutex
	stopping            bool
	restartAttempts     map[string]int
	notificationHandler func(serverName, method string, params json.RawMessage)
	lifecycleHandler    func(serverName, state string, err error)
}

// NewManager creates a server manager from configs.
func NewManager(configs []ServerConfig) *Manager {
	return &Manager{
		servers:         make(map[string]*Server),
		configs:         configs,
		restartAttempts: make(map[string]int),
	}
}

// SetNotificationHandler forwards upstream MCP notifications such as progress
// to the connected client. The handler must be concurrency-safe.
func (m *Manager) SetNotificationHandler(handler func(serverName, method string, params json.RawMessage)) {
	m.mu.Lock()
	m.notificationHandler = handler
	for name, srv := range m.servers {
		srv.notify = m.serverNotifier(name)
	}
	m.mu.Unlock()
}

// SetLifecycleHandler reports backend availability changes to the proxy so it
// can remove stale capabilities before a dead process is restarted.
func (m *Manager) SetLifecycleHandler(handler func(serverName, state string, err error)) {
	m.mu.Lock()
	m.lifecycleHandler = handler
	m.mu.Unlock()
}

func (m *Manager) serverNotifier(name string) func(string, json.RawMessage) {
	return func(method string, params json.RawMessage) {
		m.mu.RLock()
		handler := m.notificationHandler
		m.mu.RUnlock()
		if handler != nil {
			handler(name, method, params)
		}
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
		if transport == "http" || transport == "sse" {
			if strings.TrimSpace(cfg.URL) == "" {
				fmt.Fprintf(os.Stderr, "[agentkeeper] skipping MCP server %s: empty URL for HTTP transport\n", cfg.Name)
				continue
			}
			cfg.Transport = transport
			// HTTP servers don't need to be spawned — they're remote
			m.mu.Lock()
			m.servers[cfg.Name] = &Server{
				config:        cfg,
				pending:       make(map[int64]chan rpcResponse),
				notify:        m.serverNotifier(cfg.Name),
				sseEndpointCh: make(chan string, 1),
				sseErrCh:      make(chan error, 1),
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
		notify:  m.serverNotifier(cfg.Name),
		done:    make(chan struct{}),
	}

	// Read responses and own cmd.Wait in background. Exactly one goroutine may
	// wait on an exec.Cmd; StopAll waits on srv.done instead.
	go srv.readResponses()

	m.mu.Lock()
	m.servers[cfg.Name] = srv
	m.mu.Unlock()
	go m.watchServer(cfg, srv)

	return nil
}

func (m *Manager) watchServer(cfg ServerConfig, srv *Server) {
	err := srv.cmd.Wait()
	close(srv.done)
	if err == nil {
		err = io.EOF
	}
	srv.failPending(err)

	m.mu.Lock()
	if current := m.servers[cfg.Name]; current == srv {
		delete(m.servers, cfg.Name)
	}
	stopping := m.stopping
	handler := m.lifecycleHandler
	m.mu.Unlock()
	if handler != nil {
		handler(cfg.Name, "degraded", err)
	}
	if !stopping {
		m.scheduleRestart(cfg, err)
	}
}

const maxRestartAttempts = 5

func (m *Manager) scheduleRestart(cfg ServerConfig, cause error) {
	m.mu.Lock()
	if m.stopping || !m.configuredLocked(cfg.Name) {
		m.mu.Unlock()
		return
	}
	m.restartAttempts[cfg.Name]++
	attempt := m.restartAttempts[cfg.Name]
	handler := m.lifecycleHandler
	m.mu.Unlock()
	if attempt > maxRestartAttempts {
		if handler != nil {
			handler(cfg.Name, "circuit_open", cause)
		}
		return
	}
	delay := 100 * time.Millisecond * time.Duration(1<<min(attempt-1, 5))
	if handler != nil {
		handler(cfg.Name, "restarting", cause)
	}
	time.AfterFunc(delay, func() {
		m.startMu.Lock()
		defer m.startMu.Unlock()
		m.mu.RLock()
		stopping := m.stopping
		configured := m.configuredLockedRead(cfg.Name)
		alreadyRunning := m.servers[cfg.Name] != nil
		m.mu.RUnlock()
		if stopping || !configured || alreadyRunning {
			return
		}
		if err := m.startServer(cfg); err != nil {
			m.scheduleRestart(cfg, err)
		}
	})
}

func (m *Manager) configuredLocked(name string) bool {
	for _, cfg := range m.configs {
		if cfg.Name == name {
			return true
		}
	}
	return false
}

func (m *Manager) configuredLockedRead(name string) bool {
	return m.configuredLocked(name)
}

// MarkHealthy resets the crash-loop budget after a successful MCP operation.
func (m *Manager) MarkHealthy(name string) {
	m.mu.Lock()
	m.restartAttempts[name] = 0
	handler := m.lifecycleHandler
	m.mu.Unlock()
	if handler != nil {
		handler(name, "ready", nil)
	}
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

// ConfiguredNames returns desired backends, including ones that are currently
// degraded or waiting for bounded restart.
func (m *Manager) ConfiguredNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.configs))
	for _, cfg := range m.configs {
		if cfg.Name != "" {
			names = append(names, cfg.Name)
		}
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
	m.stopping = true
	servers := make([]*Server, 0, len(m.servers))
	for _, srv := range m.servers {
		servers = append(servers, srv)
	}
	m.servers = make(map[string]*Server)
	m.mu.Unlock()
	for _, srv := range servers {
		srv.stop()
	}
}

func (s *Server) stop() {
	if s.IsSSE() {
		s.sseMu.Lock()
		if s.sseCancel != nil {
			s.sseCancel()
		}
		if s.sseBody != nil {
			_ = s.sseBody.Close()
		}
		s.sseMu.Unlock()
	}
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.stdin.Close()
	select {
	case <-s.done:
	case <-time.After(backendStopGracePeriod):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
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
	if s.IsSSE() {
		return s.ensureSSEInitializedContext(ctx)
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
	if s.IsSSE() {
		if method != "initialize" && !strings.HasPrefix(method, "notifications/") {
			if err := s.ensureSSEInitializedContext(ctx); err != nil {
				return nil, err
			}
		}
		return s.callSSEContext(ctx, method, params)
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
		s.sendCancellation(id, ctx.Err())
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
	if s.IsSSE() {
		s.sendSSENotification(method, params)
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

func (s *Server) IsSSE() bool {
	return normalizeTransport(s.config) == "sse"
}

func (s *Server) sendCancellation(id int64, cause error) {
	reason := "request cancelled"
	if cause != nil {
		reason = cause.Error()
	}
	params, _ := json.Marshal(map[string]interface{}{"requestId": id, "reason": reason})
	s.sendNotification("notifications/cancelled", params)
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

	result, err := s.postHTTPContext(ctx, msg, id, true, timeoutForMethod(method))
	if err != nil && ctx.Err() != nil {
		s.sendCancellation(id, ctx.Err())
	}
	return result, err
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
	s.sessionMu.RLock()
	sessionID := s.sessionID
	s.sessionMu.RUnlock()
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
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
		s.sessionMu.Lock()
		s.sessionID = sid
		s.sessionMu.Unlock()
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
		return readSSEResult(resp.Body, id, s.notify)
	}
	return readJSONRPCResult(resp.Body, id)
}

func (s *Server) ensureSSEInitializedContext(ctx context.Context) error {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initialized {
		return nil
	}
	if err := s.ensureSSEConnectedContext(ctx); err != nil {
		return err
	}
	params := map[string]interface{}{
		"protocolVersion": latestProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name": "agentkeeper-mcp-gateway", "version": "0.1.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)
	result, err := s.callSSEContext(ctx, "initialize", paramsJSON)
	if err != nil {
		return err
	}
	if err := s.recordInitializeResult(result); err != nil {
		return err
	}
	s.sendSSENotification("notifications/initialized", nil)
	s.initialized = true
	return nil
}

func (s *Server) ensureSSEConnectedContext(ctx context.Context) error {
	s.sseMu.Lock()
	if s.sseEndpoint != "" {
		s.sseMu.Unlock()
		return nil
	}
	if s.sseCancel != nil {
		endpointCh := s.sseEndpointCh
		errCh := s.sseErrCh
		s.sseMu.Unlock()
		return waitForSSEEndpoint(ctx, endpointCh, errCh)
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	s.sseCancel = cancel
	endpointCh := s.sseEndpointCh
	errCh := s.sseErrCh
	s.sseMu.Unlock()

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, s.config.URL, nil)
	if err != nil {
		s.resetSSEConnection(cancel, err)
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: backendDiscoveryTimeout}}
	resp, err := client.Do(req)
	if err != nil {
		s.resetSSEConnection(cancel, err)
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		err := fmt.Errorf("HTTP %d from %s", resp.StatusCode, s.config.URL)
		s.resetSSEConnection(cancel, err)
		return err
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		_ = resp.Body.Close()
		err := fmt.Errorf("legacy SSE endpoint %s returned %q", s.config.URL, resp.Header.Get("Content-Type"))
		s.resetSSEConnection(cancel, err)
		return err
	}
	s.sseMu.Lock()
	s.sseBody = resp.Body
	s.sseMu.Unlock()
	go s.readLegacySSE(resp.Body)
	return waitForSSEEndpoint(ctx, endpointCh, errCh)
}

func waitForSSEEndpoint(ctx context.Context, endpointCh <-chan string, errCh <-chan error) error {
	timer := time.NewTimer(backendDiscoveryTimeout)
	defer timer.Stop()
	select {
	case endpoint := <-endpointCh:
		if endpoint == "" {
			return errors.New("legacy SSE endpoint event was empty")
		}
		return nil
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("legacy SSE endpoint discovery timed out after %s", backendDiscoveryTimeout)
	}
}

func (s *Server) readLegacySSE(body io.Reader) {
	scanner := bufio.NewScanner(body)
	eventName := ""
	dataLines := make([]string, 0, 1)
	dispatch := func() {
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if strings.TrimSpace(data) == "" {
			eventName = ""
			return
		}
		switch eventName {
		case "endpoint":
			endpoint, err := resolveSSEEndpoint(s.config.URL, strings.TrimSpace(data))
			if err != nil {
				s.signalSSEError(err)
				return
			}
			s.sseMu.Lock()
			s.sseEndpoint = endpoint
			s.sseMu.Unlock()
			select {
			case s.sseEndpointCh <- endpoint:
			default:
			}
		default:
			s.dispatchRPCPayload([]byte(data))
		}
		eventName = ""
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			dispatch()
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	dispatch()
	err := scanner.Err()
	if err == nil {
		err = io.EOF
	}
	s.failPending(err)
	s.sseMu.Lock()
	errCh := s.sseErrCh
	if s.sseCancel != nil {
		s.sseCancel()
	}
	s.sseEndpoint = ""
	s.sseBody = nil
	s.sseCancel = nil
	s.sseEndpointCh = make(chan string, 1)
	s.sseErrCh = make(chan error, 1)
	s.sseMu.Unlock()
	s.initMu.Lock()
	s.initialized = false
	s.initMu.Unlock()
	select {
	case errCh <- err:
	default:
	}
}

func (s *Server) resetSSEConnection(cancel context.CancelFunc, cause error) {
	if cancel != nil {
		cancel()
	}
	s.sseMu.Lock()
	errCh := s.sseErrCh
	s.sseEndpoint = ""
	s.sseBody = nil
	s.sseCancel = nil
	s.sseEndpointCh = make(chan string, 1)
	s.sseErrCh = make(chan error, 1)
	s.sseMu.Unlock()
	if cause != nil {
		select {
		case errCh <- cause:
		default:
		}
	}
}

func resolveSSEEndpoint(baseURL, endpoint string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(reference)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported legacy SSE message endpoint %q", resolved.String())
	}
	return resolved.String(), nil
}

func (s *Server) signalSSEError(err error) {
	select {
	case s.sseErrCh <- err:
	default:
	}
}

func (s *Server) callSSEContext(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if err := s.ensureSSEConnectedContext(ctx); err != nil {
		return nil, err
	}
	id := s.nextID.Add(1)
	msg := map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}
	ch := make(chan rpcResponse, 1)
	s.pendMu.Lock()
	s.pending[id] = ch
	s.pendMu.Unlock()
	if err := s.postSSE(ctx, msg); err != nil {
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		return nil, err
	}
	timer := time.NewTimer(timeoutForMethod(method))
	defer timer.Stop()
	select {
	case response := <-ch:
		return response.result, response.err
	case <-ctx.Done():
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		s.sendCancellation(id, ctx.Err())
		return nil, ctx.Err()
	case <-timer.C:
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
		return nil, fmt.Errorf("%s timed out after %s", method, timeoutForMethod(method))
	}
}

func (s *Server) sendSSENotification(method string, params json.RawMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.ensureSSEConnectedContext(ctx); err != nil {
		return
	}
	msg := map[string]interface{}{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = json.RawMessage(params)
	}
	_ = s.postSSE(ctx, msg)
}

func (s *Server) postSSE(ctx context.Context, msg map[string]interface{}) error {
	s.sseMu.Lock()
	endpoint := s.sseEndpoint
	s.sseMu.Unlock()
	if endpoint == "" {
		return errors.New("legacy SSE message endpoint is unavailable")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}
	resp, err := (&http.Client{Timeout: backendDefaultTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
	}
	return nil
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

func readSSEResult(r io.Reader, id int64, notify func(string, json.RawMessage)) (json.RawMessage, error) {
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
		var envelope struct {
			ID     *int64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
			continue
		}
		if envelope.ID == nil && envelope.Method != "" {
			if notify != nil {
				notify(envelope.Method, envelope.Params)
			}
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
	case "http", "streamable-http":
		return "http"
	case "sse":
		return "sse"
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

		s.dispatchRPCPayload(line)
	}
}

func (s *Server) dispatchRPCPayload(payload []byte) {
	var msg struct {
		ID     *int64          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	if msg.ID == nil {
		if msg.Method != "" && s.notify != nil {
			s.notify(msg.Method, msg.Params)
		}
		return
	}
	s.pendMu.Lock()
	ch, ok := s.pending[*msg.ID]
	if ok {
		delete(s.pending, *msg.ID)
	}
	s.pendMu.Unlock()
	if !ok {
		return
	}
	if msg.Error != nil {
		ch <- rpcResponse{err: fmt.Errorf("%s", msg.Error.Message)}
		return
	}
	if msg.Result == nil {
		msg.Result = json.RawMessage(`{}`)
	}
	ch <- rpcResponse{result: msg.Result}
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
