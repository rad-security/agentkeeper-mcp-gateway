// Package server manages the lifecycle of registered MCP servers,
// including process spawning, health checking, and graceful shutdown.
package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
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
	config  ServerConfig
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	mu      sync.Mutex
	nextID  atomic.Int64
	pending map[int64]chan json.RawMessage
	pendMu  sync.Mutex
}

// Manager manages multiple MCP server processes.
type Manager struct {
	servers map[string]*Server
	configs []ServerConfig
	mu      sync.RWMutex
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
	for _, cfg := range m.configs {
		if cfg.Transport == "http" {
			// HTTP servers don't need to be spawned — they're remote
			m.mu.Lock()
			m.servers[cfg.Name] = &Server{
				config:  cfg,
				pending: make(map[int64]chan json.RawMessage),
			}
			m.mu.Unlock()
			continue
		}
		if err := m.startServer(cfg); err != nil {
			return fmt.Errorf("starting %s: %w", cfg.Name, err)
		}
	}
	return nil
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
		pending: make(map[int64]chan json.RawMessage),
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
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, srv := range m.servers {
		if srv.cmd != nil && srv.cmd.Process != nil {
			srv.stdin.Close()
			srv.cmd.Process.Kill()
		}
	}
}

// Initialize sends the initialize handshake to a server.
func (s *Server) Initialize() error {
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
	return nil
}

// ListTools calls tools/list on the server.
func (s *Server) ListTools() ([]interface{}, error) {
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

	ch := make(chan json.RawMessage, 1)
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

	// Wait for response (with timeout handled upstream)
	result := <-ch
	return result, nil
}

func (s *Server) sendNotification(method string, params json.RawMessage) {
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
				ch <- json.RawMessage(fmt.Sprintf(`{"error": "%s"}`, msg.Error.Message))
			} else {
				ch <- msg.Result
			}
		}
	}
}
