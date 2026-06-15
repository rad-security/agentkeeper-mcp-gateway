package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStartAllSkipsInvalidServersAndKeepsHealthyHTTP(t *testing.T) {
	mgr := NewManager([]ServerConfig{
		{Name: "benchling", Transport: "stdio", Command: ""},
		{Name: "remote", Transport: "http", URL: "https://mcp.example.test"},
	})

	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	names := mgr.ServerNames()
	if len(names) != 1 || names[0] != "remote" {
		t.Fatalf("expected only healthy HTTP server to be registered, got %v", names)
	}
	if srv := mgr.Get("benchling"); srv != nil {
		t.Fatalf("invalid stdio server was registered: %+v", srv)
	}
}

func TestHTTPServerInitializeAndListTools(t *testing.T) {
	var sawAuth bool
	var sawSession bool
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test" {
			sawAuth = true
		}
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "session-1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"capabilities": map[string]any{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") == "session-1" {
				sawSession = true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{{
						"name":        "search",
						"description": "Search docs",
					}},
				},
			})
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{
		Name:      "remote",
		Transport: "http",
		URL:       httpSrv.URL,
		Headers:   map[string]string{"Authorization": "Bearer test"},
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	srv := mgr.Get("remote")
	if srv == nil {
		t.Fatal("remote server was not registered")
	}
	if err := srv.Initialize(); err != nil {
		t.Fatal(err)
	}
	tools, err := srv.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected one tool, got %+v", tools)
	}
	if !sawAuth {
		t.Fatal("configured HTTP header was not forwarded")
	}
	if !sawSession {
		t.Fatal("MCP session header from initialize was not reused")
	}
}

func TestHTTPServerListToolsLazyInitializes(t *testing.T) {
	var methods []string
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, req.Method)
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "session-1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"capabilities": map[string]any{}},
			})
		case "notifications/initialized":
			if req.ID != 0 {
				t.Fatalf("notification unexpectedly had id %d", req.ID)
			}
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != "session-1" {
				t.Fatalf("tools/list did not reuse session header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"tools": []map[string]any{{"name": "search"}}},
			})
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{
		Name:      "remote",
		Transport: "http",
		URL:       httpSrv.URL,
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	tools, err := mgr.Get("remote").ListTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected one tool, got %+v", tools)
	}
	want := []string{"initialize", "notifications/initialized", "tools/list"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
}

func TestHTTPServerParsesSSEToolList(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"capabilities": map[string]any{}},
			})
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		payload := `{"jsonrpc":"2.0","id":` + strconv.FormatInt(req.ID, 10) + `,"result":{"tools":[{"name":"lookup"}]}}`
		_, _ = w.Write([]byte("event: message\n"))
		_, _ = w.Write([]byte("data: " + payload + "\n\n"))
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{
		Name:      "remote",
		Transport: "streamable-http",
		URL:       httpSrv.URL,
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	tools, err := mgr.Get("remote").ListTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || !strings.Contains(tools[0].(map[string]any)["name"].(string), "lookup") {
		t.Fatalf("unexpected SSE tools: %+v", tools)
	}
}

func TestHTTPServerReturnsJSONRPCResultOnHTTPUnauthorized(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"capabilities": map[string]any{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/call":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/search"`)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{{
						"type": "text",
						"text": "Request is missing required authentication credential.",
					}},
					"isError": true,
				},
			})
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{
		Name:      "remote",
		Transport: "http",
		URL:       httpSrv.URL,
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"name":"search","arguments":{"query":"x"}}`)
	result, err := mgr.Get("remote").Call("tools/call", params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "missing required authentication") || !strings.Contains(string(result), `"isError":true`) {
		t.Fatalf("expected auth failure tool result, got %s", result)
	}
}

func TestStdioServerInitializeTimesOut(t *testing.T) {
	mgr := NewManager([]ServerConfig{{
		Name:    "hung",
		Command: "sh",
		Args:    []string{"-c", "sleep 30"},
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()

	started := time.Now()
	err := mgr.Get("hung").Initialize()
	if err == nil {
		t.Fatal("expected initialize timeout")
	}
	if elapsed := time.Since(started); elapsed > 22*time.Second {
		t.Fatalf("initialize took too long to fail: %s", elapsed)
	}
	if !strings.Contains(err.Error(), "initialize timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiscoveryTimeoutsTolerateSlowEnterpriseBackends(t *testing.T) {
	if got := timeoutForMethod("initialize"); got != backendDiscoveryTimeout {
		t.Fatalf("initialize timeout = %s, want %s", got, backendDiscoveryTimeout)
	}
	if got := timeoutForMethod("tools/list"); got != backendDiscoveryTimeout {
		t.Fatalf("tools/list timeout = %s, want %s", got, backendDiscoveryTimeout)
	}
	if backendDiscoveryTimeout < 20*time.Second {
		t.Fatalf("discovery timeout regressed below enterprise backend floor: %s", backendDiscoveryTimeout)
	}
}
