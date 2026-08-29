package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLegacySSETransportUsesEndpointStreamAndForwardsProgress(t *testing.T) {
	responses := make(chan []byte, 16)
	var streamReady sync.Once
	ready := make(chan struct{})
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("test server does not support flushing")
			}
			_, _ = io.WriteString(w, "event: endpoint\ndata: /messages\n\n")
			flusher.Flush()
			streamReady.Do(func() { close(ready) })
			for {
				select {
				case payload := <-responses:
					_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					flusher.Flush()
				case <-r.Context().Done():
					return
				}
			}
		}
		if r.Method != http.MethodPost || r.URL.Path != "/messages" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			ID     *int64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if request.ID == nil {
			return
		}
		var result interface{}
		switch request.Method {
		case "initialize":
			result = map[string]interface{}{"protocolVersion": latestProtocolVersion, "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}
		case "tools/list":
			result = map[string]interface{}{"tools": []map[string]interface{}{{"name": "lookup"}}}
		case "tools/call":
			progress, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]interface{}{"progress": 1, "total": 1}})
			responses <- progress
			result = map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "ok"}}}
		default:
			result = map[string]interface{}{}
		}
		response, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": *request.ID, "result": result})
		responses <- response
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{Name: "legacy", Transport: "sse", URL: httpSrv.URL + "/sse"}})
	progress := make(chan json.RawMessage, 1)
	mgr.SetNotificationHandler(func(_ string, method string, params json.RawMessage) {
		if method == "notifications/progress" {
			progress <- params
		}
	})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	srv := mgr.Get("legacy")
	tools, err := srv.ListTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].(map[string]interface{})["name"] != "lookup" {
		t.Fatalf("unexpected legacy SSE tools: %+v", tools)
	}
	select {
	case <-ready:
	default:
		t.Fatal("legacy SSE GET stream never connected")
	}
	if _, err := srv.Call("tools/call", json.RawMessage(`{"name":"lookup","arguments":{}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case params := <-progress:
		if !strings.Contains(string(params), `"progress":1`) {
			t.Fatalf("unexpected progress params: %s", params)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy SSE progress notification was not forwarded")
	}
}

func TestStdioCancellationIsForwardedUpstream(t *testing.T) {
	reader, writer := io.Pipe()
	srv := &Server{
		config:  ServerConfig{Name: "slow"},
		stdin:   writer,
		pending: make(map[int64]chan rpcResponse),
	}
	cancelled := make(chan map[string]interface{}, 1)
	go func() {
		decoder := json.NewDecoder(bufio.NewReader(reader))
		var call map[string]interface{}
		if err := decoder.Decode(&call); err != nil {
			return
		}
		var notification map[string]interface{}
		if err := decoder.Decode(&notification); err != nil {
			return
		}
		cancelled <- notification
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := srv.CallContext(ctx, "tools/call", json.RawMessage(`{"name":"slow"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("call error = %v, want deadline exceeded", err)
	}
	select {
	case notification := <-cancelled:
		if notification["method"] != "notifications/cancelled" {
			t.Fatalf("upstream notification = %+v", notification)
		}
		params := notification["params"].(map[string]interface{})
		if params["requestId"] != float64(1) {
			t.Fatalf("upstream cancellation did not reference request 1: %+v", notification)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream cancellation notification was not written")
	}
}

func TestCrashedStdioBackendIsRemovedAndRestarted(t *testing.T) {
	dir := t.TempDir()
	countPath := filepath.Join(dir, "starts")
	scriptPath := filepath.Join(dir, "backend.sh")
	script := "#!/bin/sh\nprintf x >> \"$1\"\nif [ \"$(wc -c < \"$1\")\" -eq 1 ]; then exit 17; fi\nwhile IFS= read -r line; do :; done\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager([]ServerConfig{{Name: "restartable", Command: scriptPath, Args: []string{countPath}}})
	states := make(chan string, 8)
	mgr.SetLifecycleHandler(func(_ string, state string, _ error) { states <- state })
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(countPath)
		if len(data) >= 2 && mgr.Get("restartable") != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	data, _ := os.ReadFile(countPath)
	if len(data) < 2 || mgr.Get("restartable") == nil {
		t.Fatalf("backend was not restarted: starts=%d active=%v", len(data), mgr.Get("restartable") != nil)
	}
	seenDegraded, seenRestarting := false, false
	for len(states) > 0 {
		switch <-states {
		case "degraded":
			seenDegraded = true
		case "restarting":
			seenRestarting = true
		}
	}
	if !seenDegraded || !seenRestarting {
		t.Fatalf("lifecycle did not report removal and restart: degraded=%v restarting=%v", seenDegraded, seenRestarting)
	}
}

func TestStartServerPreservesExecutablePathContainingSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "MCP Server With Spaces")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(dir, "harmless backend")
	if err := os.WriteFile(backend, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager([]ServerConfig{{Name: "space-path", Command: backend}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	srv := mgr.Get("space-path")
	if srv == nil || srv.cmd == nil {
		t.Fatal("server with a valid executable path containing spaces was not started")
	}
	if srv.cmd.Path != backend {
		t.Fatalf("command path = %q, want exact %q", srv.cmd.Path, backend)
	}
}

func TestResolveCommandRetainsLegacyPATHCommandString(t *testing.T) {
	command, args, err := resolveCommand(ServerConfig{Name: "legacy", Command: "sh -c", Args: []string{"exit 0"}})
	if err != nil {
		t.Fatal(err)
	}
	if command != "sh" || strings.Join(args, "|") != "-c|exit 0" {
		t.Fatalf("legacy command resolved as command=%q args=%v", command, args)
	}
}

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
	var sawProtocol bool
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
				"result":  map[string]any{"protocolVersion": latestProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") == "session-1" {
				sawSession = true
			}
			if r.Header.Get("MCP-Protocol-Version") == latestProtocolVersion {
				sawProtocol = true
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
	if !sawProtocol {
		t.Fatal("negotiated MCP protocol header was not sent after initialize")
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
				"result":  map[string]any{"protocolVersion": latestProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}},
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
				"result":  map[string]any{"protocolVersion": latestProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}},
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
				"result":  map[string]any{"protocolVersion": latestProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}},
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

func TestExplicitCapabilitiesSkipUnsupportedResourceMethod(t *testing.T) {
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": latestProtocolVersion,
					"capabilities":    map[string]any{"tools": map[string]any{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unsupported method was called: %s", req.Method)
		}
	}))
	defer httpSrv.Close()

	mgr := NewManager([]ServerConfig{{Name: "tools-only", Transport: "http", URL: httpSrv.URL}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	resources, err := mgr.Get("tools-only").ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 0 || time.Since(started) > time.Second {
		t.Fatalf("unsupported resource list did not return immediately: resources=%v elapsed=%s", resources, time.Since(started))
	}
	if strings.Join(methods, ",") != "initialize,notifications/initialized" {
		t.Fatalf("methods = %v", methods)
	}
}

func TestResourceTemplatesUseDeclaredResourceCapability(t *testing.T) {
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
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
				"protocolVersion": latestProtocolVersion,
				"capabilities":    map[string]any{"resources": map[string]any{}},
			}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/templates/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
				"resourceTemplates": []map[string]any{{"name": "record", "uriTemplate": "qa://records/{id}"}},
			}})
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer httpSrv.Close()
	mgr := NewManager([]ServerConfig{{Name: "resources", Transport: "http", URL: httpSrv.URL}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	templates, err := mgr.Get("resources").ListResourceTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 1 {
		t.Fatalf("templates = %+v", templates)
	}
}

func TestContextCancellationStopsPendingDiscovery(t *testing.T) {
	mgr := NewManager([]ServerConfig{{Name: "hung", Command: "sh", Args: []string{"-c", `while IFS= read -r line; do case "$line" in *\"method\":\"initialize\"*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}}}}' ;; *\"method\":\"resources/list\"*) sleep 30 ;; esac; done`}}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := mgr.Get("hung").ListResourcesContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("cancellation took too long: %s", time.Since(started))
	}
}
