package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
)

// A tool that ran and then reported an error is recorded as having reached
// the server with an error result, since it may have made a change first.
func TestToolErrorResultIsRecorded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     *json.RawMessage       `json:"id"`
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}})
		case "tools/call":
			result := map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "ok"}}}
			if req.Params["name"] == "commit_then_fail" {
				result = map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "committed, then failed"}}, "isError": true}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(backend.Close)
	mgr := server.NewManager([]server.ServerConfig{{Name: "fixture", Transport: "http", URL: backend.URL}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.StopAll)
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := logging.NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := NewProxy(Config{Logger: logger}, mgr, nil)
	t.Cleanup(p.Close)
	p.mu.Lock()
	p.toolMap = map[string]string{"fixture__commit_then_fail": "fixture", "fixture__lookup": "fixture"}
	p.mu.Unlock()

	callTool(t, p, 1, "fixture__commit_then_fail", map[string]interface{}{})
	callTool(t, p, 2, "fixture__lookup", map[string]interface{}{})

	byTool := map[string]map[string]interface{}{}
	for _, e := range readEvents(t, logPath) {
		if e["event_type"] == "mcp.tool_call" {
			ctx, _ := e["context"].(map[string]interface{})
			byTool[e["tool_name"].(string)] = ctx
		}
	}
	if ctx := byTool["commit_then_fail"]; ctx == nil || ctx["result_is_error"] != true || ctx["applied_disposition"] != "result_returned" {
		t.Fatalf("error result not recorded: %+v", ctx)
	}
	if ctx := byTool["lookup"]; ctx == nil || ctx["result_is_error"] != nil {
		t.Fatalf("successful result recorded as an error: %+v", ctx)
	}
}
