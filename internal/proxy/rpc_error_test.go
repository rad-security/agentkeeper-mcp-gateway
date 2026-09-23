package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
)

func TestUpstreamApplicationErrorIsReturnedWithOriginalFieldsAndReceipt(t *testing.T) {
	dispatches := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		switch request.Method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}})
		case "tools/call":
			dispatches++
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "error": map[string]interface{}{"code": -32042, "message": "synthetic quota exhausted", "data": map[string]interface{}{"retryAfter": 12}}})
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer backend.Close()
	store, err := receipt.NewStore(t.TempDir(), "native-fidelity-test")
	if err != nil {
		t.Fatal(err)
	}
	mgr := server.NewManager([]server.ServerConfig{{Name: "fixture", Transport: "http", URL: backend.URL}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	p := NewProxy(Config{ReceiptStore: store}, mgr, nil)
	defer p.Close()
	p.toolMap["fixture__lookup"] = "fixture"
	id := json.RawMessage(`"original-client-id"`)
	response, err := p.handleToolsCall(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "tools/call", Params: json.RawMessage(`{"name":"fixture__lookup","arguments":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32042 || response.Error.Message != "synthetic quota exhausted" || string(response.Error.Data) != `{"retryAfter":12}` || string(*response.ID) != string(id) {
		t.Fatalf("lost upstream error or client id: %+v", response)
	}
	if dispatches != 1 {
		t.Fatalf("dispatches=%d", dispatches)
	}
	rows, err := store.Peek(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("receipt count=%d", len(rows))
	}
	r := rows[0]
	if r.AppliedDisposition != "result_returned" || !r.Dispatched || !r.ResultReceived || !r.ResultReturned || r.FailureReason != "upstream_rpc_error" {
		t.Fatalf("receipt confuses application error with transport failure: %+v", r)
	}
}
