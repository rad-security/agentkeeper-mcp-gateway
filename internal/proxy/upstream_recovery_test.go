package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
)

// A routed tool whose stdio upstream exited is served by an on-demand restart,
// whether the call still finds the stale route (restart at dispatch) or the
// lifecycle update already removed it (restart and re-list).
func TestRoutedCallRestartsExitedStdioUpstreamOnDemand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := filepath.Join(dir, "backend.sh")
	// Replies with the request's own id so either recovery path (dispatch-time
	// restart, or re-list after the lifecycle update removed the route) works.
	body := `#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *die*) exit 0 ;;
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"RESTARTED_OK"}]}}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := receipt.NewStore(filepath.Join(dir, "receipts"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	mgr := server.NewManager([]server.ServerConfig{{Name: "fixture", Command: script}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	p := NewProxy(Config{ReceiptStore: store, GatewayVersion: "0.2.0-test"}, mgr, nil)
	defer p.Close()
	p.mu.Lock()
	p.toolMap["fixture__echo"] = "fixture"
	p.mu.Unlock()

	first := mgr.Get("fixture")
	first.Notify("die", nil)
	select {
	case <-first.Stopped():
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not exit")
	}
	id := json.RawMessage(`7`)
	response, err := p.handleToolsCall(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "tools/call", Params: json.RawMessage(`{"name":"fixture__echo","arguments":{}}`)})
	if err != nil {
		t.Fatalf("routed call after upstream exit failed: %v", err)
	}
	if !strings.Contains(string(response.Result), "RESTARTED_OK") {
		t.Fatalf("unexpected response: %s", response.Result)
	}
	queued, err := store.Peek(10)
	if err != nil || len(queued) != 1 || queued[0].AppliedDisposition != "result_returned" {
		t.Fatalf("receipts=%+v err=%v", queued, err)
	}
}
