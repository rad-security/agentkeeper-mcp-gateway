package proxy

import (
	"encoding/json"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
)

// Clients such as Cursor treat a tool without readOnlyHint as a write that
// needs approval. Both built-ins only read Gateway state (agentkeeper_audit
// also triggers the same background tools/list refresh as tools/list), so they
// must be advertised as read-only, non-destructive, idempotent and closed-world.
func TestBuiltinToolsAdvertiseReadOnlyAnnotations(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := NewProxy(Config{}, server.NewManager(nil), nil)
	defer p.Close()
	id := json.RawMessage(`1`)
	response, err := p.handleToolsList(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "tools/list"})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tools []struct {
			Name        string                 `json:"name"`
			Annotations map[string]interface{} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	seen := map[string]bool{}
	for _, tool := range result.Tools {
		if tool.Name != "agentkeeper_status" && tool.Name != "agentkeeper_audit" {
			continue
		}
		seen[tool.Name] = true
		if title, _ := tool.Annotations["title"].(string); title == "" {
			t.Errorf("%s: missing annotations.title", tool.Name)
		}
		for key, value := range want {
			if tool.Annotations[key] != value {
				t.Errorf("%s: annotations.%s=%v, want %v", tool.Name, key, tool.Annotations[key], value)
			}
		}
	}
	if !seen["agentkeeper_status"] || !seen["agentkeeper_audit"] {
		t.Fatalf("built-in tools missing from tools/list: %s", response.Result)
	}
}
