package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A policy apply notifies the client its tool list may have changed, but only
// when the effective signature actually changed, so steady-state heartbeats
// stay quiet.
func TestOnPolicyAppliedNotifiesOnlyOnChange(t *testing.T) {
	var out bytes.Buffer
	p := &Proxy{
		config:         Config{},
		toolCache:      map[string][]interface{}{},
		shadowReported: map[string]bool{},
		clientReady:    true,
		output:         &out,
	}
	p.OnPolicyApplied()
	first := strings.Count(out.String(), "notifications/tools/list_changed")
	if first != 1 {
		t.Fatalf("first policy apply emitted %d notifications, want 1", first)
	}
	p.OnPolicyApplied()
	if again := strings.Count(out.String(), "notifications/tools/list_changed"); again != 1 {
		t.Fatalf("unchanged policy emitted another notification: total %d", again)
	}
	// A mode change moves the signature and emits again.
	p.SetEnforceMode(true)
	p.OnPolicyApplied()
	if total := strings.Count(out.String(), "notifications/tools/list_changed"); total != 2 {
		t.Fatalf("mode change did not notify: total %d", total)
	}
}

// A server blocked by policy is represented in tools/list by one placeholder
// tool, and calling it returns the standard refusal.
func TestBlockedServerPlaceholderListedAndRefused(t *testing.T) {
	p, _, _ := blockedFixture(t)
	id := json.RawMessage(`5`)
	resp, err := p.handleToolsList(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "tools/list"})
	if err != nil {
		t.Fatal(err)
	}
	list := string(resp.Result)
	placeholder := "fixture__" + blockedToolSuffix
	if !strings.Contains(list, placeholder) {
		t.Fatalf("blocked server placeholder missing from tools/list: %s", list)
	}
	if !strings.Contains(list, "AgentKeeper blocked the fixture MCP server") {
		t.Fatalf("placeholder description missing: %s", list)
	}
	if strings.Contains(list, "fixture__echo") {
		t.Fatalf("blocked server's real tool was listed: %s", list)
	}

	callID := json.RawMessage(`6`)
	params, _ := json.Marshal(map[string]interface{}{"name": placeholder, "arguments": map[string]interface{}{}})
	call, err := p.handleToolsCall(JSONRPCMessage{JSONRPC: "2.0", ID: &callID, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	if call == nil || !strings.Contains(string(call.Result), "Blocked by AgentKeeper") {
		t.Fatalf("calling the placeholder was not refused: %+v", call)
	}
}
