package cmd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// definitionAPI is a fake AgentKeeper API that records what the Gateway
// sends: syncs, registrations, evaluations, events and receipts.
type definitionAPI struct {
	*httptest.Server
	mu            sync.Mutex
	syncs         []map[string]interface{}
	registrations []map[string]interface{}
	evaluations   []map[string]interface{}
	events        []map[string]interface{}
	receipts      []map[string]interface{}
}

func newDefinitionAPI(t *testing.T) *definitionAPI {
	t.Helper()
	api := &definitionAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		api.mu.Lock()
		defer api.mu.Unlock()
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			api.registrations = append(api.registrations, body)
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"22222222-2222-4222-8222-222222222222"}`))
		case "/api/v1/mcp/sync":
			api.syncs = append(api.syncs, body)
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"22222222-2222-4222-8222-222222222222","policy":{"mode":"audit"}}`))
		case "/api/v2/mcp/evaluate", "/api/v1/mcp/evaluate":
			api.evaluations = append(api.evaluations, body)
			_, _ = w.Write([]byte(`{"verdict":"pass","decision_id":"decision-0001","evaluation_status":"evaluated"}`))
		case "/api/v1/mcp/events", "/api/v2/mcp/receipts":
			key, idKey := "events", "event_id"
			if r.URL.Path == "/api/v2/mcp/receipts" {
				key, idKey = "receipts", "receipt_id"
			}
			items, _ := body[key].([]interface{})
			acks := make([]map[string]string, 0, len(items))
			for _, raw := range items {
				item, _ := raw.(map[string]interface{})
				if key == "events" {
					api.events = append(api.events, item)
				} else {
					api.receipts = append(api.receipts, item)
				}
				id, _ := item[idKey].(string)
				acks = append(acks, map[string]string{idKey: id, "status": "accepted"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "acks": acks, "inserted": len(acks)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	return api
}

func (a *definitionAPI) snapshot() (syncs, registrations, evaluations, events, receipts []map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	clone := func(in []map[string]interface{}) []map[string]interface{} {
		return append([]map[string]interface{}(nil), in...)
	}
	return clone(a.syncs), clone(a.registrations), clone(a.evaluations), clone(a.events), clone(a.receipts)
}

func waitUntil(t *testing.T, within time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return condition()
}

func definitionGatewayConfig(home, apiURL, mode string) map[string]interface{} {
	return map[string]interface{}{
		"mode":     mode,
		"api_key":  "ak_live_definition_sync_fixture",
		"api_url":  apiURL,
		"log_path": filepath.Join(home, "events.jsonl"),
		"servers":  []map[string]interface{}{crashableFixtureServer(nil)},
	}
}

func connectedServerEntry(payload map[string]interface{}, name string) map[string]interface{} {
	servers, _ := payload["connected_servers"].([]interface{})
	for _, raw := range servers {
		if entry, _ := raw.(map[string]interface{}); entry["name"] == name {
			return entry
		}
	}
	return nil
}

func discoveredEntry(payload map[string]interface{}, name string) map[string]interface{} {
	servers, _ := payload["discovered_servers"].([]interface{})
	for _, raw := range servers {
		if entry, _ := raw.(map[string]interface{}); entry["name"] == name {
			return entry
		}
	}
	return nil
}

// Each Gateway process stamps its evaluations and events with one session
// derived from the boot id on its receipts, and the first sync of a process
// carries the definitions of the tools the Gateway has listed.
func TestE2ESessionIDAndToolDefinitionsReachTheAPI(t *testing.T) {
	api := newDefinitionAPI(t)
	home := t.TempDir()
	runSession := func(call int) string {
		t.Helper()
		gw := startGatewayProcess(t, home, definitionGatewayConfig(home, api.URL, "audit"))
		gw.handshake(t)
		if response := gw.request(t, call, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}}); !strings.Contains(response, "FIXTURE_ECHO_OK") {
			t.Fatalf("call was not forwarded: %s", response)
		}
		gw.closeStdinAndWait(t, 10*time.Second)
		_, _, evaluations, _, _ := api.snapshot()
		session, _ := evaluations[len(evaluations)-1]["session_id"].(string)
		return session
	}

	first := runSession(100)
	if !strings.HasPrefix(first, "gw-boot-") {
		t.Fatalf("evaluation session_id = %q", first)
	}
	_, _, _, events, receipts := api.snapshot()
	bootIDs := map[string]bool{}
	for _, receipt := range receipts {
		bootIDs[fmt.Sprint(receipt["boot_id"])] = true
	}
	if !bootIDs[strings.TrimPrefix(first, "gw-")] {
		t.Fatalf("session %s is not the boot id of the receipts %v", first, bootIDs)
	}
	callEvents := 0
	for _, event := range events {
		context, _ := event["context"].(map[string]interface{})
		if event["tool_name"] == "echo" {
			callEvents++
			if context["session_id"] != first {
				t.Fatalf("event context session_id = %v, want %s", context["session_id"], first)
			}
		}
	}
	if callEvents == 0 {
		t.Fatal("no call event uploaded")
	}

	syncsBefore, registrationsBefore, _, _, _ := api.snapshot()
	second := runSession(200)
	if !strings.HasPrefix(second, "gw-boot-") || second == first {
		t.Fatalf("a new process must have its own session: %s then %s", first, second)
	}
	syncs, registrations, _, _, _ := api.snapshot()
	startupSync := syncs[len(syncsBefore)]
	entry := connectedServerEntry(startupSync, "native_matrix")
	hash, _ := entry["tools_hash"].(string)
	tools, _ := entry["tools"].([]interface{})
	if !strings.HasPrefix(hash, "sha256:") || len(tools) != 2 {
		t.Fatalf("the first sync of the second process did not carry the listed tools: %v", entry)
	}
	names := []string{}
	for _, raw := range tools {
		tool, _ := raw.(map[string]interface{})
		names = append(names, fmt.Sprint(tool["name"]))
		if tool["inputSchema"] == nil || tool["description"] == nil {
			t.Fatalf("uploaded tool: %v", tool)
		}
	}
	if strings.Join(names, ",") != "disconnect,echo" {
		t.Fatalf("uploaded tool names: %v", names)
	}
	registered := connectedServerEntry(registrations[len(registrationsBefore)], "native_matrix")
	if registered["tools_hash"] != hash {
		t.Fatalf("registration tools_hash = %v, want %s", registered["tools_hash"], hash)
	}
	if _, has := registered["tools"]; has {
		t.Fatal("registration carried tool definitions")
	}
}

func writeRoutedClaudeJSON(t *testing.T, home string, servers map[string]interface{}) string {
	t.Helper()
	all := map[string]interface{}{
		"agentkeeper-mcp-gateway": map[string]interface{}{
			"command": binary,
			"args":    []string{"server"},
			"env":     map[string]string{"AGENTKEEPER_MCP_CLIENT": "claude-code"},
		},
	}
	for name, entry := range servers {
		all[name] = entry
	}
	data, err := json.MarshalIndent(map[string]interface{}{"numStartups": 3, "mcpServers": all}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func addClaudeServer(t *testing.T, path, name string, entry map[string]interface{}) {
	t.Helper()
	var document map[string]interface{}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["mcpServers"].(map[string]interface{})[name] = entry
	updated, _ := json.MarshalIndent(document, "", "  ")
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}

var claudeRouteEnv = []string{
	"AGENTKEEPER_MCP_CLIENT=claude-code",
	"AGENTKEEPER_MCP_CONFIG_SOURCE_HASH=sha256:definition-sync-e2e",
	"AGENTKEEPER_MCP_ROUTE_REVISION=route:definition-sync-e2e",
}

// A server added to the client config while the client runs reaches the API
// within seconds, marked as added after setup. Observe writes nothing.
func TestE2ERoutingWatchReportsAServerAddedWhileTheClientRuns(t *testing.T) {
	api := newDefinitionAPI(t)
	home := t.TempDir()
	claudeJSON := writeRoutedClaudeJSON(t, home, map[string]interface{}{"notes-local": map[string]interface{}{"command": "notes-mcp"}})
	gw := startGatewayProcess(t, home, definitionGatewayConfig(home, api.URL, "audit"), claudeRouteEnv...)
	gw.handshake(t)

	syncs, _, _, _, _ := api.snapshot()
	startup := discoveredEntry(syncs[0], "notes-local")
	if startup == nil || startup["route_state"] != "direct" || startup["first_seen_at"] == nil || startup["direct_reason"] != nil {
		t.Fatalf("startup report of a server present at start: %v", startup)
	}

	addClaudeServer(t, claudeJSON, "weather", map[string]interface{}{"command": "weather-mcp", "env": map[string]interface{}{"WEATHER_TOKEN": "synthetic-token"}})
	added := time.Now()
	clientAfterAdd, _ := os.ReadFile(claudeJSON)
	gatewayConfig, _ := os.ReadFile(filepath.Join(home, "gateway.json"))
	var reportedWeather map[string]interface{}
	if !waitUntil(t, 15*time.Second, func() bool {
		syncs, _, _, _, _ := api.snapshot()
		for _, payload := range syncs {
			if entry := discoveredEntry(payload, "weather"); entry != nil {
				reportedWeather = entry
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the added server was not reported; stderr:\n%s", gw.stderrText())
	}
	if elapsed := time.Since(added); elapsed > 12*time.Second {
		t.Fatalf("reported after %v", elapsed)
	}
	if reportedWeather["direct_reason"] != "added_after_setup" || reportedWeather["route_state"] != "direct" || reportedWeather["first_seen_at"] == nil {
		t.Fatalf("report: %v", reportedWeather)
	}
	if encoded, _ := json.Marshal(reportedWeather); strings.Contains(string(encoded), "synthetic-token") {
		t.Fatalf("an env value was reported: %s", encoded)
	}
	clientNow, _ := os.ReadFile(claudeJSON)
	gatewayNow, _ := os.ReadFile(filepath.Join(home, "gateway.json"))
	if !bytes.Equal(clientNow, clientAfterAdd) || !bytes.Equal(gatewayNow, gatewayConfig) {
		t.Fatal("Observe wrote a client or Gateway config")
	}
}

// In Enforce the same server is moved behind the Gateway with a backup, and
// reported as routed pending the client's restart.
func TestE2EEnforceRoutesAServerAddedWhileTheClientRuns(t *testing.T) {
	api := newDefinitionAPI(t)
	home := t.TempDir()
	claudeJSON := writeRoutedClaudeJSON(t, home, map[string]interface{}{"calendar-sso": map[string]interface{}{"type": "http", "url": "https://mcp.example.com/calendar"}})
	gw := startGatewayProcess(t, home, definitionGatewayConfig(home, api.URL, "enforce"), claudeRouteEnv...)
	gw.handshake(t)

	addClaudeServer(t, claudeJSON, "weather", map[string]interface{}{"command": "weather-mcp", "args": []string{"--stdio"}})
	var pending map[string]interface{}
	if !waitUntil(t, 20*time.Second, func() bool {
		syncs, _, _, _, _ := api.snapshot()
		for _, payload := range syncs {
			if entry := discoveredEntry(payload, "weather"); entry != nil && entry["route_state"] == "routed_pending_restart" {
				pending = entry
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the added server was not routed and reported; stderr:\n%s", gw.stderrText())
	}
	if pending["direct_reason"] != "added_after_setup" || pending["gateway_covered"] != true || pending["gateway_name"] != "weather" {
		t.Fatalf("report: %v", pending)
	}
	var client map[string]interface{}
	data, _ := os.ReadFile(claudeJSON)
	if err := json.Unmarshal(data, &client); err != nil {
		t.Fatal(err)
	}
	servers, _ := client["mcpServers"].(map[string]interface{})
	if _, still := servers["weather"]; still {
		t.Fatalf("weather is still direct: %s", data)
	}
	if _, kept := servers["calendar-sso"]; !kept || client["numStartups"] != float64(3) {
		t.Fatalf("unrelated client config changed: %s", data)
	}
	var gatewayConfig struct {
		Servers []struct {
			Name    string   `json:"name"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"servers"`
	}
	raw, _ := os.ReadFile(filepath.Join(home, "gateway.json"))
	if err := json.Unmarshal(raw, &gatewayConfig); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, server := range gatewayConfig.Servers {
		found = found || (server.Name == "weather" && server.Command == "weather-mcp")
	}
	if !found {
		t.Fatalf("weather is not in the Gateway config: %s", raw)
	}
	backups, _ := filepath.Glob(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "backups", ".claude.json.agentkeeper-backup-*"))
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	if stderr := gw.stderrText(); strings.Count(stderr, `routed MCP server "weather"`) != 1 {
		t.Fatalf("expected one routing line:\n%s", stderr)
	}
}
