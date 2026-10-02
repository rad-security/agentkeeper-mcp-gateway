package ideconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
)

func namesOf(servers []NamedServer) []string {
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, server.Name)
	}
	sort.Strings(names)
	return names
}

func sameNames(got []string, want ...string) bool {
	sort.Strings(want)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func optionalAdapter(t *testing.T, name, path string) *Adapter {
	t.Helper()
	for _, adapter := range OptionalAdapters() {
		if adapter.Name == name {
			adapter.PathResolver = func() (string, error) { return path, nil }
			return adapter
		}
	}
	t.Fatalf("no optional adapter named %q", name)
	return nil
}

// The clients below keep their MCP servers under `mcpServers`, like Cursor,
// in a file of their own. Each is routed only when the developer has that
// client, so the default set must not grow.
func TestOptionalAdapters_AreSeparateFromTheDefaultSet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	want := map[string]string{
		"windsurf":    filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		"gemini-cli":  filepath.Join(home, ".gemini", "settings.json"),
		"antigravity": filepath.Join(home, ".gemini", "antigravity", "mcp_config.json"),
		"kiro":        filepath.Join(home, ".kiro", "settings", "mcp.json"),
	}
	got := map[string]string{}
	for _, adapter := range OptionalAdapters() {
		if !adapter.Optional {
			t.Errorf("%s is not marked optional", adapter.Name)
		}
		path, err := adapter.PathResolver()
		if err != nil {
			t.Fatalf("%s: %v", adapter.Name, err)
		}
		got[adapter.Name] = path
	}
	for name, path := range want {
		if got[name] != path {
			t.Errorf("%s path = %q, want %q", name, got[name], path)
		}
	}
	if len(got) != len(want) {
		t.Errorf("optional adapters = %v, want exactly %v", got, want)
	}
	for _, adapter := range Adapters() {
		if adapter.Optional {
			t.Errorf("default adapter %s is marked optional", adapter.Name)
		}
		if _, optional := want[adapter.Name]; optional {
			t.Errorf("default set contains optional client %s", adapter.Name)
		}
	}
	if len(AllAdapters()) != len(Adapters())+len(OptionalAdapters()) {
		t.Errorf("AllAdapters() does not hold every adapter once")
	}
}

func TestPlan_WindsurfMigratesLocalServersAndKeepsTheRestNative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_config.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "tok"}},
			"notes": {"command": "node", "args": ["notes.js"], "disabled": false, "disabledTools": []},
			"docs": {"serverUrl": "https://mcp.example.test/sse"},
			"paused": {"command": "node", "args": ["paused.js"], "disabled": true},
			"trimmed": {"command": "node", "args": ["trimmed.js"], "disabledTools": ["delete_everything"]}
		}
	}`)
	plan, err := optionalAdapter(t, "windsurf", path).Plan()
	if err != nil {
		t.Fatal(err)
	}
	if got := namesOf(plan.Migrated); !sameNames(got, "github", "notes") {
		t.Errorf("migrated = %v, want github and notes", got)
	}
	// A remote server signs in inside the client. A server the developer
	// switched off, or trimmed tools from, must not come back whole behind
	// the Gateway.
	if got := namesOf(plan.NativeKept); !sameNames(got, "docs", "paused", "trimmed") {
		t.Errorf("kept native = %v, want docs, paused and trimmed", got)
	}
}

func TestPlan_KiroMigratesAServerThatCarriesAnApprovalList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"fetch": {"command": "uvx", "args": ["mcp-server-fetch"], "env": {}, "disabled": false, "autoApprove": ["fetch"]},
			"paused": {"command": "uvx", "args": ["mcp-server-time"], "disabled": true, "autoApprove": []}
		}
	}`)
	plan, err := optionalAdapter(t, "kiro", path).Plan()
	if err != nil {
		t.Fatal(err)
	}
	if got := namesOf(plan.Migrated); !sameNames(got, "fetch") {
		t.Errorf("migrated = %v, want fetch", got)
	}
	if got := namesOf(plan.NativeKept); !sameNames(got, "paused") {
		t.Errorf("kept native = %v, want paused", got)
	}
}

func TestPlan_GeminiCLIKeepsServersWhoseSettingsTheGatewayCannotCarry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, `{
		"theme": "Default",
		"mcpServers": {
			"local": {"command": "node", "args": ["server.js"], "timeout": 30000, "trust": true},
			"scoped": {"command": "node", "args": ["server.js"], "cwd": "/srv/tool"},
			"filtered": {"command": "node", "args": ["server.js"], "excludeTools": ["delete_file"]},
			"allowlisted": {"command": "node", "args": ["server.js"], "includeTools": ["read_file"]},
			"remote": {"httpUrl": "https://mcp.example.test/mcp"}
		}
	}`)
	plan, err := optionalAdapter(t, "gemini-cli", path).Plan()
	if err != nil {
		t.Fatal(err)
	}
	if got := namesOf(plan.Migrated); !sameNames(got, "local") {
		t.Errorf("migrated = %v, want local", got)
	}
	if got := namesOf(plan.NativeKept); !sameNames(got, "allowlisted", "filtered", "remote", "scoped") {
		t.Errorf("kept native = %v, want allowlisted, filtered, remote and scoped", got)
	}
}

// Claude Code, Claude Desktop and Cursor keep their behaviour: any field the
// Gateway does not model keeps the server in the client.
func TestPlan_DefaultAdaptersKeepAnyUnknownFieldNative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, path, `{"mcpServers": {"notes": {"command": "node", "args": ["notes.js"], "disabled": false}}}`)
	plan, err := mkNamedAdapter(t, "cursor", path).Plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Migrated) != 0 || !sameNames(namesOf(plan.NativeKept), "notes") {
		t.Errorf("migrated=%v kept=%v, want notes kept native", namesOf(plan.Migrated), namesOf(plan.NativeKept))
	}
}

func TestApply_GeminiCLIWritesAnAttestedEntryAndKeepsOtherSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, `{
		"theme": "Default",
		"selectedAuthType": "oauth-personal",
		"mcpServers": {
			"local": {"command": "node", "args": ["server.js"], "trust": true},
			"remote": {"httpUrl": "https://mcp.example.test/mcp"}
		}
	}`)
	adapter := optionalAdapter(t, "gemini-cli", path)
	plan, err := adapter.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ApplyManaged(&plan); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Theme            string                     `json:"theme"`
		SelectedAuthType string                     `json:"selectedAuthType"`
		Servers          map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(written, &document); err != nil {
		t.Fatal(err)
	}
	if document.Theme != "Default" || document.SelectedAuthType != "oauth-personal" {
		t.Errorf("other settings changed: %s", written)
	}
	if _, moved := document.Servers["local"]; moved {
		t.Errorf("the migrated server is still in the client config: %s", written)
	}
	var remote map[string]string
	if err := json.Unmarshal(document.Servers["remote"], &remote); err != nil || remote["httpUrl"] != "https://mcp.example.test/mcp" {
		t.Errorf("the native remote server changed: %s", document.Servers["remote"])
	}
	var gateway struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	}
	if err := json.Unmarshal(document.Servers[GatewayServerName], &gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.Env[gatewayentry.EnvClientName] != "gemini-cli" {
		t.Errorf("route client = %q, want gemini-cli", gateway.Env[gatewayentry.EnvClientName])
	}
	if !gatewayentry.IsAttestedRoute(gateway.Command, gateway.Env) {
		t.Errorf("the Gateway entry is not an attested route: %+v", gateway)
	}
	again, err := adapter.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !again.AlreadyWired {
		t.Errorf("a second plan is not a no-op: %+v", again)
	}
}
