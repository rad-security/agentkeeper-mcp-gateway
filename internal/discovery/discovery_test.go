package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
)

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverClaudeCodeProjectMCPJSON(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "work", "customer")
	writeFixture(t, filepath.Join(cwd, ".mcp.json"), `{
		"mcpServers": {
			"customer-mcp": {
				"command": "npx",
				"args": ["-y", "customer-mcp-server"],
				"env": {"CUSTOMER_TOKEN": "secret"}
			}
		}
	}`)

	res, err := Discover(Options{Home: home, CWD: cwd, Client: ClientClaudeCode})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 {
		t.Fatalf("want 1 server, got %d: %+v", len(res.Servers), res.Servers)
	}
	got := res.Servers[0]
	if got.Name != "customer-mcp" || got.SourceKind != "project_mcp_json" || got.RouteState != RouteDirect || !got.Routable {
		t.Fatalf("unexpected discovery: %+v", got)
	}
	if len(got.EnvKeys) != 1 || got.EnvKeys[0] != "CUSTOMER_TOKEN" {
		t.Fatalf("env keys not redacted/preserved as keys: %+v", got.EnvKeys)
	}
	data, _ := json.Marshal(got)
	if string(data) == "" || strings.Contains(string(data), "secret") {
		t.Fatalf("serialized discovery leaked secret: %s", data)
	}
}

func TestDiscoverClaudeJSONUserAndProject(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "repo")
	writeFixture(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"user-server": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer secret"}}
		},
		"projects": {
			"`+jsonPath(cwd)+`": {
				"mcpServers": {
					"local-server": {"command": "node", "args": ["server.js"]}
				}
			}
		}
	}`)

	res, err := Discover(Options{Home: home, CWD: cwd, Client: ClientClaudeCode})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DiscoveredServer{}
	for _, s := range res.Servers {
		byName[s.Name] = s
	}
	if byName["user-server"].SourceKind != "claude_json_user" || byName["user-server"].Transport != "http" {
		t.Fatalf("user server missing/wrong: %+v", byName["user-server"])
	}
	if byName["local-server"].SourceKind != "claude_json_project" || byName["local-server"].Scope != "local" {
		t.Fatalf("project server missing/wrong: %+v", byName["local-server"])
	}
	if len(byName["user-server"].HeaderKeys) != 1 || byName["user-server"].HeaderKeys[0] != "Authorization" {
		t.Fatalf("header keys not redacted/preserved as keys: %+v", byName["user-server"].HeaderKeys)
	}
}

func TestDiscoverCoworkPluginMCP(t *testing.T) {
	home := t.TempDir()
	pluginMCP := filepath.Join(testClaudeAppSupportPath(home), "local-agent-mode-sessions", "session-1", "cowork_plugins", "marketplaces", "vendor", "plugin", ".mcp.json")
	writeFixture(t, pluginMCP, `{
		"mcpServers": {
			"plugin-server": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/dist/server.js"]}
		}
	}`)

	res, err := Discover(Options{Home: home, Client: ClientCowork})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 {
		t.Fatalf("want 1 cowork plugin server, got %d: %+v", len(res.Servers), res.Servers)
	}
	got := res.Servers[0]
	if got.Client != ClientCowork || got.SourceKind != "cowork_plugin_mcp" || got.Routeability != RouteabilityCoworkLocalPlugin {
		t.Fatalf("unexpected cowork discovery: %+v", got)
	}
}

func TestDiscoverEmptyCommandIsNotRoutable(t *testing.T) {
	home := t.TempDir()
	pluginMCP := filepath.Join(testClaudeAppSupportPath(home), "local-agent-mode-sessions", "session-1", "vendor", "plugin", ".mcp.json")
	writeFixture(t, pluginMCP, `{
		"mcpServers": {
			"benchling": {"command": ""}
		}
	}`)

	res, err := Discover(Options{Home: home, Client: ClientCowork})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 {
		t.Fatalf("want 1 server, got %d: %+v", len(res.Servers), res.Servers)
	}
	got := res.Servers[0]
	if got.Routable || got.Routeability != RouteabilityUnknownRequiresReview {
		t.Fatalf("empty-command server should not be routable: %+v", got)
	}
}

func TestMigrateMCPFileDoesNotClobberNameCollisions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	if err := config.Save(config.Config{
		Mode: "audit",
		Servers: []config.ServerEntry{{
			Name:    "atlas",
			Command: "node",
			Args:    []string{"old.js"},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	source := filepath.Join(home, "source", ".mcp.json")
	writeFixture(t, source, `{
		"mcpServers": {
			"atlas": {"command": "python3", "args": ["server.py"]}
		}
	}`)

	plan, err := MigrateMCPFile(source, ClientCowork, "plugin", "cowork_plugin_mcp", RouteabilityCoworkLocalPlugin, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Migrated) != 1 || plan.Migrated[0].GatewayName == "" || plan.Migrated[0].GatewayName == "atlas" {
		t.Fatalf("expected migrated collision to get gateway_name: %+v", plan.Migrated)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("want 2 servers, got %d: %+v", len(cfg.Servers), cfg.Servers)
	}
	byCommand := map[string]string{}
	for _, s := range cfg.Servers {
		byCommand[s.Command] = s.Name
	}
	if byCommand["node"] != "atlas" {
		t.Fatalf("existing atlas server was clobbered: %+v", cfg.Servers)
	}
	if byCommand["python3"] == "" || byCommand["python3"] == "atlas" {
		t.Fatalf("new colliding server did not get unique name: %+v", cfg.Servers)
	}
}

func TestMigrateMCPFileSkipsInvalidEmptyCommandServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	source := filepath.Join(home, "source", ".mcp.json")
	writeFixture(t, source, `{
		"mcpServers": {
			"atlas": {"command": "node", "args": ["server.js"]},
			"benchling": {"command": ""}
		}
	}`)

	plan, err := MigrateMCPFile(source, ClientCowork, "plugin", "cowork_plugin_mcp", RouteabilityCoworkLocalPlugin, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Migrated) != 1 || plan.Migrated[0].Name != "atlas" {
		t.Fatalf("expected only atlas to migrate: %+v", plan.Migrated)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "atlas" {
		t.Fatalf("invalid server was added to gateway config: %+v", cfg.Servers)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "benchling") {
		t.Fatalf("source should be rewired to gateway only, got: %s", data)
	}
}

func TestMigrateMCPFileNoopsWhenOnlyInvalidServersExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	source := filepath.Join(home, "source", ".mcp.json")
	original := `{"mcpServers":{"benchling":{"command":""}}}`
	writeFixture(t, source, original)

	plan, err := MigrateMCPFile(source, ClientCowork, "plugin", "cowork_plugin_mcp", RouteabilityCoworkLocalPlugin, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Migrated) != 0 || plan.AlreadyRouted {
		t.Fatalf("expected no migration for invalid-only source: %+v", plan)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("invalid-only source should not be rewritten; got %s", data)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")); !os.IsNotExist(err) {
		t.Fatalf("gateway config should not be created for invalid-only source, stat err=%v", err)
	}
}

func TestDiscoverAndImportCoworkRemoteMCPConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	session := filepath.Join(testClaudeAppSupportPath(home), "local-agent-mode-sessions", "account", "env", "local_google.json")
	writeFixture(t, session, `{
		"remoteMcpServersConfig": [{
			"uuid": "0601e193-a1f4-4153-aa4e-850858ce2066",
			"name": "Google Drive",
			"url": "https://drivemcp.googleapis.com/mcp/v1"
		}],
		"enabledMcpTools": {
			"0601e193-a1f4-4153-aa4e-850858ce2066:search": true
		}
	}`)
	writeFixture(t, filepath.Join(testClaudeAppSupportPath(home), "local-agent-mode-sessions", "account", "env", "local_google_old.json"), `{
		"remoteMcpServersConfig": [{
			"uuid": "0601e193-a1f4-4153-aa4e-850858ce2066",
			"name": "Google Drive",
			"url": "https://drivemcp.googleapis.com/mcp/v1"
		}]
	}`)

	res, err := Discover(Options{Home: home, Client: ClientCowork})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 {
		t.Fatalf("want 1 remote server, got %d: %+v", len(res.Servers), res.Servers)
	}
	got := res.Servers[0]
	if got.Name != "google-drive" || got.SourceKind != "cowork_remote_mcp_config" || got.Routeability != RouteabilityCoworkRemoteMCP || !got.Routable {
		t.Fatalf("unexpected remote discovery: %+v", got)
	}

	result, err := MigrateCoworkMCPForHome(home, "", false)
	if err != nil {
		t.Fatal(err)
	}
	migrated := 0
	disabled := 0
	for _, plan := range result.Plans {
		migrated += len(plan.Migrated)
		disabled += len(plan.NativeDisabled)
		if len(plan.NativeDisabled) > 0 && plan.BackupPath == "" {
			t.Fatalf("expected backup for disabled native source: %+v", plan)
		}
	}
	if migrated != 2 || disabled != 2 {
		t.Fatalf("expected both duplicate remote sources to be imported/disabled: %+v", result.Plans)
	}
	if result.GatewayEntrypoint == nil || result.GatewayEntrypoint.AlreadyRouted {
		t.Fatalf("expected Cowork gateway entrypoint to be wired: %+v", result.GatewayEntrypoint)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "google-drive" || cfg.Servers[0].URL != "https://drivemcp.googleapis.com/mcp/v1" || cfg.Servers[0].Transport != "http" {
		t.Fatalf("remote MCP not imported into gateway config: %+v", cfg.Servers)
	}
	rewritten, err := os.ReadFile(session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rewritten), "https://drivemcp.googleapis.com/mcp/v1") || strings.Contains(string(rewritten), "0601e193-a1f4-4153-aa4e-850858ce2066:search") {
		t.Fatalf("remote direct config was not disabled: %s", rewritten)
	}

	res, err = Discover(Options{Home: home, Client: ClientCowork})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 || res.Servers[0].Name != "agentkeeper-mcp-gateway" || res.Servers[0].RouteState != RouteRouted {
		t.Fatalf("remote direct source should be gone and only gateway entrypoint should remain: %+v", res.Servers)
	}
}

func testClaudeAppSupportPath(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	default:
		return filepath.Join(home, ".config", "Claude")
	}
}

func jsonPath(path string) string {
	data, _ := json.Marshal(path)
	trimmed := string(data)
	return trimmed[1 : len(trimmed)-1]
}
