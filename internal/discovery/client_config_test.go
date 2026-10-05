package discovery

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseClientConfigReadsEveryClaudeCodeProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, "gateway.json"))
	file := ClaudeJSONFile(home)
	data := []byte(`{
		"mcpServers": {"notes": {"command": "notes-mcp"}, "wiki": {"type": "http", "url": "https://mcp.example.com/wiki"}},
		"projects": {
			"/srv/alpha": {"mcpServers": {"search": {"command": "search-mcp", "env": {"SEARCH_KEY": "synthetic"}}}},
			"/srv/beta": {"allowedTools": []}
		}
	}`)
	servers, err := ParseClientConfig(file, data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]DiscoveredServer{}
	for _, server := range servers {
		got[server.Project+"/"+server.Name] = server
	}
	if notes := got["/notes"]; notes.Scope != "user" || notes.SourceKind != "claude_json_user" || !notes.Routable || notes.SourceHash != sourceHash(file.Path) {
		t.Fatalf("user server: %+v", notes)
	}
	if wiki := got["/wiki"]; wiki.Routeability != RouteabilityNativeClientAuth || wiki.Routable {
		t.Fatalf("OAuth server: %+v", wiki)
	}
	search := got["/srv/alpha/search"]
	if search.Scope != "local" || search.SourceKind != "claude_json_project" || search.Project != "/srv/alpha" || len(search.EnvKeys) != 1 {
		t.Fatalf("project server: %+v", search)
	}
	if len(servers) != 3 {
		t.Fatalf("servers: %+v", servers)
	}
	encoded, _ := json.Marshal(servers)
	if strings.Contains(string(encoded), "/srv/alpha") || strings.Contains(string(encoded), "synthetic") {
		t.Fatalf("project key or env value serialized: %s", encoded)
	}
}

func TestParseClientConfigRejectsMalformedDocuments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, "gateway.json"))
	for _, body := range []string{
		`{"mcpServers": {"half`,
		`{"mcpServers": ["not", "a", "map"]}`,
		`{"mcpServers": {"bad": {"args": "not-a-list"}}}`,
		`{"projects": {"/srv/alpha": {"mcpServers": 7}}}`,
	} {
		if _, err := ParseClientConfig(ClaudeJSONFile(home), []byte(body)); err == nil {
			t.Fatalf("no error for %s", body)
		}
	}
	servers, err := ParseClientConfig(ClaudeJSONFile(home), []byte(`{"projects": null}`))
	if err != nil || len(servers) != 0 {
		t.Fatalf("an empty document: %+v %v", servers, err)
	}
}

func TestClaudeCodePluginServersReadsOnlyInstalledEnabledPlugins(t *testing.T) {
	home := t.TempDir()
	plugins := filepath.Join(home, ".claude", "plugins")
	flat := filepath.Join(plugins, "cache", "example-market", "release-notes", "1.0.0")
	wrapped := filepath.Join(plugins, "cache", "example-market", "status-board", "2.1.0")
	manifestInline := filepath.Join(plugins, "cache", "example-market", "inline-tools", "0.3.0")
	manifestPath := filepath.Join(plugins, "cache", "example-market", "referenced", "1.2.0")
	disabled := filepath.Join(plugins, "cache", "example-market", "switched-off", "1.0.0")

	writeFixture(t, filepath.Join(flat, ".mcp.json"), `{"changelog": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/changelog", "env": {"CHANGELOG_TOKEN": "synthetic"}}, "$schema": "https://example.com/schema.json"}`)
	writeFixture(t, filepath.Join(wrapped, ".mcp.json"), `{"mcpServers": {"status": {"type": "http", "url": "https://mcp.example.com/status", "headers": {"Authorization": "Bearer synthetic"}}}}`)
	writeFixture(t, filepath.Join(manifestInline, ".claude-plugin", "plugin.json"), `{"name": "inline-tools", "mcpServers": {"formatter": {"command": "formatter-mcp"}}}`)
	writeFixture(t, filepath.Join(manifestPath, ".claude-plugin", "plugin.json"), `{"name": "referenced", "mcpServers": "${CLAUDE_PLUGIN_ROOT}/config/servers.json"}`)
	writeFixture(t, filepath.Join(manifestPath, "config", "servers.json"), `{"mcpServers": {"indexer": {"command": "indexer-mcp"}}}`)
	writeFixture(t, filepath.Join(disabled, ".mcp.json"), `{"quiet": {"command": "quiet-mcp"}}`)
	// A marketplace checkout carries plugins nobody installed.
	writeFixture(t, filepath.Join(plugins, "marketplaces", "example-market", "plugins", "not-installed", ".mcp.json"), `{"stray": {"command": "stray-mcp"}}`)
	// A manifest path may not leave its plugin.
	escape := filepath.Join(plugins, "cache", "example-market", "escape", "1.0.0")
	writeFixture(t, filepath.Join(escape, ".claude-plugin", "plugin.json"), `{"mcpServers": "../../../../../../outside.json"}`)
	writeFixture(t, filepath.Join(plugins, "outside.json"), `{"outside": {"command": "outside-mcp"}}`)

	installed := map[string]interface{}{"version": 2, "plugins": map[string]interface{}{
		"release-notes@example-market": []interface{}{map[string]interface{}{"scope": "user", "installPath": flat}},
		"status-board@example-market":  []interface{}{map[string]interface{}{"scope": "user", "installPath": wrapped}},
		"inline-tools@example-market":  []interface{}{map[string]interface{}{"scope": "project", "projectPath": filepath.Join(home, "work"), "installPath": manifestInline}},
		"referenced@example-market":    []interface{}{map[string]interface{}{"scope": "user", "installPath": manifestPath}},
		"switched-off@example-market":  []interface{}{map[string]interface{}{"scope": "user", "installPath": disabled}},
		"escape@example-market":        []interface{}{map[string]interface{}{"scope": "user", "installPath": escape}},
		"relative@example-market":      []interface{}{map[string]interface{}{"scope": "user", "installPath": "cache/relative"}},
	}}
	raw, _ := json.Marshal(installed)
	writeFixture(t, filepath.Join(plugins, "installed_plugins.json"), string(raw))
	writeFixture(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins": {"switched-off@example-market": false, "release-notes@example-market": true}}`)

	servers, files := ClaudeCodePluginServers(home)
	var names []string
	byName := map[string]DiscoveredServer{}
	for _, server := range servers {
		names = append(names, server.Name)
		byName[server.Name] = server
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "changelog,formatter,indexer,status" {
		t.Fatalf("plugin servers = %v", names)
	}
	changelog := byName["changelog"]
	if changelog.Scope != "plugin" || changelog.SourceKind != SourceKindClaudeCodePlugin || changelog.Routable || changelog.Routeability != RouteabilityClaudeCodePlugin ||
		changelog.RouteState != RouteDirect || changelog.SourcePath != filepath.Join(flat, ".mcp.json") || len(changelog.EnvKeys) != 1 {
		t.Fatalf("flat plugin server: %+v", changelog)
	}
	if status := byName["status"]; status.Transport != "http" || len(status.HeaderKeys) != 1 {
		t.Fatalf("wrapped plugin server: %+v", status)
	}
	if indexer := byName["indexer"]; indexer.SourcePath != filepath.Join(manifestPath, "config", "servers.json") {
		t.Fatalf("referenced plugin server: %+v", indexer)
	}
	watched := strings.Join(files, "\n")
	for _, want := range []string{
		filepath.Join(plugins, "installed_plugins.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(flat, ".mcp.json"),
		filepath.Join(manifestPath, "config", "servers.json"),
	} {
		if !strings.Contains(watched, want) {
			t.Fatalf("files do not include %s:\n%s", want, watched)
		}
	}
	if strings.Contains(watched, "marketplaces") || strings.Contains(watched, "outside.json") {
		t.Fatalf("files include a plugin that is not installed or a path outside a plugin:\n%s", watched)
	}
}

func TestClaudeCodePluginServersWithoutInstalls(t *testing.T) {
	home := t.TempDir()
	servers, files := ClaudeCodePluginServers(home)
	if len(servers) != 0 || len(files) != 2 {
		t.Fatalf("servers %+v files %v", servers, files)
	}
}
