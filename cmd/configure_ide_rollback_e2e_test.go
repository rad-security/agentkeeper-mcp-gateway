package cmd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---- rollback fixtures ----------------------------------------------------

func serverNames(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	servers := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &servers); err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func projectServerNames(t *testing.T, document map[string]json.RawMessage, project string) []string {
	t.Helper()
	projects := map[string]map[string]json.RawMessage{}
	if err := json.Unmarshal(document["projects"], &projects); err != nil {
		t.Fatal(err)
	}
	return serverNames(t, projects[project]["mcpServers"])
}

func gatewayServerNames(t *testing.T, home string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Servers []struct {
			Name string `json:"name"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, server := range cfg.Servers {
		names = append(names, server.Name)
	}
	sort.Strings(names)
	return names
}

func mustRun(t *testing.T, home string, args ...string) string {
	t.Helper()
	out, stderr, code := run(t, home, args...)
	if code != 0 {
		t.Fatalf("%v exit=%d\nstdout=%s\nstderr=%s", args, code, out, stderr)
	}
	return out
}

func wantNames(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got == nil {
		got = []string{}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}

// simulateClientRewrite models the MCP client saving its own state into the
// routed file after routing, which is what Claude Code does on every launch.
func simulateClientRewrite(t *testing.T, path string) {
	t.Helper()
	document := readConfig(t, path)
	document["numStartups"] = json.RawMessage(`99`)
	document["stateWrittenAfterRouting"] = json.RawMessage(`{"lastSession":"synthetic"}`)
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func claudeCodeFixtureWithProject(project string) string {
	return fmt.Sprintf(`{
  "numStartups": 1,
  "mcpServers": {"global-db": {"command": "fixture-global"}},
  "projects": {
    %q: {
      "allowedTools": ["Bash"],
      "mcpServers": {"project-db": {"command": "fixture-project", "env": {"DATABASE": "synthetic"}}}
    }
  }
}
`, project)
}

// ---- tests ---------------------------------------------------------------

// The documented rollback command names no client. It must restore everything
// a default `configure-ide` run routed.
func TestRemoveRoutingWithoutIDERestoresDefaultConfigure(t *testing.T) {
	home := t.TempDir()
	cursor := writeFixture(t, home, "cursor", "{\n  \"mcpServers\": {\"cursor-db\": {\"command\": \"fixture-cursor\"}}\n}\n")
	desktop := writeFixture(t, home, "claude-desktop", "{\n  \"mcpServers\": {\"desktop-db\": {\"command\": \"fixture-desktop\"}}\n}\n")
	cursorOriginal, _ := os.ReadFile(cursor)
	desktopOriginal, _ := os.ReadFile(desktop)

	mustRun(t, home, "configure-ide")
	wantNames(t, "routed gateway servers", gatewayServerNames(t, home), "cursor-db", "desktop-db")

	mustRun(t, home, "configure-ide", "--remove-routing")
	for path, original := range map[string][]byte{cursor: cursorOriginal, desktop: desktopOriginal} {
		restored, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(restored, original) {
			t.Fatalf("%s was not restored\n got: %s\nwant: %s", path, restored, original)
		}
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// `claude mcp add` stores servers per project inside ~/.claude.json by
// default. Rolling back must restore them, including after the client has
// rewritten the file, and must not leave their copies in the Gateway config.
func TestRemoveRoutingRestoresProjectScopedClaudeCodeServers(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediately", true: "after_client_rewrite"}[drift], func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "repo")
			path := writeFixture(t, home, "claude-code", claudeCodeFixtureWithProject(project))

			mustRun(t, home, "configure-ide", "--ide=claude-code")
			routed := readConfig(t, path)
			wantNames(t, "routed global servers", serverNames(t, routed["mcpServers"]), "agentkeeper-mcp-gateway")
			wantNames(t, "routed project servers", projectServerNames(t, routed, project), "agentkeeper-mcp-gateway")
			wantNames(t, "routed gateway servers", gatewayServerNames(t, home), "global-db", "project-db")
			if drift {
				simulateClientRewrite(t, path)
			}

			mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
			restored := readConfig(t, path)
			wantNames(t, "restored global servers", serverNames(t, restored["mcpServers"]), "global-db")
			wantNames(t, "restored project servers", projectServerNames(t, restored, project), "project-db")
			wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
			if !strings.Contains(string(restored["projects"]), `"DATABASE":"synthetic"`) && !strings.Contains(string(restored["projects"]), `"DATABASE": "synthetic"`) {
				t.Fatalf("project server definition was not restored intact: %s", restored["projects"])
			}
			if !strings.Contains(string(restored["projects"]), `"allowedTools"`) {
				t.Fatalf("project settings were lost: %s", restored["projects"])
			}
			if drift {
				if string(restored["numStartups"]) != "99" || len(restored["stateWrittenAfterRouting"]) == 0 {
					t.Fatalf("rollback discarded state the client wrote after routing: %v", restored)
				}
			}
		})
	}
}

// Routes created by the released v0.2.1 left the manifest holding the route
// identity from before the project migration re-attested the entry. Those
// installs must still be able to roll back.
func TestRemoveRoutingAcceptsManifestWithSupersededRouteIdentity(t *testing.T) {
	home := t.TempDir()
	path := writeFixture(t, home, "claude-code", `{"mcpServers":{"global-db":{"command":"fixture-global"}}}`)
	mustRun(t, home, "configure-ide", "--ide=claude-code")

	manifestPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "manual-routing.json")
	manifest := readConfig(t, manifestPath)
	var clients []map[string]json.RawMessage
	if err := json.Unmarshal(manifest["clients"], &clients); err != nil {
		t.Fatal(err)
	}
	clients[0]["source_hash"] = json.RawMessage(`"sha256:superseded-by-project-migration"`)
	clients[0]["route_revision"] = json.RawMessage(`"route:superseded-by-project-migration"`)
	manifest["clients"], _ = json.Marshal(clients)
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	simulateClientRewrite(t, path)

	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	wantNames(t, "restored global servers", serverNames(t, readConfig(t, path)["mcpServers"]), "global-db")
}

func TestRemoveRoutingRestoresExplicitProjectMCPFile(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	projectMCP := filepath.Join(project, ".mcp.json")
	original := []byte("{\n  \"mcpServers\": {\"repo-db\": {\"command\": \"fixture-repo\"}}\n}\n")
	if err := os.WriteFile(projectMCP, original, 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
	wantNames(t, "routed project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "agentkeeper-mcp-gateway")
	wantNames(t, "routed gateway servers", gatewayServerNames(t, home), "repo-db")

	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	restored, err := os.ReadFile(projectMCP)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("project .mcp.json was not restored\n got: %s\nwant: %s", restored, original)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

func coworkPluginFixture(t *testing.T, home string) (string, []byte) {
	t.Helper()
	pluginMCP := filepath.Join(claudeAppSupportPath(home), "local-agent-mode-sessions", "session-1", "cowork_plugins", "marketplaces", "vendor", "atlas", ".mcp.json")
	if err := os.MkdirAll(filepath.Dir(pluginMCP), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\n  \"mcpServers\": {\"atlas\": {\"command\": \"node\", \"args\": [\"server.js\"]}},\n  \"plugin\": true\n}\n")
	if err := os.WriteFile(pluginMCP, original, 0o644); err != nil {
		t.Fatal(err)
	}
	return pluginMCP, original
}

func coworkRemoteFixture(t *testing.T, home string) string {
	t.Helper()
	session := filepath.Join(claudeAppSupportPath(home), "local-agent-mode-sessions", "account", "env", "local_remote.json")
	if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(session, []byte(`{
  "remoteMcpServersConfig": [{
    "uuid": "11111111-2222-4333-8444-555555555555",
    "name": "Synthetic Remote",
    "url": "https://remote.example.test/mcp",
    "headers": {"Authorization": "Bearer synthetic"}
  }],
  "enabledMcpTools": {"11111111-2222-4333-8444-555555555555:search": true},
  "sessionTitle": "before routing"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return session
}

// Cowork routes are created by `configure-ide`, `cowork configure` and the
// Cowork guard. Each must be reversible with the same rollback command.
func TestRemoveRoutingRestoresCoworkSources(t *testing.T) {
	for _, entry := range []struct {
		name      string
		configure []string
		remove    []string
	}{
		{"configure_ide_default", []string{"configure-ide"}, []string{"configure-ide", "--remove-routing"}},
		{"cowork_configure", []string{"cowork", "configure"}, []string{"configure-ide", "--ide=cowork", "--remove-routing"}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			home := t.TempDir()
			pluginMCP, pluginOriginal := coworkPluginFixture(t, home)
			session := coworkRemoteFixture(t, home)

			mustRun(t, home, entry.configure...)
			wantNames(t, "routed plugin file", serverNames(t, readConfig(t, pluginMCP)["mcpServers"]), "agentkeeper-mcp-gateway")
			if routedSession, _ := os.ReadFile(session); strings.Contains(string(routedSession), "remote.example.test") {
				t.Fatalf("remote source was not routed: %s", routedSession)
			}
			if len(gatewayServerNames(t, home)) != 2 {
				t.Fatalf("expected both Cowork backends in the Gateway config: %v", gatewayServerNames(t, home))
			}
			// Cowork keeps writing its own session state after routing.
			sessionDocument := readConfig(t, session)
			sessionDocument["sessionTitle"] = json.RawMessage(`"after routing"`)
			drifted, _ := json.MarshalIndent(sessionDocument, "", "  ")
			if err := os.WriteFile(session, drifted, 0o644); err != nil {
				t.Fatal(err)
			}

			mustRun(t, home, entry.remove...)
			restoredPlugin, err := os.ReadFile(pluginMCP)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restoredPlugin, pluginOriginal) {
				t.Fatalf("Cowork plugin file was not restored\n got: %s\nwant: %s", restoredPlugin, pluginOriginal)
			}
			restoredSession := readConfig(t, session)
			if !strings.Contains(string(restoredSession["remoteMcpServersConfig"]), "https://remote.example.test/mcp") {
				t.Fatalf("native remote source was not restored: %s", restoredSession["remoteMcpServersConfig"])
			}
			if !strings.Contains(string(restoredSession["enabledMcpTools"]), "11111111-2222-4333-8444-555555555555:search") {
				t.Fatalf("native remote tool selection was not restored: %s", restoredSession["enabledMcpTools"])
			}
			if string(restoredSession["sessionTitle"]) != `"after routing"` {
				t.Fatalf("rollback discarded Cowork state written after routing: %s", restoredSession["sessionTitle"])
			}
			wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
			desktop := ideConfigPath(home, "claude-desktop")
			if data, err := os.ReadFile(desktop); err == nil && strings.Contains(string(data), "agentkeeper-mcp-gateway") {
				t.Fatalf("Cowork Gateway entrypoint remains after rollback: %s", data)
			}
		})
	}
}

// Real ~/.claude.json files run to megabytes. The ownership manifest keeps the
// pre-route bytes, so it must not be capped below them.
func TestRemoveRoutingHandlesLargeClientConfig(t *testing.T) {
	home := t.TempDir()
	history := strings.Repeat("synthetic history entry; ", 60000) // ~1.5 MB
	body, _ := json.Marshal(map[string]interface{}{
		"mcpServers": map[string]interface{}{"global-db": map[string]interface{}{"command": "fixture-global"}},
		"history":    history,
	})
	path := writeFixture(t, home, "claude-code", string(body))

	mustRun(t, home, "configure-ide", "--ide=claude-code")
	mustRun(t, home, "configure-ide", "--ide=claude-code") // re-run reads the manifest back
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, body) {
		t.Fatalf("large client config was not restored byte-for-byte (got %d bytes, want %d)", len(restored), len(body))
	}
}

// Rolling back one client must leave the others routed, with the Gateway
// servers they still depend on.
func TestRemoveRoutingForOneClientKeepsTheOthersRouted(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	cursor := writeFixture(t, home, "cursor", `{"mcpServers":{"cursor-db":{"command":"fixture-cursor"}}}`)
	claude := writeFixture(t, home, "claude-code", claudeCodeFixtureWithProject(project))
	mustRun(t, home, "configure-ide")

	mustRun(t, home, "configure-ide", "--ide=cursor", "--remove-routing")
	wantNames(t, "cursor servers", serverNames(t, readConfig(t, cursor)["mcpServers"]), "cursor-db")
	routed := readConfig(t, claude)
	wantNames(t, "claude-code global servers", serverNames(t, routed["mcpServers"]), "agentkeeper-mcp-gateway")
	wantNames(t, "claude-code project servers", projectServerNames(t, routed, project), "agentkeeper-mcp-gateway")
	wantNames(t, "gateway servers still owned", gatewayServerNames(t, home), "global-db", "project-db")

	mustRun(t, home, "configure-ide", "--remove-routing")
	restored := readConfig(t, claude)
	wantNames(t, "restored global servers", serverNames(t, restored["mcpServers"]), "global-db")
	wantNames(t, "restored project servers", projectServerNames(t, restored, project), "project-db")
	wantNames(t, "gateway servers after full rollback", gatewayServerNames(t, home))
}

// Running configure-ide again must not disturb what rollback restores.
func TestRemoveRoutingAfterRepeatedConfigure(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	claude := writeFixture(t, home, "claude-code", claudeCodeFixtureWithProject(project))
	pluginMCP, pluginOriginal := coworkPluginFixture(t, home)
	for i := 0; i < 3; i++ {
		mustRun(t, home, "configure-ide")
		simulateClientRewrite(t, claude)
	}
	mustRun(t, home, "configure-ide", "--remove-routing")
	restored := readConfig(t, claude)
	wantNames(t, "restored global servers", serverNames(t, restored["mcpServers"]), "global-db")
	wantNames(t, "restored project servers", projectServerNames(t, restored, project), "project-db")
	if plugin, _ := os.ReadFile(pluginMCP); !bytes.Equal(plugin, pluginOriginal) {
		t.Fatalf("Cowork plugin file was not restored: %s", plugin)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// The Cowork entrypoint is written into the Claude Desktop config. Rollback
// removes a config that step created and restores one that already existed,
// and must never delete a file the customer had.
func TestRemoveRoutingCoworkEntrypointNeverDeletesExistingDesktopConfig(t *testing.T) {
	for _, existed := range []bool{false, true} {
		t.Run(map[bool]string{false: "created_by_routing", true: "existed_before_routing"}[existed], func(t *testing.T) {
			home := t.TempDir()
			coworkPluginFixture(t, home)
			desktop := ideConfigPath(home, "claude-desktop")
			original := []byte("{\n  \"globalShortcut\": \"Cmd+Shift+Space\"\n}\n")
			if existed {
				if err := os.MkdirAll(filepath.Dir(desktop), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(desktop, original, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			mustRun(t, home, "cowork", "configure")
			if data, err := os.ReadFile(desktop); err != nil || !strings.Contains(string(data), "agentkeeper-mcp-gateway") {
				t.Fatalf("Cowork entrypoint was not written: %v %s", err, data)
			}
			mustRun(t, home, "configure-ide", "--ide=cowork", "--remove-routing")
			data, err := os.ReadFile(desktop)
			if existed {
				if err != nil || !bytes.Equal(data, original) {
					t.Fatalf("existing Claude Desktop config was not restored: %v %s", err, data)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("config created by routing was left behind: %s", data)
			}
		})
	}
}

// Running the migration again on already-routed Cowork sources changes
// nothing, and must not record a file as created by routing.
func TestRepeatedCoworkConfigureDoesNotClaimExistingFiles(t *testing.T) {
	home := t.TempDir()
	pluginMCP, pluginOriginal := coworkPluginFixture(t, home)
	desktop := writeFixture(t, home, "claude-desktop", "{\n  \"globalShortcut\": \"Cmd+Shift+Space\"\n}\n")
	desktopOriginal, _ := os.ReadFile(desktop)
	for i := 0; i < 3; i++ {
		mustRun(t, home, "cowork", "configure")
	}
	mustRun(t, home, "configure-ide", "--remove-routing")
	if data, err := os.ReadFile(desktop); err != nil || !bytes.Equal(data, desktopOriginal) {
		t.Fatalf("Claude Desktop config after rollback: %v %s", err, data)
	}
	if data, err := os.ReadFile(pluginMCP); err != nil || !bytes.Equal(data, pluginOriginal) {
		t.Fatalf("Cowork plugin file after rollback: %v %s", err, data)
	}
}

// ---- routes that change after the first run -------------------------------

func addServerToRoutedFile(t *testing.T, path, name, command string) {
	t.Helper()
	document := readConfig(t, path)
	servers := map[string]json.RawMessage{}
	if err := json.Unmarshal(document["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	servers[name], _ = json.Marshal(map[string]string{"command": command})
	document["mcpServers"], _ = json.Marshal(servers)
	data, _ := json.MarshalIndent(document, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A server the customer adds to an already-routed file is routed by the next
// run. Rollback must give back both generations of servers, not the file as
// it stood before the first run.
func TestRemoveRoutingKeepsServersRoutedByALaterRun(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediately", true: "after_client_rewrite"}[drift], func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "repo")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			projectMCP := filepath.Join(project, ".mcp.json")
			if err := os.WriteFile(projectMCP, []byte(`{"mcpServers":{"repo-db":{"command":"fixture-repo"}}}`), 0o644); err != nil {
				t.Fatal(err)
			}
			mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
			addServerToRoutedFile(t, projectMCP, "added-later", "fixture-later")
			mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
			wantNames(t, "routed project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "agentkeeper-mcp-gateway")
			wantNames(t, "routed gateway servers", gatewayServerNames(t, home), "added-later", "repo-db")
			if drift {
				simulateClientRewrite(t, projectMCP)
			}

			mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
			wantNames(t, "restored project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "added-later", "repo-db")
			wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
		})
	}
}

func TestRemoveRoutingKeepsCoworkStateFromALaterRun(t *testing.T) {
	home := t.TempDir()
	coworkPluginFixture(t, home)
	session := coworkRemoteFixture(t, home)
	mustRun(t, home, "cowork", "configure")

	// Cowork keeps writing its state, and the user connects a second remote.
	document := readConfig(t, session)
	document["sessionTitle"] = json.RawMessage(`"between runs"`)
	document["remoteMcpServersConfig"] = json.RawMessage(`[{"uuid":"99999999-2222-4333-8444-555555555555","name":"Second Remote","url":"https://second.example.test/mcp","headers":{"Authorization":"Bearer synthetic"}}]`)
	data, _ := json.MarshalIndent(document, "", "  ")
	if err := os.WriteFile(session, data, 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "cowork", "configure")
	if routed, _ := os.ReadFile(session); strings.Contains(string(routed), "second.example.test") {
		t.Fatalf("second remote was not routed: %s", routed)
	}

	mustRun(t, home, "configure-ide", "--remove-routing")
	restored := readConfig(t, session)
	for _, want := range []string{"https://remote.example.test/mcp", "https://second.example.test/mcp"} {
		if !strings.Contains(string(restored["remoteMcpServersConfig"]), want) {
			t.Fatalf("remote %s was not restored: %s", want, restored["remoteMcpServersConfig"])
		}
	}
	if string(restored["sessionTitle"]) != `"between runs"` {
		t.Fatalf("rollback reverted Cowork state written after the first run: %s", restored["sessionTitle"])
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// The Cowork entrypoint may create the Claude Desktop config. Once the
// customer has put their own settings in it, rollback must not delete it.
func TestRemoveRoutingKeepsCustomerContentAddedToAConfigRoutingCreated(t *testing.T) {
	home := t.TempDir()
	coworkPluginFixture(t, home)
	mustRun(t, home, "cowork", "configure")
	desktop := ideConfigPath(home, "claude-desktop")
	document := readConfig(t, desktop)
	document["globalShortcut"] = json.RawMessage(`"Cmd+Shift+Space"`)
	data, _ := json.MarshalIndent(document, "", "  ")
	if err := os.WriteFile(desktop, data, 0o644); err != nil {
		t.Fatal(err)
	}
	addServerToRoutedFile(t, desktop, "desk-later", "fixture-desk")
	mustRun(t, home, "cowork", "configure")

	mustRun(t, home, "configure-ide", "--remove-routing")
	restored := readConfig(t, desktop)
	if string(restored["globalShortcut"]) != `"Cmd+Shift+Space"` {
		t.Fatalf("customer settings were lost: %v", restored)
	}
	wantNames(t, "restored desktop servers", serverNames(t, restored["mcpServers"]), "desk-later")
}

// `cowork configure` writes its entrypoint into the Claude Desktop config.
// A later `configure-ide` routes the same file; both must roll back together.
func TestRemoveRoutingWhenCoworkWasConfiguredBeforeConfigureIDE(t *testing.T) {
	home := t.TempDir()
	pluginMCP, pluginOriginal := coworkPluginFixture(t, home)
	cursor := writeFixture(t, home, "cursor", "{\n  \"mcpServers\": {\"cursor-db\": {\"command\": \"fixture-cursor\"}}\n}\n")
	cursorOriginal, _ := os.ReadFile(cursor)
	mustRun(t, home, "cowork", "configure")
	mustRun(t, home, "configure-ide")

	mustRun(t, home, "configure-ide", "--remove-routing")
	if data, _ := os.ReadFile(cursor); !bytes.Equal(data, cursorOriginal) {
		t.Fatalf("cursor config was not restored: %s", data)
	}
	if data, _ := os.ReadFile(pluginMCP); !bytes.Equal(data, pluginOriginal) {
		t.Fatalf("Cowork plugin file was not restored: %s", data)
	}
	if data, err := os.ReadFile(ideConfigPath(home, "claude-desktop")); err == nil && strings.Contains(string(data), "agentkeeper-mcp-gateway") {
		t.Fatalf("Gateway entry remains in the Claude Desktop config: %s", data)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// Cowork session and plugin directories come and go. One that is gone has
// nothing to restore now and must not stop every other client from rolling
// back. Its record and its Gateway servers are kept, because a file that is
// only absent (a renamed or unmounted project) can still come back routed.
func TestRemoveRoutingSkipsSourcesMissingAtRollback(t *testing.T) {
	home := t.TempDir()
	pluginMCP, _ := coworkPluginFixture(t, home)
	cursor := writeFixture(t, home, "cursor", "{\n  \"mcpServers\": {\"cursor-db\": {\"command\": \"fixture-cursor\"}}\n}\n")
	cursorOriginal, _ := os.ReadFile(cursor)
	mustRun(t, home, "configure-ide")
	if err := os.RemoveAll(filepath.Dir(pluginMCP)); err != nil {
		t.Fatal(err)
	}
	// Removing the orphaned backend by hand must not turn into "drift".
	mustRun(t, home, "remove", "atlas")

	out := mustRun(t, home, "configure-ide", "--remove-routing")
	if !strings.Contains(out, "skipped_missing") {
		t.Fatalf("rollback did not report the missing source:\n%s", out)
	}
	if data, _ := os.ReadFile(cursor); !bytes.Equal(data, cursorOriginal) {
		t.Fatalf("cursor config was not restored: %s", data)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

func TestRemoveRoutingRestoresAFileAbsentDuringAnEarlierRollback(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	projectMCP := filepath.Join(project, ".mcp.json")
	original := []byte("{\n  \"mcpServers\": {\"repo-db\": {\"command\": \"fixture-repo\"}}\n}\n")
	if err := os.WriteFile(projectMCP, original, 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)

	away := filepath.Join(home, "repo-on-another-volume")
	if err := os.Rename(project, away); err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, home, "configure-ide", "--remove-routing")
	if !strings.Contains(out, "skipped_missing") {
		t.Fatalf("rollback did not report the absent file:\n%s", out)
	}
	wantNames(t, "gateway servers kept for the absent route", gatewayServerNames(t, home), "repo-db")

	if err := os.Rename(away, project); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "configure-ide", "--remove-routing")
	if restored, _ := os.ReadFile(projectMCP); !bytes.Equal(restored, original) {
		t.Fatalf("returned file was not restored: %s", restored)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
	if out, _, code := run(t, home, "configure-ide", "--remove-routing"); code != 0 || !strings.Contains(out, "not_configured") {
		t.Fatalf("final rollback exit=%d out=%s", code, out)
	}
}

// A Gateway backend the customer already removed by hand is not drift.
func TestRemoveRoutingToleratesAGatewayServerRemovedByHand(t *testing.T) {
	home := t.TempDir()
	cursor := writeFixture(t, home, "cursor", "{\n  \"mcpServers\": {\"cursor-db\": {\"command\": \"fixture-cursor\"}}\n}\n")
	cursorOriginal, _ := os.ReadFile(cursor)
	mustRun(t, home, "configure-ide", "--ide=cursor")
	mustRun(t, home, "remove", "cursor-db")
	mustRun(t, home, "configure-ide", "--ide=cursor", "--remove-routing")
	if data, _ := os.ReadFile(cursor); !bytes.Equal(data, cursorOriginal) {
		t.Fatalf("cursor config was not restored: %s", data)
	}
}

// Dotfile managers symlink client configs. The migration writes through the
// link, so the record has to follow it too.
func TestRemoveRoutingRestoresASymlinkedProjectFile(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	dotfiles := filepath.Join(home, "dotfiles")
	for _, dir := range []string{project, dotfiles} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dotfiles, "mcp.json")
	original := []byte("{\n  \"mcpServers\": {\"repo-db\": {\"command\": \"fixture-repo\"}}\n}\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	projectMCP := filepath.Join(project, ".mcp.json")
	if err := os.Symlink(target, projectMCP); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
	wantNames(t, "routed project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "agentkeeper-mcp-gateway")

	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	if restored, _ := os.ReadFile(target); !bytes.Equal(restored, original) {
		t.Fatalf("symlinked file was not restored: %s", restored)
	}
	if info, err := os.Lstat(projectMCP); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink itself was replaced: %v", err)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// A ~/.claude.json that holds only project-scoped servers has no top-level
// server map. An immediate rollback must return it byte for byte.
func TestRemoveRoutingRestoresClaudeConfigWithOnlyProjectServersExactly(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	original := fmt.Sprintf("{\n  \"note\": \"a < b && c > d\",\n  \"projects\": {\n    %q: {\"mcpServers\": {\"project-db\": {\"command\": \"fixture-project\"}}}\n  }\n}\n", project)
	path := writeFixture(t, home, "claude-code", original)
	mustRun(t, home, "configure-ide", "--ide=claude-code")
	wantNames(t, "routed project servers", projectServerNames(t, readConfig(t, path), project), "agentkeeper-mcp-gateway")
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	if restored, _ := os.ReadFile(path); string(restored) != original {
		t.Fatalf("file was not restored exactly\n got: %s\nwant: %s", restored, original)
	}
}

// A Gateway entry the customer wrote under their own name, with their own
// settings, is their server. Rollback must give it back.
func TestRemoveRoutingRestoresACustomerAuthoredGatewayEntry(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	projectMCP := filepath.Join(project, ".mcp.json")
	body := fmt.Sprintf(`{"mcpServers":{"team-gateway":{"command":%q,"args":["server"],"env":{"AGENTKEEPER_CONFIG":"/opt/team/gateway.json"}},"repo-db":{"command":"fixture-repo"}}}`, binary)
	if err := os.WriteFile(projectMCP, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
	simulateClientRewrite(t, projectMCP)
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	restored := readConfig(t, projectMCP)
	wantNames(t, "restored project file", serverNames(t, restored["mcpServers"]), "repo-db", "team-gateway")
	if !strings.Contains(string(restored["mcpServers"]), "/opt/team/gateway.json") {
		t.Fatalf("customer's Gateway entry lost its settings: %s", restored["mcpServers"])
	}
}

// A migration that fails part-way has already rewritten some sources. Those
// must still be recorded, or nothing can ever restore them.
func TestCoworkSourcesRoutedBeforeAFailureAreStillRecorded(t *testing.T) {
	home := t.TempDir()
	pluginMCP, pluginOriginal := coworkPluginFixture(t, home)
	desktop := writeFixture(t, home, "claude-desktop", "{ this is not json")
	if _, _, code := run(t, home, "cowork", "configure"); code == 0 {
		t.Fatal("cowork configure succeeded despite a malformed Claude Desktop config")
	}
	wantNames(t, "plugin file routed before the failure", serverNames(t, readConfig(t, pluginMCP)["mcpServers"]), "agentkeeper-mcp-gateway")

	mustRun(t, home, "configure-ide", "--ide=cowork", "--remove-routing")
	if data, _ := os.ReadFile(pluginMCP); !bytes.Equal(data, pluginOriginal) {
		t.Fatalf("Cowork plugin file was not restored: %s", data)
	}
	if data, _ := os.ReadFile(desktop); string(data) != "{ this is not json" {
		t.Fatalf("malformed customer file was modified: %s", data)
	}
	wantNames(t, "gateway servers after rollback", gatewayServerNames(t, home))
}

// A file routed by a release that kept no ownership record is re-attested by
// the next run. What gets recorded as its pre-route content must not be the
// routed file, or rollback would "restore" the Gateway entry.
func TestRemoveRoutingStripsRouteAdoptedWithoutAPriorRecord(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	projectMCP := filepath.Join(project, ".mcp.json")
	legacy := fmt.Sprintf(`{"mcpServers":{"agentkeeper-mcp-gateway":{"command":%q,"args":["server"]},"late":{"command":"fixture-late"}}}`, binary)
	if err := os.WriteFile(projectMCP, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, home, "configure-ide", "--ide=claude-code", "--cwd", project)
	wantNames(t, "routed project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "agentkeeper-mcp-gateway")

	mustRun(t, home, "configure-ide", "--ide=claude-code", "--remove-routing")
	wantNames(t, "restored project file", serverNames(t, readConfig(t, projectMCP)["mcpServers"]), "late")
	if out, _, code := run(t, home, "configure-ide", "--ide=claude-code", "--remove-routing"); code != 0 || !strings.Contains(out, "not_configured") {
		t.Fatalf("second rollback exit=%d out=%s", code, out)
	}
}
