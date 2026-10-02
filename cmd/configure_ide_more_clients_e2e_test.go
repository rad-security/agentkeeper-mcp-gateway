// End-to-end tests for routing Windsurf, Gemini CLI, Antigravity and Kiro
// with `configure-ide`. They run the compiled binary against a fresh $HOME.
package cmd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var optionalClientPaths = map[string][]string{
	"windsurf":    {".codeium", "windsurf", "mcp_config.json"},
	"gemini-cli":  {".gemini", "settings.json"},
	"antigravity": {".gemini", "antigravity", "mcp_config.json"},
	"kiro":        {".kiro", "settings", "mcp.json"},
}

func optionalClientPath(home, client string) string {
	return filepath.Join(append([]string{home}, optionalClientPaths[client]...)...)
}

func writeOptionalClient(t *testing.T, home, client, body string) string {
	t.Helper()
	path := optionalClientPath(home, client)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func routeClientOf(t *testing.T, path string) string {
	t.Helper()
	var servers map[string]struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(readConfig(t, path)["mcpServers"], &servers); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return servers["agentkeeper-mcp-gateway"].Env["AGENTKEEPER_MCP_CLIENT"]
}

// Routing everything must not leave config files behind for clients the
// developer does not have.
func TestE2EMoreClients_RoutingEverythingSkipsClientsThatAreNotInstalled(t *testing.T) {
	home := t.TempDir()
	out, stderr, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for client := range optionalClientPaths {
		if _, err := os.Stat(optionalClientPath(home, client)); !os.IsNotExist(err) {
			t.Errorf("%s config was created for a client that is not installed (err=%v)", client, err)
		}
		if strings.Contains(out, client) {
			t.Errorf("output mentions %s:\n%s", client, out)
		}
	}
	assertGatewayWired(t, ideConfigPath(home, "cursor"))
}

func TestE2EMoreClients_RoutingEverythingIncludesAClientWhoseConfigExists(t *testing.T) {
	for client := range optionalClientPaths {
		t.Run(client, func(t *testing.T) {
			home := t.TempDir()
			path := writeOptionalClient(t, home, client, `{"mcpServers": {"fixture": {"command": "fixture-server", "args": ["--stdio"]}}}`)
			out, stderr, code := run(t, home, "configure-ide")
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}
			if !strings.Contains(out, client) || !strings.Contains(out, "migrate 1 + wire") {
				t.Errorf("output does not report routing %s:\n%s", client, out)
			}
			assertGatewayWired(t, path)
			if got := routeClientOf(t, path); got != client {
				t.Errorf("route client = %q, want %q", got, client)
			}
			gateway, _ := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
			if !strings.Contains(string(gateway), `"fixture"`) {
				t.Errorf("the server was not moved into the Gateway config:\n%s", gateway)
			}
		})
	}
}

func TestE2EMoreClients_NamingAClientCreatesItsConfig(t *testing.T) {
	home := t.TempDir()
	out, stderr, code := run(t, home, "configure-ide", "--ide=kiro")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "kiro") || !strings.Contains(out, "create") {
		t.Errorf("output does not report creating the Kiro config:\n%s", out)
	}
	assertGatewayWired(t, optionalClientPath(home, "kiro"))
	if _, err := os.Stat(ideConfigPath(home, "cursor")); !os.IsNotExist(err) {
		t.Errorf("--ide=kiro also touched Cursor (err=%v)", err)
	}
}

func TestE2EMoreClients_DryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	body := `{"mcpServers": {"fixture": {"command": "fixture-server"}}}`
	path := writeOptionalClient(t, home, "windsurf", body)
	out, stderr, code := run(t, home, "configure-ide", "--ide=windsurf", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "would migrate 1 + wire") {
		t.Errorf("unexpected preview:\n%s", out)
	}
	after, _ := os.ReadFile(path)
	if string(after) != body {
		t.Errorf("the dry run changed the file:\n%s", after)
	}
}

// Windsurf and Antigravity name a remote server with serverUrl, Gemini CLI
// with httpUrl. The preview must say which server stays in the client.
func TestE2EMoreClients_PreviewNamesARemoteServerByItsAddress(t *testing.T) {
	home := t.TempDir()
	writeOptionalClient(t, home, "windsurf", `{"mcpServers": {
		"docs": {"serverUrl": "https://mcp.example.test/sse"},
		"notes": {"command": "node", "args": ["notes.js"]}
	}}`)
	out, stderr, code := run(t, home, "configure-ide", "--ide=windsurf", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "-> keep native: docs (https://mcp.example.test/sse)") {
		t.Errorf("preview does not name the remote server by its address:\n%s", out)
	}
	if !strings.Contains(out, "-> migrate: notes (node notes.js)") {
		t.Errorf("preview does not list the local server:\n%s", out)
	}
}

func TestE2EMoreClients_RemoveRoutingRestoresTheOriginalBytes(t *testing.T) {
	home := t.TempDir()
	body := "{\n  \"theme\": \"Default\",\n  \"mcpServers\": {\"fixture\": {\"command\": \"fixture-server\", \"trust\": true}}\n}\n"
	path := writeOptionalClient(t, home, "gemini-cli", body)
	if _, stderr, code := run(t, home, "configure-ide"); code != 0 {
		t.Fatalf("configure exit=%d stderr=%s", code, stderr)
	}
	if got := routeClientOf(t, path); got != "gemini-cli" {
		t.Fatalf("route client = %q, want gemini-cli", got)
	}
	// Without --ide, rollback covers every client configure-ide can route.
	out, stderr, code := run(t, home, "configure-ide", "--remove-routing")
	if code != 0 {
		t.Fatalf("remove exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(out, `"gemini-cli"`) {
		t.Errorf("rollback report does not name gemini-cli:\n%s", out)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, []byte(body)) {
		t.Errorf("rollback changed the original bytes\n got: %s\nwant: %s", restored, body)
	}
}

func TestE2EMoreClients_UnknownClientErrorNamesEveryClient(t *testing.T) {
	_, stderr, code := run(t, t.TempDir(), "configure-ide", "--ide=emacs")
	if code == 0 {
		t.Fatal("expected a nonzero exit")
	}
	for _, client := range []string{"claude-code", "claude-desktop", "cursor", "cowork", "windsurf", "gemini-cli", "antigravity", "kiro"} {
		if !strings.Contains(stderr, client) {
			t.Errorf("error does not name %s: %s", client, stderr)
		}
	}
}

func TestE2EMoreClients_ListHealthShowsARoutedOptionalClient(t *testing.T) {
	home := t.TempDir()
	writeOptionalClient(t, home, "windsurf", `{"mcpServers": {"fixture": {"command": "fixture-server"}}}`)
	if _, stderr, code := run(t, home, "configure-ide", "--ide=windsurf"); code != 0 {
		t.Fatalf("configure exit=%d stderr=%s", code, stderr)
	}
	out, stderr, code := run(t, home, "list", "--health")
	if code != 0 {
		t.Fatalf("list exit=%d stderr=%s", code, stderr)
	}
	routed := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "windsurf") && strings.Contains(line, "routed") {
			routed = true
		}
	}
	if !routed {
		t.Errorf("list --health does not show the Windsurf route:\n%s", out)
	}
}
