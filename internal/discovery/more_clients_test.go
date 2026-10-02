package discovery

import (
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
)

func TestDiscoverOptionalClients(t *testing.T) {
	files := map[string][]string{
		ClientWindsurf:    {".codeium", "windsurf", "mcp_config.json"},
		ClientGeminiCLI:   {".gemini", "settings.json"},
		ClientAntigravity: {".gemini", "antigravity", "mcp_config.json"},
		ClientKiro:        {".kiro", "settings", "mcp.json"},
	}
	home := t.TempDir()
	for client, elements := range files {
		writeFixture(t, filepath.Join(append([]string{home}, elements...)...), `{
			"mcpServers": {"`+client+`-notes": {"command": "node", "args": ["notes.js"]}}
		}`)
	}
	for client := range files {
		res, err := Discover(Options{Home: home, Client: client})
		if err != nil {
			t.Fatalf("%s: %v", client, err)
		}
		if len(res.Servers) != 1 {
			t.Fatalf("%s: want 1 server, got %+v", client, res.Servers)
		}
		got := res.Servers[0]
		if got.Name != client+"-notes" || got.Client != client || !got.Routable || got.RouteState != RouteDirect {
			t.Errorf("%s: unexpected discovery: %+v", client, got)
		}
	}

	all, err := Discover(Options{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, server := range all.Servers {
		seen[server.Client] = true
	}
	for client := range files {
		if !seen[client] {
			t.Errorf("discovering every client misses %s: %+v", client, all.Servers)
		}
	}
}

// configure-ide and discovery must agree on where each client keeps its
// servers, or a routed client would show as unrouted.
func TestOptionalClientPathsMatchTheRoutingAdapters(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	paths := OptionalClientConfigPaths(home)
	adapters := ideconfig.OptionalAdapters()
	if len(paths) != len(adapters) {
		t.Fatalf("discovery knows %d optional clients, routing knows %d", len(paths), len(adapters))
	}
	for _, adapter := range adapters {
		want, err := adapter.PathResolver()
		if err != nil {
			t.Fatal(err)
		}
		if paths[adapter.Name] != want {
			t.Errorf("%s: discovery reads %q, routing writes %q", adapter.Name, paths[adapter.Name], want)
		}
	}
}

func TestDiscoverRejectsAnUnknownClient(t *testing.T) {
	if _, err := Discover(Options{Home: t.TempDir(), Client: "emacs"}); err == nil {
		t.Fatal("expected an error for an unknown client")
	}
}
