package cmd_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestListEmptyStateIsAutomaticFirst(t *testing.T) {
	home := t.TempDir()
	out, stderr, code := run(t, home, "list")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"No routed MCP servers configured.",
		"agentkeeper-mcp-gateway configure-ide --dry-run",
		"agentkeeper-mcp-gateway configure-ide",
		"Manual fallback/admin:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestListHealthShowsDiscoveredSeenOnly(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {"GITHUB_TOKEN": "secret"}
			}
		}
	}`)

	out, stderr, code := run(t, home, "list", "--health")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"Discovered local config servers: 1",
		"Seen only: 1",
		"github",
		"cursor",
		"configure-ide --dry-run",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("health output leaked secret:\n%s", out)
	}
}

func TestListHealthTreatsDirectConfigAsSeenOnlyEvenWhenBackendExists(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"]
			}
		}
	}`)
	writeGatewayConfig(t, home, `{
		"mode": "audit",
		"servers": [{
			"name": "github",
			"command": "npx",
			"args": ["-y", "@modelcontextprotocol/server-github"]
		}]
	}`)

	out, stderr, code := run(t, home, "list", "--health")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"Routed servers: 1",
		"Discovered local config servers: 1",
		"Seen only: 1",
		"Run agentkeeper-mcp-gateway configure-ide --dry-run",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestListHealthJSONForMDMStatus(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "claude-code", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "`+filepath.ToSlash(filepath.Join(home, "repo"))+`"]
			}
		}
	}`)

	out, stderr, code := run(t, home, "list", "--health", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var report struct {
		DashboardConnected bool `json:"dashboard_connected"`
		RoutedServers      []struct {
			Name string `json:"name"`
		} `json:"routed_servers"`
		DiscoveredServers []struct {
			Name   string `json:"name"`
			Client string `json:"client"`
		} `json:"discovered_servers"`
		SeenOnlyCount int      `json:"seen_only_count"`
		NextSteps     []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parsing json: %v\n%s", err, out)
	}
	if report.DashboardConnected {
		t.Fatalf("expected local-only dashboard state")
	}
	if len(report.RoutedServers) != 0 {
		t.Fatalf("unexpected routed servers: %+v", report.RoutedServers)
	}
	if len(report.DiscoveredServers) != 1 || report.DiscoveredServers[0].Name != "filesystem" {
		t.Fatalf("unexpected discovered servers: %+v", report.DiscoveredServers)
	}
	if report.SeenOnlyCount != 1 {
		t.Fatalf("want seen_only_count=1, got %d", report.SeenOnlyCount)
	}
	if strings.Join(report.NextSteps, "\n") == "" || !strings.Contains(strings.Join(report.NextSteps, "\n"), "configure-ide") {
		t.Fatalf("missing configure-ide next step: %+v", report.NextSteps)
	}
}
