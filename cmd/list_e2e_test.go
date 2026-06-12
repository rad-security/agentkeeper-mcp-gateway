package cmd_test

import (
	"encoding/json"
	"os"
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

func TestListHealthReportsRemoteAuthRequired(t *testing.T) {
	home := t.TempDir()

	writeGatewayConfig(t, home, `{
		"mode": "audit",
		"servers": [{
			"name": "notion",
			"transport": "http",
			"url": "https://mcp.notion.com/mcp"
		}]
	}`)

	out, stderr, code := run(t, home, "list", "--health", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var report struct {
		ToolManifestStatus string `json:"tool_manifest_status"`
		BackendToolHealth  []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"backend_tool_health"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parsing json: %v\n%s", err, out)
	}
	if report.ToolManifestStatus != "action_required" {
		t.Fatalf("expected action_required, got %q in %s", report.ToolManifestStatus, out)
	}
	if len(report.BackendToolHealth) != 1 || report.BackendToolHealth[0].Name != "notion" || report.BackendToolHealth[0].Status != "auth_required" {
		t.Fatalf("unexpected backend health: %+v\n%s", report.BackendToolHealth, out)
	}
	if !strings.Contains(strings.Join(report.NextSteps, "\n"), "auth_required") {
		t.Fatalf("missing auth next step: %+v", report.NextSteps)
	}
}

func TestListHealthReportsRemoteAuthConfigured(t *testing.T) {
	home := t.TempDir()

	writeGatewayConfig(t, home, `{
		"mode": "audit",
		"servers": [{
			"name": "notion",
			"transport": "http",
			"url": "https://mcp.notion.com/mcp",
			"headers": {"Authorization": "Bearer test"}
		}]
	}`)

	out, stderr, code := run(t, home, "list", "--health", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var report struct {
		ToolManifestStatus string `json:"tool_manifest_status"`
		BackendToolHealth  []struct {
			Name      string `json:"name"`
			Status    string `json:"status"`
			ToolCount int    `json:"tool_count"`
		} `json:"backend_tool_health"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parsing json: %v\n%s", err, out)
	}
	if report.ToolManifestStatus != "pending" {
		t.Fatalf("expected pending until a real tool call observes tools, got %q in %s", report.ToolManifestStatus, out)
	}
	if len(report.BackendToolHealth) != 1 || report.BackendToolHealth[0].Status != "auth_configured" || report.BackendToolHealth[0].ToolCount != 0 {
		t.Fatalf("unexpected backend health: %+v\n%s", report.BackendToolHealth, out)
	}
}

func TestListHealthReportsObservedToolCalls(t *testing.T) {
	home := t.TempDir()
	logPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")

	writeGatewayConfig(t, home, `{
		"mode": "audit",
		"log_path": "`+filepath.ToSlash(logPath)+`",
		"servers": [
			{
				"name": "supabase",
				"command": "npx",
				"args": ["-y", "@supabase/mcp-server-supabase"]
			},
			{
				"name": "google-drive",
				"transport": "http",
				"url": "https://drivemcp.googleapis.com/mcp/v1"
			}
		]
	}`)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(`{"timestamp":"2026-06-12T00:09:18.571889Z","event_type":"mcp.tool_call","server_name":"supabase","tool_name":"search_docs","verdict":"pass"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := run(t, home, "list", "--health", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var report struct {
		ToolManifestStatus string `json:"tool_manifest_status"`
		BackendToolHealth  []struct {
			Name         string `json:"name"`
			Status       string `json:"status"`
			LastToolName string `json:"last_tool_name"`
			LastCallAt   string `json:"last_call_at"`
		} `json:"backend_tool_health"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parsing json: %v\n%s", err, out)
	}
	if report.ToolManifestStatus != "observed" {
		t.Fatalf("expected observed after local tool call evidence, got %q in %s", report.ToolManifestStatus, out)
	}
	byName := map[string]struct {
		Status       string
		LastToolName string
		LastCallAt   string
	}{}
	for _, h := range report.BackendToolHealth {
		byName[h.Name] = struct {
			Status       string
			LastToolName string
			LastCallAt   string
		}{Status: h.Status, LastToolName: h.LastToolName, LastCallAt: h.LastCallAt}
	}
	if got := byName["supabase"]; got.Status != "calls_observed" || got.LastToolName != "search_docs" || got.LastCallAt == "" {
		t.Fatalf("supabase should report observed call evidence, got %+v in %s", got, out)
	}
	if got := byName["google-drive"]; got.Status != "pending" {
		t.Fatalf("google-drive should remain pending until its own call, got %+v in %s", got, out)
	}
	if !strings.Contains(strings.Join(report.NextSteps, "\n"), "make one real harmless tool call") {
		t.Fatalf("missing next step for remaining pending backends: %+v", report.NextSteps)
	}
}
