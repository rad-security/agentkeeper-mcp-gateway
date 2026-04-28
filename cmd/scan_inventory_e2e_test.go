// E2E tests for `scan-inventory`. Shares the test binary built by
// configure_ide_e2e_test.go's TestMain.
package cmd_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func scanWriteFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

type stdinReader struct{ s string }

func (r *stdinReader) Read(p []byte) (int, error) {
	if r.s == "" {
		return 0, io.EOF
	}
	n := copy(p, r.s)
	r.s = r.s[n:]
	return n, nil
}

// SCAN-01: empty home → empty inventory, no crash.
func TestScan01_EmptyHome(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}
	var payload struct {
		InstalledSkills    []any `json:"installed_skills"`
		InstalledMCPServer []any `json:"installed_mcp_servers"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if len(payload.InstalledSkills) != 0 || len(payload.InstalledMCPServer) != 0 {
		t.Errorf("empty home should produce empty arrays, got skills=%d mcp=%d",
			len(payload.InstalledSkills), len(payload.InstalledMCPServer))
	}
}

// SCAN-02: plugin-manifest skills are found.
func TestScan02_PluginManifestSkills(t *testing.T) {
	home := t.TempDir()
	installPath := filepath.Join(home, ".claude", "plugins", "cache", "org", "repo", "v1")
	scanWriteFixture(t, filepath.Join(installPath, "skills", "my-plugin-skill", "SKILL.md"), "# Plugin skill")
	scanWriteFixture(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
		`{"plugins":{"org/repo":[{"installPath":"`+installPath+`","scope":"user"}]}}`)

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		InstalledSkills []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"installed_skills"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.InstalledSkills) != 1 {
		t.Fatalf("want 1 plugin skill, got %d", len(payload.InstalledSkills))
	}
	if payload.InstalledSkills[0].Name != "my-plugin-skill" {
		t.Errorf("wrong name: %q", payload.InstalledSkills[0].Name)
	}
}

// SCAN-03: MCP servers in settings.json picked up.
func TestScan03_MCPServersInSettings(t *testing.T) {
	home := t.TempDir()
	scanWriteFixture(t, filepath.Join(home, ".claude", "settings.json"),
		`{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}}`)

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		InstalledMCPServer []struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"installed_mcp_servers"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.InstalledMCPServer) != 1 {
		t.Fatalf("want 1 server, got %d", len(payload.InstalledMCPServer))
	}
	got := payload.InstalledMCPServer[0]
	if got.Name != "github" || got.Type != "stdio" {
		t.Errorf("wrong shape: %+v", got)
	}
	if got.Command != "npx -y @modelcontextprotocol/server-github" {
		t.Errorf("command not joined: %q", got.Command)
	}
}

// SCAN-04: --cwd flag drives project-scoped discovery.
func TestScan04_ProjectCWDFlag(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	scanWriteFixture(t, filepath.Join(cwd, ".claude", "skills", "proj-skill", "SKILL.md"), "# proj")
	scanWriteFixture(t, filepath.Join(cwd, ".claude", "settings.json"),
		`{"mcpServers":{"proj-mcp":{"command":"node","args":["server.js"]}}}`)

	cmd := exec.Command(binary, "scan-inventory", "--dry-run", "--cwd", cwd)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		CWD                string `json:"cwd"`
		InstalledSkills    []any  `json:"installed_skills"`
		InstalledMCPServer []any  `json:"installed_mcp_servers"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CWD != cwd {
		t.Errorf("cwd not passed through: %q", payload.CWD)
	}
	if len(payload.InstalledSkills) != 1 {
		t.Errorf("want 1 project skill, got %d", len(payload.InstalledSkills))
	}
	if len(payload.InstalledMCPServer) != 1 {
		t.Errorf("want 1 project MCP server, got %d", len(payload.InstalledMCPServer))
	}
}

// SCAN-05: stdin envelope from Claude Code hook delivers cwd + claude_version.
func TestScan05_ProjectCWDFromStdin(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	scanWriteFixture(t, filepath.Join(cwd, ".claude", "skills", "from-stdin", "SKILL.md"), "# stdin")

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	envelope := `{"session_id":"s1","cwd":"` + cwd + `","hook_event_name":"SessionStart","claude_version":"0.2.76"}`
	cmd.Stdin = &stdinReader{s: envelope}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		CWD             string `json:"cwd"`
		ClaudeVersion   string `json:"claude_version"`
		InstalledSkills []any  `json:"installed_skills"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CWD != cwd {
		t.Errorf("cwd not extracted from stdin: %q", payload.CWD)
	}
	if payload.ClaudeVersion != "0.2.76" {
		t.Errorf("claude_version not extracted: %q", payload.ClaudeVersion)
	}
	if len(payload.InstalledSkills) != 1 {
		t.Errorf("project skill not discovered via stdin cwd")
	}
}

// SCAN-06: no API key + no --dry-run → exit 0 (fail-open).
func TestScan06_NoAPIKey_FailsOpen(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(binary, "scan-inventory")
	// Fresh env — no AGENTKEEPER_API_KEY, no config file.
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0; got %v\n%s", err, out)
	}
}

// SCAN-08: marketplace-cached skills are discovered end-to-end.
// Regression test for the Ontra customer report — layout:
//
//	~/.claude/plugins/marketplaces/<marketplace>/skills/<skill>/SKILL.md
//
// The skill should appear in the payload with source="marketplace" even
// when installed_plugins.json is empty (the marketplace cache is not a
// formal "install").
func TestScan08_MarketplaceCachedSkills(t *testing.T) {
	home := t.TempDir()
	marketplaceSkillDir := filepath.Join(home, ".claude", "plugins", "marketplaces", "secure-supply-chain", "skills", "supply-chain-hardening")
	scanWriteFixture(t, filepath.Join(marketplaceSkillDir, "SKILL.md"), "# supply-chain-hardening\ncontent")

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		InstalledSkills []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"installed_skills"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("output invalid JSON: %v\n%s", err, out)
	}
	if len(payload.InstalledSkills) != 1 {
		t.Fatalf("expected 1 marketplace skill, got %d: %+v", len(payload.InstalledSkills), payload.InstalledSkills)
	}
	if payload.InstalledSkills[0].Name != "supply-chain-hardening" {
		t.Errorf("unexpected skill name: %q", payload.InstalledSkills[0].Name)
	}
	if payload.InstalledSkills[0].Source != "marketplace" {
		t.Errorf("expected source=marketplace, got %q", payload.InstalledSkills[0].Source)
	}
}

// SCAN-07: malformed settings.json doesn't crash.
func TestScan07_MalformedSettingsDoesNotCrash(t *testing.T) {
	home := t.TempDir()
	scanWriteFixture(t, filepath.Join(home, ".claude", "settings.json"), "{ not valid json")

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("output invalid JSON: %v\n%s", err, out)
	}
}

// SCAN-09: dry-run includes Cowork posture when Claude Desktop data exists.
func TestScan09_CoworkPostureDryRun(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("scan-inventory uses the host OS to locate Claude Desktop app data")
	}
	home := t.TempDir()
	appDir := filepath.Join(home, "Library", "Application Support", "Claude")
	scanWriteFixture(t, filepath.Join(appDir, "claude_desktop_config.json"),
		`{"preferences":{"allowAllBrowserActions":true}}`)

	cmd := exec.Command(binary, "scan-inventory", "--dry-run")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error: %v\n%s", err, out)
	}
	var payload struct {
		CoworkPosture *struct {
			Source string `json:"source"`
			Score  int    `json:"score"`
			Grade  string `json:"grade"`
			Checks []struct {
				CheckName string `json:"check_name"`
				Status    string `json:"status"`
			} `json:"checks"`
		} `json:"cowork_posture"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("output invalid JSON: %v\n%s", err, out)
	}
	if payload.CoworkPosture == nil {
		t.Fatalf("expected cowork_posture in dry-run output: %s", out)
	}
	if payload.CoworkPosture.Source != "cowork_desktop_posture" {
		t.Fatalf("wrong posture source: %q", payload.CoworkPosture.Source)
	}
	foundBrowserFail := false
	for _, check := range payload.CoworkPosture.Checks {
		if check.CheckName == "Cowork Browser Actions" && check.Status == "FAIL" {
			foundBrowserFail = true
		}
	}
	if !foundBrowserFail {
		t.Fatalf("expected failing browser posture check: %+v", payload.CoworkPosture.Checks)
	}
}
