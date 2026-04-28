package skillinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedSkill writes a dummy SKILL.md under `dir/<name>/SKILL.md`.
func seedSkill(t *testing.T, dir, name, content string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, name, "SKILL.md"), content)
}

func TestScan_EmptyHome(t *testing.T) {
	home := t.TempDir()
	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Skills) != 0 {
		t.Errorf("empty home → expected 0 skills, got %d", len(inv.Skills))
	}
	if len(inv.MCPServers) != 0 {
		t.Errorf("empty home → expected 0 MCP servers, got %d", len(inv.MCPServers))
	}
}

func TestScan_StandaloneGlobalSkills(t *testing.T) {
	home := t.TempDir()
	seedSkill(t, filepath.Join(home, ".claude", "skills"), "my-skill", "# My Skill\nDoes a thing.")
	seedSkill(t, filepath.Join(home, ".claude", "skills"), "another", "# Another\nAlso does things.")

	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Skills) != 2 {
		t.Fatalf("want 2 skills, got %d", len(inv.Skills))
	}
	for _, s := range inv.Skills {
		if s.Source != "global" {
			t.Errorf("expected global source, got %q for %s", s.Source, s.Name)
		}
		if s.Hash == "" {
			t.Errorf("missing hash for %s", s.Name)
		}
		if s.Preview == "" {
			t.Errorf("missing preview for %s", s.Name)
		}
	}
}

func TestScan_PluginInstalledSkillsViaManifest(t *testing.T) {
	home := t.TempDir()

	// Simulate a plugin install: manifest points at an install path with skills.
	installPath := filepath.Join(home, ".claude", "plugins", "cache", "org", "repo", "v1")
	seedSkill(t, filepath.Join(installPath, "skills"), "plugin-skill-1", "# Plugin 1")
	seedSkill(t, filepath.Join(installPath, "skills"), "plugin-skill-2", "# Plugin 2")

	manifest := map[string]any{
		"plugins": map[string]any{
			"org/repo": []map[string]any{
				{
					"installPath": installPath,
					"scope":       "user",
				},
			},
		},
	}
	data, _ := json.Marshal(manifest)
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), string(data))

	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Skills) != 2 {
		t.Fatalf("want 2 plugin skills, got %d: %+v", len(inv.Skills), inv.Skills)
	}
	for _, s := range inv.Skills {
		if s.Source != "global" {
			t.Errorf("manifest scope=user should map to global; got %q for %s", s.Source, s.Name)
		}
	}
}

func TestScan_PluginProjectScopeManifest(t *testing.T) {
	home := t.TempDir()

	installPath := filepath.Join(home, ".claude", "plugins", "cache", "proj", "plugin", "v1")
	seedSkill(t, filepath.Join(installPath, "skills"), "proj-skill", "# Proj")

	manifest := map[string]any{
		"plugins": map[string]any{
			"proj/plugin": []map[string]any{
				{"installPath": installPath, "scope": "project"},
			},
		},
	}
	data, _ := json.Marshal(manifest)
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), string(data))

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.Skills) != 1 {
		t.Fatalf("want 1 skill, got %d", len(inv.Skills))
	}
	if inv.Skills[0].Source != "project" {
		t.Errorf("scope=project should surface as project source; got %q", inv.Skills[0].Source)
	}
}

func TestScan_ManifestMissing_FallbackCacheGlob(t *testing.T) {
	home := t.TempDir()
	// No manifest at all; the scanner should fall back to the cache glob.
	cachePath := filepath.Join(home, ".claude", "plugins", "cache", "org", "repo", "v1")
	seedSkill(t, filepath.Join(cachePath, "skills"), "cached-skill", "# Cached")

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.Skills) != 1 {
		t.Fatalf("fallback glob should find the cached skill; got %d", len(inv.Skills))
	}
}

func TestScan_MarketplaceCachedSkills_SkillsUnderMarketplace(t *testing.T) {
	// Real-world layout observed at customer (Ontra / secure-supply-chain):
	//   ~/.claude/plugins/marketplaces/<marketplace>/skills/<skill>/SKILL.md
	home := t.TempDir()
	marketplaceSkillDir := filepath.Join(home, ".claude", "plugins", "marketplaces", "secure-supply-chain", "skills")
	seedSkill(t, marketplaceSkillDir, "supply-chain-hardening", "# supply-chain-hardening\ncontent")
	seedSkill(t, marketplaceSkillDir, "another-mkt-skill", "# another\ncontent")

	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Skills) != 2 {
		t.Fatalf("want 2 marketplace skills, got %d: %+v", len(inv.Skills), inv.Skills)
	}
	for _, s := range inv.Skills {
		if s.Source != "marketplace" {
			t.Errorf("expected source=marketplace for %s, got %q", s.Name, s.Source)
		}
		if s.Platform != PlatformClaudeCode {
			t.Errorf("expected platform=%s for %s, got %q", PlatformClaudeCode, s.Name, s.Platform)
		}
		if s.Hash == "" || s.Preview == "" {
			t.Errorf("marketplace skill %s missing hash/preview", s.Name)
		}
	}
}

func TestScan_MarketplaceCachedSkills_PluginsNested(t *testing.T) {
	// Alternate layout where a marketplace groups skills by plugin:
	//   ~/.claude/plugins/marketplaces/<m>/plugins/<plugin>/skills/<skill>/SKILL.md
	home := t.TempDir()
	pluginSkillsDir := filepath.Join(home, ".claude", "plugins", "marketplaces", "some-mkt", "plugins", "scanner-plugin", "skills")
	seedSkill(t, pluginSkillsDir, "nested-mkt-skill", "# nested\ncontent")

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.Skills) != 1 {
		t.Fatalf("want 1 nested-plugin marketplace skill, got %d", len(inv.Skills))
	}
	if inv.Skills[0].Source != "marketplace" {
		t.Errorf("expected source=marketplace, got %q", inv.Skills[0].Source)
	}
	if inv.Skills[0].Name != "nested-mkt-skill" {
		t.Errorf("expected name=nested-mkt-skill, got %q", inv.Skills[0].Name)
	}
}

func TestScan_MarketplaceAndInstalledAreDistinct(t *testing.T) {
	// When the same skill name exists in an installed plugin AND in a
	// marketplace cache, both rows should surface (distinct source values).
	home := t.TempDir()

	// Installed plugin with a "shared" skill
	installPath := filepath.Join(home, ".claude", "plugins", "cache", "org", "repo", "v1")
	seedSkill(t, filepath.Join(installPath, "skills"), "shared", "# installed")
	manifest := map[string]any{
		"plugins": map[string]any{
			"org/repo": []map[string]any{{"installPath": installPath, "scope": "user"}},
		},
	}
	data, _ := json.Marshal(manifest)
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), string(data))

	// Marketplace-cached "shared" skill
	seedSkill(t, filepath.Join(home, ".claude", "plugins", "marketplaces", "some-mkt", "skills"), "shared", "# marketplace")

	inv, _ := Scan(ScanOptions{Home: home})
	sourceCount := map[string]int{}
	for _, s := range inv.Skills {
		if s.Name == "shared" {
			sourceCount[s.Source]++
		}
	}
	if sourceCount["global"] != 1 {
		t.Errorf("want 1 global-source `shared`, got %d", sourceCount["global"])
	}
	if sourceCount["marketplace"] != 1 {
		t.Errorf("want 1 marketplace-source `shared`, got %d", sourceCount["marketplace"])
	}
}

func TestScan_ProjectScopeSkills(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	seedSkill(t, filepath.Join(cwd, ".claude", "skills"), "proj-only", "# Project only")

	inv, _ := Scan(ScanOptions{Home: home, CWD: cwd})
	if len(inv.Skills) != 1 {
		t.Fatalf("want 1 project skill, got %d", len(inv.Skills))
	}
	if inv.Skills[0].Source != "project" {
		t.Errorf("expected project source, got %q", inv.Skills[0].Source)
	}
}

func TestScan_MCPServersFromGlobalSettings(t *testing.T) {
	home := t.TempDir()
	settings := map[string]any{
		"mcpServers": map[string]any{
			"github": map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-github"},
			},
			"remote-sse": map[string]any{
				"type": "http",
				"url":  "https://api.example.com/mcp/sse",
			},
		},
	}
	data, _ := json.Marshal(settings)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), string(data))

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.MCPServers) != 2 {
		t.Fatalf("want 2 MCP servers, got %d: %+v", len(inv.MCPServers), inv.MCPServers)
	}

	byName := map[string]MCPServer{}
	for _, s := range inv.MCPServers {
		byName[s.Name] = s
	}

	gh := byName["github"]
	if gh.Type != "stdio" {
		t.Errorf("github type: want stdio, got %q", gh.Type)
	}
	if gh.Command != "npx -y @modelcontextprotocol/server-github" {
		t.Errorf("github command: want joined args, got %q", gh.Command)
	}
	if gh.Source != "global" {
		t.Errorf("github source: want global, got %q", gh.Source)
	}

	remote := byName["remote-sse"]
	if remote.Type != "http" {
		t.Errorf("remote-sse type: want http, got %q", remote.Type)
	}
}

func TestScan_MCPServersFromProjectSettings(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	settings := map[string]any{
		"mcpServers": map[string]any{
			"project-pg": map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-postgres"},
			},
		},
	}
	data, _ := json.Marshal(settings)
	writeFile(t, filepath.Join(cwd, ".claude", "settings.json"), string(data))

	inv, _ := Scan(ScanOptions{Home: home, CWD: cwd})
	if len(inv.MCPServers) != 1 {
		t.Fatalf("want 1 project MCP server, got %d", len(inv.MCPServers))
	}
	if inv.MCPServers[0].Source != "project" {
		t.Errorf("want project source, got %q", inv.MCPServers[0].Source)
	}
}

func TestScan_MalformedSettingsJSON_DoesNotCrash(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), "{ not valid json")

	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatalf("malformed json should not error; got %v", err)
	}
	if len(inv.MCPServers) != 0 {
		t.Errorf("malformed json → expected 0 servers, got %d", len(inv.MCPServers))
	}
}

func TestScan_NoDuplicatesAcrossPaths(t *testing.T) {
	home := t.TempDir()

	// Same skill name appears via both the manifest and the fallback glob.
	installPath := filepath.Join(home, ".claude", "plugins", "cache", "org", "repo", "v1")
	seedSkill(t, filepath.Join(installPath, "skills"), "shared", "# Shared")

	manifest := map[string]any{
		"plugins": map[string]any{
			"org/repo": []map[string]any{
				{"installPath": installPath, "scope": "user"},
			},
		},
	}
	data, _ := json.Marshal(manifest)
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), string(data))

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.Skills) != 1 {
		t.Fatalf("deduplication broken: expected 1 skill, got %d", len(inv.Skills))
	}
}

func TestBuildPayload_HasAllFields(t *testing.T) {
	inv := Inventory{
		Skills:     []Skill{{Name: "x", Source: "global"}},
		MCPServers: []MCPServer{{Name: "y", Type: "stdio", Source: "global"}},
	}
	p := BuildPayload(inv, "/tmp/cwd", "0.2.76", "abc123")
	if p.CWD != "/tmp/cwd" {
		t.Errorf("cwd not passed through: %q", p.CWD)
	}
	if p.ClaudeVersion != "0.2.76" {
		t.Errorf("claude_version not passed through: %q", p.ClaudeVersion)
	}
	if p.MachineID != "abc123" {
		t.Errorf("machine_id not passed through: %q", p.MachineID)
	}
	if p.Source != "gateway-scan-inventory" {
		t.Errorf("source tag missing / wrong: %q", p.Source)
	}
	if len(p.InstalledSkills) != 1 || len(p.InstalledMCPServer) != 1 {
		t.Errorf("skills/mcp arrays not passed through")
	}
}

// --- Cowork (Claude Desktop) ------------------------------------------------

// coworkAppSupportDir varies by runtime.GOOS, which we can't change at test
// time. These tests seed whichever dir the current OS's helper would pick,
// using the same helper so the test reflects production behavior.
//
// The helper is in the scanner package and already resolves the right dir
// for the OS we're running on (macOS on dev, Linux in CI).

func TestScan_CCPlatformTagOnAllCCEntries(t *testing.T) {
	home := t.TempDir()
	seedSkill(t, filepath.Join(home, ".claude", "skills"), "cc-skill", "# CC")
	settings := map[string]any{
		"mcpServers": map[string]any{
			"gh": map[string]any{"command": "npx", "args": []string{"gh"}},
		},
	}
	data, _ := json.Marshal(settings)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), string(data))

	inv, _ := Scan(ScanOptions{Home: home})

	if len(inv.Skills) != 1 || inv.Skills[0].Platform != PlatformClaudeCode {
		t.Errorf("CC skill should carry platform=claude_code; got %+v", inv.Skills)
	}
	if len(inv.MCPServers) != 1 || inv.MCPServers[0].Platform != PlatformClaudeCode {
		t.Errorf("CC MCP server should carry platform=claude_code; got %+v", inv.MCPServers)
	}
}

func TestScan_CoworkPersistentSkills(t *testing.T) {
	home := t.TempDir()
	appSupport := coworkAppSupportDir(home)
	if appSupport == "" {
		t.Skip("no cowork app-support dir on this OS")
	}

	// Persistent skill under skills-plugin/<session-id>/skills/<name>/SKILL.md
	persistentDir := filepath.Join(appSupport, "local-agent-mode-sessions", "skills-plugin", "session-abc", "skills")
	seedSkill(t, persistentDir, "compliance-auditor", "# Compliance Auditor\nAudits compliance.")

	inv, err := Scan(ScanOptions{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Skills) != 1 {
		t.Fatalf("want 1 cowork skill, got %d: %+v", len(inv.Skills), inv.Skills)
	}
	s := inv.Skills[0]
	if s.Name != "compliance-auditor" {
		t.Errorf("wrong name: %q", s.Name)
	}
	if s.Platform != PlatformClaudeDesktop {
		t.Errorf("cowork skill should carry platform=claude_desktop; got %q", s.Platform)
	}
	if s.Hash == "" || s.Preview == "" {
		t.Errorf("cowork skill missing hash/preview")
	}
}

func TestScan_CoworkEphemeralSessionSkillsSkipped(t *testing.T) {
	home := t.TempDir()
	appSupport := coworkAppSupportDir(home)
	if appSupport == "" {
		t.Skip("no cowork app-support dir on this OS")
	}

	// Ephemeral per-session skill under local_<uuid> — MUST NOT be scanned
	// (anthropics/claude-code#31422).
	ephemeralDir := filepath.Join(appSupport, "local-agent-mode-sessions", "sess-123", "local_abcdef", ".claude", "skills")
	seedSkill(t, ephemeralDir, "user-scratch", "# User Scratch")

	inv, _ := Scan(ScanOptions{Home: home})
	for _, s := range inv.Skills {
		if s.Name == "user-scratch" {
			t.Errorf("ephemeral session skill must not be surfaced; got %+v", s)
		}
	}
}

func TestScan_CoworkMCPServersFromDesktopConfig(t *testing.T) {
	home := t.TempDir()
	cfgPath := coworkDesktopConfigPath(home)
	if cfgPath == "" {
		t.Skip("no cowork config path on this OS")
	}

	cfg := map[string]any{
		"mcpServers": map[string]any{
			"notion": map[string]any{"command": "npx", "args": []string{"@notionhq/mcp"}},
			"remote": map[string]any{"type": "http", "url": "https://mcp.example.com"},
		},
	}
	data, _ := json.Marshal(cfg)
	writeFile(t, cfgPath, string(data))

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.MCPServers) != 2 {
		t.Fatalf("want 2 cowork mcp servers, got %d: %+v", len(inv.MCPServers), inv.MCPServers)
	}
	for _, s := range inv.MCPServers {
		if s.Platform != PlatformClaudeDesktop {
			t.Errorf("cowork mcp server should carry platform=claude_desktop; got %q for %s", s.Platform, s.Name)
		}
	}
}

func TestScan_MixedCCandCoworkCoexistByPlatform(t *testing.T) {
	home := t.TempDir()
	appSupport := coworkAppSupportDir(home)
	if appSupport == "" {
		t.Skip("no cowork app-support dir on this OS")
	}

	// Same skill NAME on both platforms — must be captured twice with
	// distinct platform values so the server can preserve both.
	seedSkill(t, filepath.Join(home, ".claude", "skills"), "aws-cli", "# CC AWS CLI")
	seedSkill(
		t,
		filepath.Join(appSupport, "local-agent-mode-sessions", "skills-plugin", "s1", "skills"),
		"aws-cli",
		"# Cowork AWS CLI",
	)

	inv, _ := Scan(ScanOptions{Home: home})
	if len(inv.Skills) != 2 {
		t.Fatalf("same-name skills across platforms should yield 2 rows; got %d", len(inv.Skills))
	}
	platforms := map[string]bool{}
	for _, s := range inv.Skills {
		platforms[s.Platform] = true
	}
	if !platforms[PlatformClaudeCode] || !platforms[PlatformClaudeDesktop] {
		t.Errorf("expected both platforms present; got %+v", platforms)
	}
}
