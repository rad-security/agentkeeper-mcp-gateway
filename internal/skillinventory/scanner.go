// Package skillinventory scans a developer laptop for installed Claude Code
// skills and MCP servers, and reports the inventory to the AgentKeeper
// dashboard via /api/v1/claude-code/checkin.
//
// This exists as a gateway binary subcommand (`scan-inventory`) so the same
// single endpoint agent can handle:
//
//   - MCP proxy (server)
//   - IDE config rewiring (configure-ide)
//   - Inventory reporting (scan-inventory) ← this package
//
// ...without requiring a separate Claude Code plugin install. The Kandji /
// Jamf / MDM path becomes: install one binary, point a SessionStart hook at
// `type: command` -> `/usr/local/bin/agentkeeper-mcp-gateway scan-inventory`.
//
// Logic mirrors plugin/skills/connect/SKILL.md collect_skills + collect_mcp
// byte-for-byte so both paths report identical data to the same endpoint.
package skillinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Platform discriminates Claude Code vs Claude Desktop (Cowork) inventory.
// Empty/absent on wire is interpreted server-side as "claude_code" for
// backwards compatibility with older gateway releases.
const (
	PlatformClaudeCode    = "claude_code"
	PlatformClaudeDesktop = "claude_desktop"
)

// Skill represents one installed skill, from either agent surface.
type Skill struct {
	Name     string `json:"name"`
	Source   string `json:"source"`   // "global" or "project"
	Platform string `json:"platform"` // "claude_code" or "claude_desktop"
	Preview  string `json:"preview"`  // first 300 bytes of SKILL.md
	Hash     string `json:"hash"`     // SHA-256 of SKILL.md
}

// MCPServer represents one configured MCP server, from either agent surface.
type MCPServer struct {
	Name     string `json:"name"`
	Type     string `json:"type"`              // "stdio" or "http"
	Command  string `json:"command,omitempty"` // stdio: joined command+args
	Source   string `json:"source"`            // "global" or "project"
	Platform string `json:"platform"`          // "claude_code" or "claude_desktop"
}

// Inventory is the full payload captured from this laptop.
type Inventory struct {
	Skills     []Skill     `json:"installed_skills"`
	MCPServers []MCPServer `json:"installed_mcp_servers"`
}

// ScanOptions controls where the scanner looks.
type ScanOptions struct {
	// Home is the user's home directory. Defaults to os.UserHomeDir().
	Home string
	// CWD is the Claude Code session's working directory. When empty,
	// project-scoped skills + project settings.json are skipped.
	CWD string
}

// Scan walks all known skill + MCP locations and returns the combined inventory.
// Errors on individual files are swallowed by design — the checkin is
// fail-open, and a single unreadable SKILL.md should not drop the whole scan.
func Scan(opts ScanOptions) (Inventory, error) {
	home := opts.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Inventory{}, fmt.Errorf("resolving home dir: %w", err)
		}
		home = h
	}

	inv := Inventory{
		Skills:     scanSkills(home, opts.CWD),
		MCPServers: scanMCPServers(home, opts.CWD),
	}
	return inv, nil
}

// --- skills -----------------------------------------------------------------

// scanSkills mirrors collect_skills() in plugin/skills/connect/SKILL.md.
//
// Locations, in order:
//  1. ~/.claude/skills/*/SKILL.md                                    (global standalone)
//  2. <cwd>/.claude/skills/*/SKILL.md                                (project standalone)
//  3. plugin installs read from installed_plugins.json manifest, then fallback-globbed
// 3c. ~/.claude/plugins/marketplaces/*/skills/*/SKILL.md             (marketplace-cached, "marketplace" source)
//  4. <cwd>/.claude/plugins/*/*/skills/*/SKILL.md                    (project-level plugin installs)
//  5. Cowork (Claude Desktop) persistent skills
func scanSkills(home, cwd string) []Skill {
	skills := []Skill{}
	seen := map[string]bool{}

	add := func(skillMDPath, source, platform string) {
		name := filepath.Base(filepath.Dir(skillMDPath))
		key := name + "|" + source + "|" + platform
		if seen[key] {
			return
		}
		seen[key] = true
		skills = append(skills, Skill{
			Name:     name,
			Source:   source,
			Platform: platform,
			Preview:  readPreview(skillMDPath),
			Hash:     hashFile(skillMDPath),
		})
	}

	// 1 + 2. Well-known standalone locations (Claude Code)
	for _, entry := range []struct {
		pattern string
		source  string
	}{
		{filepath.Join(home, ".claude", "skills", "*", "SKILL.md"), "global"},
	} {
		for _, f := range globSafe(entry.pattern) {
			add(f, entry.source, PlatformClaudeCode)
		}
	}
	if cwd != "" {
		for _, f := range globSafe(filepath.Join(cwd, ".claude", "skills", "*", "SKILL.md")) {
			add(f, "project", PlatformClaudeCode)
		}
	}

	// 3. Plugin-installed skills via installed_plugins.json manifest.
	manifestPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	manifestOK := false
	if data, err := os.ReadFile(manifestPath); err == nil {
		var manifest struct {
			Plugins map[string][]struct {
				InstallPath string `json:"installPath"`
				Scope       string `json:"scope"`
			} `json:"plugins"`
		}
		if err := json.Unmarshal(data, &manifest); err == nil {
			manifestOK = true
			for _, installs := range manifest.Plugins {
				for _, inst := range installs {
					if inst.InstallPath == "" {
						continue
					}
					source := "global"
					if inst.Scope == "project" {
						source = "project"
					}
					for _, f := range globSafe(filepath.Join(inst.InstallPath, "skills", "*", "SKILL.md")) {
						add(f, source, PlatformClaudeCode)
					}
				}
			}
		}
	}
	// Fallback cache glob when the manifest is missing or malformed.
	if !manifestOK {
		cachePattern := filepath.Join(home, ".claude", "plugins", "cache", "*", "*", "*", "skills", "*", "SKILL.md")
		for _, f := range globSafe(cachePattern) {
			add(f, "global", PlatformClaudeCode)
		}
	}

	// 3c. Skills in Claude Code marketplace caches. When a user adds a
	//     marketplace (e.g. `/plugin marketplace add`), Claude Code clones
	//     the source repo under ~/.claude/plugins/marketplaces/<marketplace>/
	//     regardless of which of its plugins they go on to `/plugin install`.
	//     Teams sometimes use this tree directly as a source-of-truth for
	//     available skills without the formal install step, so from a
	//     security-posture standpoint the SKILL.md files on disk belong in
	//     the inventory — tagged distinctly so the dashboard can distinguish
	//     "installed" from "available via marketplace".
	//
	//     Two layouts observed in the wild:
	//       marketplaces/<m>/skills/<skill>/SKILL.md
	//       marketplaces/<m>/plugins/<plugin>/skills/<skill>/SKILL.md
	marketplacesRoot := filepath.Join(home, ".claude", "plugins", "marketplaces")
	for _, f := range globSafe(filepath.Join(marketplacesRoot, "*", "skills", "*", "SKILL.md")) {
		add(f, "marketplace", PlatformClaudeCode)
	}
	for _, f := range globSafe(filepath.Join(marketplacesRoot, "*", "plugins", "*", "skills", "*", "SKILL.md")) {
		add(f, "marketplace", PlatformClaudeCode)
	}

	// 4. Project-level plugin installs (rare but supported).
	if cwd != "" {
		for _, f := range globSafe(filepath.Join(cwd, ".claude", "plugins", "*", "*", "skills", "*", "SKILL.md")) {
			add(f, "project", PlatformClaudeCode)
		}
	}

	// 5. Claude Cowork (Claude Desktop) persistent skills.
	//
	//    Only the `skills-plugin` subtree is scanned. Cowork's user-created
	//    skills live under `local-agent-mode-sessions/.../local_<uuid>/...`
	//    which are per-session and get garbage-collected on cleanup (see
	//    anthropics/claude-code#31422). Scanning them would surface rows
	//    that vanish within hours, so they are deliberately skipped.
	for _, skillPath := range walkCoworkSkills(home) {
		add(skillPath, "global", PlatformClaudeDesktop)
	}

	// Deterministic output so tests and diffs are stable.
	sort.Slice(skills, func(i, j int) bool {
		if skills[i].Platform != skills[j].Platform {
			return skills[i].Platform < skills[j].Platform
		}
		if skills[i].Source != skills[j].Source {
			return skills[i].Source < skills[j].Source
		}
		return skills[i].Name < skills[j].Name
	})

	return skills
}

// --- MCP servers ------------------------------------------------------------

// scanMCPServers mirrors collect_mcp() — reads mcpServers from each of the
// three Claude Code settings.json locations, then the Claude Desktop
// claude_desktop_config.json, flattening into a single list with a
// `platform` discriminator per entry.
func scanMCPServers(home, cwd string) []MCPServer {
	servers := []MCPServer{}
	seen := map[string]bool{}

	sources := []struct {
		scope    string
		path     string
		platform string
	}{
		{"global", filepath.Join(home, ".claude", "settings.json"), PlatformClaudeCode},
	}
	if cwd != "" {
		sources = append(sources,
			struct{ scope, path, platform string }{"project", filepath.Join(cwd, ".claude", "settings.json"), PlatformClaudeCode},
			struct{ scope, path, platform string }{"project", filepath.Join(cwd, ".claude", "settings.local.json"), PlatformClaudeCode},
		)
	}
	// Claude Cowork (Claude Desktop) config. One canonical path per OS.
	if p := coworkDesktopConfigPath(home); p != "" {
		sources = append(sources, struct{ scope, path, platform string }{"global", p, PlatformClaudeDesktop})
	}

	for _, src := range sources {
		data, err := os.ReadFile(src.path)
		if err != nil {
			continue
		}
		var settings struct {
			MCPServers map[string]struct {
				Type    string   `json:"type"`
				URL     string   `json:"url"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			continue
		}
		for name, cfg := range settings.MCPServers {
			key := name + "|" + src.scope + "|" + src.platform
			if seen[key] {
				continue
			}
			seen[key] = true

			serverType := cfg.Type
			if serverType == "" {
				if cfg.URL != "" {
					serverType = "http"
				} else {
					serverType = "stdio"
				}
			}
			command := cfg.Command
			if command != "" && len(cfg.Args) > 0 {
				for _, a := range cfg.Args {
					command += " " + a
				}
			}
			servers = append(servers, MCPServer{
				Name:     name,
				Type:     serverType,
				Command:  command,
				Source:   src.scope,
				Platform: src.platform,
			})
		}
	}

	// Deterministic.
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Platform != servers[j].Platform {
			return servers[i].Platform < servers[j].Platform
		}
		if servers[i].Source != servers[j].Source {
			return servers[i].Source < servers[j].Source
		}
		return servers[i].Name < servers[j].Name
	})
	return servers
}

// --- helpers ----------------------------------------------------------------

// readPreview returns the first 300 bytes of the file as a string, or empty
// string on any error (unreadable, missing, etc.). Matches read_preview() in
// connect/SKILL.md.
func readPreview(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 300)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return ""
	}
	return string(buf[:n])
}

// hashFile returns the hex-encoded SHA-256 of the file contents, or empty
// string on any error.
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// globSafe returns filepath.Glob results without the error — any error is
// indistinguishable from "no match" for our purposes.
func globSafe(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// Platform returns the OS label expected by the checkin endpoint.
// (Separate from runtime.GOOS only because we may want friendlier labels
// later; for now keep it identical.)
func Platform() string {
	return runtime.GOOS
}

// --- Cowork (Claude Desktop) -----------------------------------------------

// coworkAppSupportDir returns the OS-canonical Claude Desktop application
// support directory for the current user. Returns "" on unsupported OSes.
//
//	macOS:   ~/Library/Application Support/Claude
//	Linux:   ~/.config/Claude
//	Windows: <home>/AppData/Roaming/Claude
//
// Derived purely from `home` — we deliberately ignore XDG_CONFIG_HOME and
// APPDATA env vars. Claude Desktop writes to the default path unconditionally
// (confirmed from Anthropic docs), so env-derived overrides would point us
// at the wrong tree in production and break test hermeticity in CI runners
// that set those vars for other reasons.
func coworkAppSupportDir(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "linux":
		return filepath.Join(home, ".config", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	}
	return ""
}

// coworkDesktopConfigPath returns the absolute path to
// claude_desktop_config.json for the current OS, or "" if unsupported.
func coworkDesktopConfigPath(home string) string {
	dir := coworkAppSupportDir(home)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "claude_desktop_config.json")
}

// walkCoworkSkills returns paths to SKILL.md files inside the Cowork
// persistent `skills-plugin` subtree. Ephemeral per-session skills under
// `local-agent-mode-sessions/.../local_<uuid>/` are deliberately skipped —
// they get garbage-collected on session cleanup (anthropics/claude-code#31422)
// and surfacing them would produce phantom inventory rows.
//
// Structure (varies slightly between Cowork versions, so walk rather than
// depending on a fixed glob depth):
//
//	<appSupportDir>/local-agent-mode-sessions/skills-plugin/<...>/skills/<name>/SKILL.md
func walkCoworkSkills(home string) []string {
	root := coworkAppSupportDir(home)
	if root == "" {
		return nil
	}
	sessionsRoot := filepath.Join(root, "local-agent-mode-sessions", "skills-plugin")
	if _, err := os.Stat(sessionsRoot); err != nil {
		return nil
	}

	var found []string
	_ = filepath.WalkDir(sessionsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Unreadable directory — skip quietly (fail-open).
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Cap walk depth — the skills-plugin tree is shallow, runaway symlinks
		// or enormous per-session dirs should not lock the hook.
		if d.IsDir() {
			rel, relErr := filepath.Rel(sessionsRoot, path)
			if relErr == nil && strings.Count(rel, string(filepath.Separator)) > 6 {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "SKILL.md" {
			return nil
		}
		// Must live under `/skills/<name>/SKILL.md`.
		parent := filepath.Base(filepath.Dir(filepath.Dir(path)))
		if parent != "skills" {
			return nil
		}
		found = append(found, path)
		return nil
	})
	return found
}
