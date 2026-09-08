package skillinventory

import "path/filepath"

// These are package discovery locations, not proof of installation, activation,
// publisher trust, or a configured override. Shared roots intentionally retain
// a separate surface identity. Never search a whole home or project tree.
func crossAgentSources(home, cwd string) []sourceSpec {
	type locations struct {
		surface       string
		home, project []string
	}
	catalog := []locations{
		{"grok", []string{".grok/skills", ".agents/skills", ".claude/skills"}, []string{".grok/skills", ".claude/skills"}},
		{"codex", []string{".agents/skills", ".codex/skills"}, []string{".agents/skills", ".codex/skills"}},
		{"cursor", []string{".cursor/skills", ".agents/skills", ".claude/skills", ".codex/skills"}, []string{".cursor/skills", ".agents/skills", ".claude/skills", ".codex/skills"}},
		{"windsurf", []string{".codeium/windsurf/skills", ".agents/skills"}, []string{".windsurf/skills", ".agents/skills"}},
		{"copilot", []string{".copilot/skills", ".agents/skills"}, []string{".github/skills", ".claude/skills", ".agents/skills"}},
		{"gemini", []string{".gemini/skills", ".agents/skills"}, []string{".gemini/skills", ".agents/skills"}},
		{"antigravity", []string{".gemini/config/skills"}, []string{".agents/skills", ".agent/skills"}},
		{"agentkeeper_runtime", []string{".agentkeeper/skills"}, []string{"skills"}},
	}
	specs := []sourceSpec{}
	for _, entry := range catalog {
		for _, root := range entry.home {
			specs = append(specs, sourceSpec{filepath.Join(home, filepath.FromSlash(root)), entry.surface, "persistent_standalone", "present", nil, true})
		}
		if cwd != "" {
			for _, root := range entry.project {
				specs = append(specs, sourceSpec{filepath.Join(cwd, filepath.FromSlash(root)), entry.surface, "persistent_standalone", "present", nil, true})
			}
		}
	}
	// A local collector cannot infer remote/account inventories from transcripts,
	// browser telemetry, MCP server lists, or the absence of a local directory.
	for _, surface := range []string{"claude_chat", "microsoft_copilot", "browser_extension", "mcp_gateway", "litellm", "agentcore"} {
		specs = append(specs, sourceSpec{filepath.Join(home, ".agentkeeper", "inventory-coverage", surface), surface, "account_only", "present", nil, false})
	}
	return specs
}
