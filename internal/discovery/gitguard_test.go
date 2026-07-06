package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInsideGitWorktree(t *testing.T) {
	root := t.TempDir()

	repo := filepath.Join(root, "repo")
	nested := filepath.Join(repo, "plugins", "dev-workflow")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	linked := filepath.Join(root, "linked-worktree")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	// Linked worktrees and submodules have a .git *file*, not a directory.
	if err := os.WriteFile(filepath.Join(linked, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"repo root file", filepath.Join(repo, ".mcp.json"), true},
		{"nested file", filepath.Join(nested, ".mcp.json"), true},
		{"git file worktree", filepath.Join(linked, ".mcp.json"), true},
		{"plain dir", filepath.Join(plain, ".mcp.json"), false},
	}
	for _, tc := range cases {
		if got := insideGitWorktree(tc.path); got != tc.want {
			t.Errorf("%s: insideGitWorktree(%s) = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
}

func TestMigrateMCPFileSkipsGitWorktree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))

	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, ".mcp.json")
	original := []byte(`{"mcpServers":{"slack":{"type":"http","url":"https://mcp.slack.com/mcp"}}}`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := MigrateMCPFile(path, ClientClaudeCode, "project", "project_mcp_json", RouteabilityLocalRoutable, false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.SkippedGitWorktree {
		t.Fatalf("expected SkippedGitWorktree, got %+v", plan)
	}
	if len(plan.Migrated) != 0 {
		t.Fatalf("no servers should migrate on skip, got %+v", plan.Migrated)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("file inside git worktree was rewritten:\n%s", after)
	}
}

func TestMigrateProjectMCPExplicitWritesInsideGitWorktree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))

	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, ".mcp.json")
	original := []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := MigrateProjectMCPExplicit(repo, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SkippedGitWorktree {
		t.Fatalf("explicit project migration must not be skipped: %+v", plan)
	}
	if len(plan.Migrated) != 1 {
		t.Fatalf("expected 1 migrated server, got %+v", plan.Migrated)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(original) {
		t.Fatalf("explicit migration did not rewrite the project file")
	}
}
