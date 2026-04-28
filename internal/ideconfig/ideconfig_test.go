package ideconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeJSON writes a raw map to path and fails on error. Preserves top-level
// key order because the tests assert unknown-key preservation.
func writeJSON(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// mkAdapter builds an Adapter whose path resolves to a test-controlled file.
func mkAdapter(t *testing.T, path string) *Adapter {
	t.Helper()
	return &Adapter{
		Name:         "test-ide",
		PathResolver: func() (string, error) { return path, nil },
	}
}

// --- Plan -------------------------------------------------------------------

func TestPlan_MissingFile(t *testing.T) {
	a := mkAdapter(t, filepath.Join(t.TempDir(), "does-not-exist.json"))
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if p.Exists {
		t.Errorf("Exists = true, want false for missing file")
	}
	if p.AlreadyWired {
		t.Errorf("AlreadyWired = true, want false for missing file")
	}
	if len(p.Migrated) != 0 {
		t.Errorf("Migrated = %v, want empty", p.Migrated)
	}
}

func TestPlan_NoMCPServersKey(t *testing.T) {
	// Claude Code's real-world shape: settings.json has general user settings
	// but no mcpServers key at all. Plan should report Exists=true, nothing
	// to migrate, and that Apply would wire the gateway in.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "settings.json")
	writeJSON(t, path, `{
		"permissions": {"allow": ["Bash", "Read"]},
		"effortLevel": "high"
	}`)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Exists {
		t.Fatal("Exists = false, want true")
	}
	if p.AlreadyWired {
		t.Error("AlreadyWired = true, want false — no mcpServers at all")
	}
	if len(p.Migrated) != 0 {
		t.Errorf("Migrated = %v, want empty", p.Migrated)
	}
}

func TestPlan_OneExistingServer(t *testing.T) {
	// Claude Desktop-style: existing MCP server must be captured for migration.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {"GITHUB_TOKEN": "tok"}
			}
		},
		"preferences": {"sidebarMode": "task"}
	}`)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Exists || p.AlreadyWired {
		t.Fatalf("Exists=%v AlreadyWired=%v", p.Exists, p.AlreadyWired)
	}
	if len(p.Migrated) != 1 {
		t.Fatalf("Migrated len = %d, want 1", len(p.Migrated))
	}
	got := p.Migrated[0]
	if got.Name != "github" || got.Entry.Command != "npx" ||
		len(got.Entry.Args) != 2 || got.Entry.Env["GITHUB_TOKEN"] != "tok" {
		t.Errorf("migrated entry not parsed correctly: %+v", got)
	}
}

func TestPlan_AlreadyWired(t *testing.T) {
	// Idempotency: a file that already has exactly the gateway entry and nothing
	// else in mcpServers must be reported as AlreadyWired=true with no migration.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"agentkeeper-mcp-gateway": {
				"command": "agentkeeper-mcp-gateway",
				"args": ["server"]
			}
		}
	}`)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !p.AlreadyWired {
		t.Error("AlreadyWired = false, want true for exact-match gateway entry")
	}
	if len(p.Migrated) != 0 {
		t.Errorf("Migrated = %v, want empty for already-wired", p.Migrated)
	}
}

func TestPlan_AlreadyWired_FullPathCommand(t *testing.T) {
	// Developers who installed via `go install` or a custom INSTALL_PREFIX end
	// up with a full-path command. That's still correctly wired — basename
	// match, not exact string match.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"agentkeeper-mcp-gateway": {
				"command": "/Users/someone/go/bin/agentkeeper-mcp-gateway",
				"args": ["server"]
			}
		}
	}`)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !p.AlreadyWired {
		t.Error("AlreadyWired = false for full-path gateway command; want true")
	}
}

func TestPlan_StaleGatewayEntryPlusOtherServers(t *testing.T) {
	// The user previously wired the gateway and added more servers afterward.
	// We need to migrate the OTHER servers, and the gateway entry itself must
	// not be migrated (it's not a real MCP server).
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	writeJSON(t, path, `{
		"mcpServers": {
			"agentkeeper-mcp-gateway": {"command": "agentkeeper-mcp-gateway", "args": ["server"]},
			"postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres"]}
		}
	}`)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if p.AlreadyWired {
		t.Error("AlreadyWired = true — only true when gateway is the SOLE entry")
	}
	if len(p.Migrated) != 1 || p.Migrated[0].Name != "postgres" {
		t.Fatalf("want migrated=[postgres], got %+v", p.Migrated)
	}
}

// --- Apply ------------------------------------------------------------------

func TestApply_BacksUpThenWrites(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	original := `{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}},"preferences":{"sidebarMode":"task"}}`
	writeJSON(t, path, original)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(&p); err != nil {
		t.Fatal(err)
	}

	// Backup must exist with original content
	if p.BackupPath == "" {
		t.Fatal("BackupPath empty — Apply should have set one")
	}
	backup, err := os.ReadFile(p.BackupPath)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(backup) != original {
		t.Errorf("backup content != original\n  got:  %s\n  want: %s", backup, original)
	}

	// New config must (a) have only the gateway entry under mcpServers,
	// (b) preserve `preferences` verbatim.
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(written, &got); err != nil {
		t.Fatalf("written file not valid JSON: %v", err)
	}
	if _, ok := got["preferences"]; !ok {
		t.Error("unknown top-level key 'preferences' was dropped")
	}
	var servers map[string]ServerEntry
	if err := json.Unmarshal(got["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Errorf("want 1 server in rewritten mcpServers, got %d", len(servers))
	}
	gw, ok := servers[GatewayServerName]
	if !ok {
		t.Fatalf("gateway entry missing; got keys: %v", servers)
	}
	if gw.Command != "agentkeeper-mcp-gateway" || len(gw.Args) != 1 || gw.Args[0] != "server" {
		t.Errorf("gateway entry wrong shape: %+v", gw)
	}
}

func TestApply_AlreadyWired_IsNoop(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	original := `{
  "mcpServers": {
    "agentkeeper-mcp-gateway": {
      "command": "agentkeeper-mcp-gateway",
      "args": ["server"]
    }
  }
}`
	writeJSON(t, path, original)
	before, _ := os.Stat(path)

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(&p); err != nil {
		t.Fatal(err)
	}
	if p.BackupPath != "" {
		t.Errorf("no backup should be created for no-op; got %q", p.BackupPath)
	}
	after, _ := os.Stat(path)
	if after.ModTime() != before.ModTime() {
		t.Error("file was rewritten despite being already wired")
	}
}

func TestApply_MissingFile_CreatesParent(t *testing.T) {
	// If an IDE's config doesn't exist, Apply should still produce a valid
	// config file — otherwise a developer who installs Cursor *after* Kanji
	// runs gets no wiring. Creates the parent directory if necessary.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "fresh", "cfg.json")

	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if p.Exists {
		t.Fatal("Exists should be false")
	}
	if err := a.Apply(&p); err != nil {
		t.Fatal(err)
	}
	if p.BackupPath != "" {
		t.Errorf("no backup expected when file didn't exist; got %q", p.BackupPath)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]ServerEntry
	if err := json.Unmarshal(written, &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := got["mcpServers"][GatewayServerName]; !ok {
		t.Errorf("gateway entry not present after creating fresh config: %+v", got)
	}
}

// --- Registry --------------------------------------------------------------

func TestAdapters_IncludesExpectedIDEs(t *testing.T) {
	adapters := Adapters()
	names := map[string]bool{}
	for _, a := range adapters {
		names[a.Name] = true
	}
	for _, want := range []string{"claude-code", "claude-desktop", "cursor"} {
		if !names[want] {
			t.Errorf("Adapters() missing %q; got %v", want, names)
		}
	}
}

func TestAdapters_PathsAreUserHomeRooted(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir on this runner")
	}
	for _, a := range Adapters() {
		p, err := a.PathResolver()
		if err != nil {
			t.Errorf("%s: path resolver errored: %v", a.Name, err)
			continue
		}
		if rel, err := filepath.Rel(home, p); err != nil || rel == "" {
			t.Errorf("%s: path %q is not under $HOME (%q)", a.Name, p, home)
		}
	}
}
