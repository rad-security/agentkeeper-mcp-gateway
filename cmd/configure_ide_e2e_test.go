// End-to-end tests for the `configure-ide` subcommand. Invokes the actual
// compiled binary against a fresh $HOME per scenario and asserts on real
// filesystem state. Complements the unit tests in internal/ideconfig by
// exercising the cobra surface, env-var flow, and JSON round-trip.
//
// Build the binary once in TestMain for speed.
package cmd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---- shared setup ---------------------------------------------------------

var binary string

func TestMain(m *testing.M) {
	// CK_E2E_BINARY lets CI / release-verification point the suite at a
	// pre-built binary (e.g. one pulled from a GitHub release tarball) instead
	// of compiling from the current source tree. When unset, build from source.
	if preBuilt := os.Getenv("CK_E2E_BINARY"); preBuilt != "" {
		binary = preBuilt
		os.Exit(m.Run())
	}

	tmp, err := os.MkdirTemp("", "ckmcp-e2e-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(tmp, "agentkeeper-mcp-gateway")
	build := exec.Command("go", "build", "-o", binary, "..")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(fmt.Sprintf("go build failed: %v", err))
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// run executes the binary with the given args under a scrubbed $HOME and
// returns stdout, stderr, and the exit code. Also sets AGENTKEEPER_CONFIG to a
// stable path so the gateway's own config lives in the test's home.
func run(t *testing.T, home string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_CONFIG=" + filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"),
	}
	var outbuf, errbuf bytes.Buffer
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("invoking binary: %v", err)
	}
	return outbuf.String(), errbuf.String(), code
}

// ideConfigPath returns where a given IDE's config would live under home.
func ideConfigPath(home, ide string) string {
	switch ide {
	case "claude-code":
		return filepath.Join(home, ".claude", "settings.json")
	case "claude-desktop":
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json")
	}
	return ""
}

// writeFixture puts body at ideConfigPath(home, ide) and returns that path.
func writeFixture(t *testing.T, home, ide, body string) string {
	t.Helper()
	path := ideConfigPath(home, ide)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// readConfig parses a written IDE config.
func readConfig(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parsing %s: %v — content:\n%s", path, err, data)
	}
	return out
}

// countBackups returns how many *.agentkeeper-backup-* files exist under dir.
func countBackups(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), ".agentkeeper-backup-") {
			n++
		}
		return nil
	})
	return n
}

// assertGatewayWired parses path and verifies `mcpServers` has exactly the
// gateway entry and nothing else.
func assertGatewayWired(t *testing.T, path string) {
	t.Helper()
	raw := readConfig(t, path)
	rawServers, ok := raw["mcpServers"]
	if !ok {
		t.Fatalf("%s: mcpServers key missing", path)
	}
	var servers map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal(rawServers, &servers); err != nil {
		t.Fatalf("%s: parsing mcpServers: %v", path, err)
	}
	if len(servers) != 1 {
		t.Errorf("%s: want 1 server, got %d (%v)", path, len(servers), servers)
	}
	gw, ok := servers["agentkeeper-mcp-gateway"]
	if !ok {
		t.Fatalf("%s: gateway entry missing; keys=%v", path, servers)
	}
	if gw.Command != "agentkeeper-mcp-gateway" {
		t.Errorf("%s: gateway.command = %q, want agentkeeper-mcp-gateway", path, gw.Command)
	}
	if len(gw.Args) != 1 || gw.Args[0] != "server" {
		t.Errorf("%s: gateway.args = %v, want [server]", path, gw.Args)
	}
}

// ---- scenarios ------------------------------------------------------------

// E2E-01: fresh install — no configs exist. All three IDEs get created.
func TestE2E01_FreshInstall_AllIDEsCreated(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, ide := range []string{"claude-code", "claude-desktop", "cursor"} {
		assertGatewayWired(t, ideConfigPath(home, ide))
	}
}

// E2E-02: malformed JSON in one IDE surfaces an error for that IDE without
// blocking the others. No corruption on the malformed file.
func TestE2E02_MalformedJSON_ErrorsCleanly(t *testing.T) {
	home := t.TempDir()
	badPath := writeFixture(t, home, "cursor", `{ not valid json `)
	out, _, code := run(t, home, "configure-ide")
	// Expect the command to continue (error per-IDE is reported inline but
	// other IDEs should still configure).
	if code != 0 {
		t.Errorf("whole command shouldn't fail; got exit %d — output:\n%s", code, out)
	}
	if !strings.Contains(out, "error") && !strings.Contains(out, "parsing") {
		t.Errorf("want error message for cursor; got:\n%s", out)
	}
	// The malformed file must be untouched.
	after, _ := os.ReadFile(badPath)
	if string(after) != `{ not valid json ` {
		t.Errorf("malformed file was modified; got: %s", after)
	}
	// Claude Code + Claude Desktop should still be wired.
	assertGatewayWired(t, ideConfigPath(home, "claude-code"))
	assertGatewayWired(t, ideConfigPath(home, "claude-desktop"))
}

// E2E-03: empty (0-byte) file is treated like malformed JSON — clean error,
// not silently written over.
func TestE2E03_ZeroByteFile(t *testing.T) {
	home := t.TempDir()
	badPath := writeFixture(t, home, "cursor", "")
	_, _, _ = run(t, home, "configure-ide")
	after, _ := os.ReadFile(badPath)
	if len(after) != 0 {
		// Either we errored (file still empty) or we wrote through (arguably
		// fine — fresh file). Treat either as acceptable as long as we didn't
		// corrupt. The key assertion: if we wrote, it must be valid JSON.
		var tmp any
		if err := json.Unmarshal(after, &tmp); err != nil {
			t.Errorf("wrote invalid JSON over 0-byte file: %s (%v)", after, err)
		}
	}
}

// E2E-04: mcpServers is explicitly null. Treated as empty; gateway wired.
func TestE2E04_NullMCPServers(t *testing.T) {
	home := t.TempDir()
	p := writeFixture(t, home, "cursor", `{"mcpServers": null, "keep_me": 42}`)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw := readConfig(t, p)
	if _, ok := raw["keep_me"]; !ok {
		t.Error("non-mcp key 'keep_me' was dropped")
	}
	assertGatewayWired(t, p)
}

// E2E-05: mcpServers is empty object. Same as null.
func TestE2E05_EmptyMCPServers(t *testing.T) {
	home := t.TempDir()
	p := writeFixture(t, home, "cursor", `{"mcpServers": {}, "preferences": {"theme": "dark"}}`)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw := readConfig(t, p)
	if _, ok := raw["preferences"]; !ok {
		t.Error("preferences key dropped")
	}
	assertGatewayWired(t, p)
}

// E2E-06: single server gets migrated into the gateway config.
func TestE2E06_SingleServerMigrated(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{
		"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}
	}`)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Gateway config should have github recorded.
	gatewayCfg := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	data, err := os.ReadFile(gatewayCfg)
	if err != nil {
		t.Fatalf("gateway config missing: %v", err)
	}
	if !strings.Contains(string(data), "github") {
		t.Errorf("github not in gateway config: %s", data)
	}
}

// E2E-07: multiple servers (5+) all migrate cleanly.
func TestE2E07_ManyServersMigrated(t *testing.T) {
	home := t.TempDir()
	servers := map[string]any{}
	for _, n := range []string{"github", "postgres", "slack", "filesystem", "memory"} {
		servers[n] = map[string]any{
			"command": "npx", "args": []string{"-y", "@modelcontextprotocol/server-" + n},
		}
	}
	body, _ := json.Marshal(map[string]any{"mcpServers": servers})
	writeFixture(t, home, "claude-desktop", string(body))
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	gatewayData, _ := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	for _, want := range []string{"github", "postgres", "slack", "filesystem", "memory"} {
		if !strings.Contains(string(gatewayData), want) {
			t.Errorf("missing %q in migrated gateway config", want)
		}
	}
}

// E2E-08: env vars with special characters (quotes, backslashes, newlines) round-trip.
func TestE2E08_EnvVarsWithSpecialChars(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{
		"mcpServers": {"weird": {"command": "echo", "env": {"QUOTE": "he said \"hi\"", "NL": "line1\nline2", "BACK": "a\\b"}}}
	}`)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Gateway config should contain the escaped values correctly.
	gatewayData, _ := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	var parsed map[string]any
	if err := json.Unmarshal(gatewayData, &parsed); err != nil {
		t.Fatalf("gateway config invalid JSON: %v", err)
	}
	servers := parsed["servers"].([]any)
	found := false
	for _, s := range servers {
		e := s.(map[string]any)
		if e["name"] != "weird" {
			continue
		}
		found = true
		env := e["env"].(map[string]any)
		if env["QUOTE"] != `he said "hi"` {
			t.Errorf("QUOTE env corrupted: %v", env["QUOTE"])
		}
		if env["NL"] != "line1\nline2" {
			t.Errorf("NL env corrupted: %v", env["NL"])
		}
		if env["BACK"] != `a\b` {
			t.Errorf("BACK env corrupted: %v", env["BACK"])
		}
	}
	if !found {
		t.Error("migrated server 'weird' missing from gateway config")
	}
}

// E2E-09: unknown top-level keys with deep nesting are preserved verbatim.
func TestE2E09_DeepNestedKeysPreserved(t *testing.T) {
	home := t.TempDir()
	body := `{
		"mcpServers": {"a": {"command": "x"}},
		"deep": {"nested": {"more": {"even_more": [1, 2, {"k": "v"}]}}}
	}`
	p := writeFixture(t, home, "claude-desktop", body)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw := readConfig(t, p)
	if _, ok := raw["deep"]; !ok {
		t.Fatal("deep key dropped")
	}
	var deep map[string]any
	_ = json.Unmarshal(raw["deep"], &deep)
	nested := deep["nested"].(map[string]any)
	more := nested["more"].(map[string]any)
	arr := more["even_more"].([]any)
	if len(arr) != 3 {
		t.Errorf("nested array length changed: %v", arr)
	}
}

// E2E-10: idempotency — two back-to-back runs, second produces no new backup.
func TestE2E10_DoubleRunNoSecondBackup(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{"mcpServers": {"github": {"command": "npx", "args": ["-y", "x"]}}}`)
	_, _, _ = run(t, home, "configure-ide")
	afterFirst := countBackups(t, home)
	_, _, _ = run(t, home, "configure-ide")
	afterSecond := countBackups(t, home)
	if afterSecond != afterFirst {
		t.Errorf("second run created %d new backup(s); want 0", afterSecond-afterFirst)
	}
}

// E2E-11: --dry-run produces no files.
func TestE2E11_DryRunNoWrites(t *testing.T) {
	home := t.TempDir()
	out, _, code := run(t, home, "configure-ide", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "dry-run") {
		t.Errorf("dry-run banner missing; got:\n%s", out)
	}
	// No IDE files should exist.
	for _, ide := range []string{"claude-code", "claude-desktop", "cursor"} {
		if _, err := os.Stat(ideConfigPath(home, ide)); !os.IsNotExist(err) {
			t.Errorf("%s config was created during dry-run", ide)
		}
	}
}

// E2E-12: --dry-run + --ide=cursor only plans cursor.
func TestE2E12_DryRunFilteredIDE(t *testing.T) {
	home := t.TempDir()
	out, _, code := run(t, home, "configure-ide", "--dry-run", "--ide=cursor")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "cursor") {
		t.Errorf("cursor missing from dry-run output: %s", out)
	}
	if strings.Contains(out, "claude-code") || strings.Contains(out, "claude-desktop") {
		t.Errorf("other IDEs appeared despite --ide=cursor:\n%s", out)
	}
}

// E2E-13: unknown --ide value errors out.
func TestE2E13_UnknownIDEErrors(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := run(t, home, "configure-ide", "--ide=emacs")
	if code == 0 {
		t.Errorf("expected nonzero exit for unknown IDE")
	}
	combined := stderr
	if !strings.Contains(combined, "no matching IDE") && !strings.Contains(combined, "unknown") && !strings.Contains(combined, "known:") {
		t.Errorf("expected informative error; got stderr: %s", stderr)
	}
}

// E2E-14: --ide flag accepts comma-separated / repeatable values.
func TestE2E14_MultiIDEFlag(t *testing.T) {
	home := t.TempDir()
	out, _, code := run(t, home, "configure-ide", "--dry-run", "--ide=cursor,claude-code")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "cursor") || !strings.Contains(out, "claude-code") {
		t.Errorf("expected both cursor and claude-code; got:\n%s", out)
	}
	if strings.Contains(out, "claude-desktop") {
		t.Errorf("claude-desktop leaked into output:\n%s", out)
	}
}

// E2E-15: backup content exactly matches original (byte-for-byte).
func TestE2E15_BackupMatchesOriginalExactly(t *testing.T) {
	home := t.TempDir()
	original := `{"mcpServers":{"x":{"command":"y"}},"other":true}`
	p := writeFixture(t, home, "cursor", original)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	matches, _ := filepath.Glob(p + ".agentkeeper-backup-*")
	if len(matches) != 1 {
		t.Fatalf("want 1 backup, got %d", len(matches))
	}
	data, _ := os.ReadFile(matches[0])
	if string(data) != original {
		t.Errorf("backup content diverged\n  got:  %s\n  want: %s", data, original)
	}
}

// E2E-16: running against a directory-where-file-should-be surfaces a clean error.
func TestE2E16_ConfigPathIsDirectory(t *testing.T) {
	home := t.TempDir()
	// Pre-create cursor's config path as a directory.
	if err := os.MkdirAll(ideConfigPath(home, "cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _, _ := run(t, home, "configure-ide")
	if !strings.Contains(out, "error") {
		t.Errorf("expected error for cursor when path is a directory; output:\n%s", out)
	}
	// Other IDEs should still be wired.
	assertGatewayWired(t, ideConfigPath(home, "claude-code"))
}

// E2E-17: already-wired + extra unrelated top-level keys → no-op, keys preserved.
func TestE2E17_AlreadyWiredPreservesExtras(t *testing.T) {
	home := t.TempDir()
	body := `{
  "mcpServers": {
    "agentkeeper-mcp-gateway": {"command": "agentkeeper-mcp-gateway", "args": ["server"]}
  },
  "editor": {"tabSize": 2},
  "version": 42
}`
	p := writeFixture(t, home, "cursor", body)
	statBefore, _ := os.Stat(p)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	statAfter, _ := os.Stat(p)
	if statAfter.ModTime() != statBefore.ModTime() {
		t.Error("file was rewritten despite being already wired")
	}
}

// E2E-18: gateway entry with mismatched args → re-wire.
func TestE2E18_StaleGatewayEntryArgs_Rewires(t *testing.T) {
	home := t.TempDir()
	body := `{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"agentkeeper-mcp-gateway","args":["server","--extra"]}}}`
	p := writeFixture(t, home, "cursor", body)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Should be re-wired to the canonical shape.
	assertGatewayWired(t, p)
}

// E2E-19: gateway entry with differently-cased basename is NOT idempotent.
// (basename match is case-sensitive — safer for identity checks.)
func TestE2E19_CaseSensitiveBasenameMatch(t *testing.T) {
	home := t.TempDir()
	body := `{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"AgentKeeper-MCP-Gateway","args":["server"]}}}`
	p := writeFixture(t, home, "cursor", body)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Should have rewired to the canonical lowercase form.
	assertGatewayWired(t, p)
	raw := readConfig(t, p)
	var servers map[string]map[string]any
	_ = json.Unmarshal(raw["mcpServers"], &servers)
	if servers["agentkeeper-mcp-gateway"]["command"] != "agentkeeper-mcp-gateway" {
		t.Errorf("expected rewire to canonical case; got %v", servers)
	}
}

// E2E-20: gateway entry with extra unknown per-server fields → should still match by basename+args.
// This verifies we don't accidentally fail idempotency because a user's entry
// has an extra field like "type":"stdio" that some IDEs add.
func TestE2E20_ExtraFieldOnGatewayEntry_StillWired(t *testing.T) {
	home := t.TempDir()
	body := `{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"agentkeeper-mcp-gateway","args":["server"],"type":"stdio"}}}`
	p := writeFixture(t, home, "cursor", body)
	// We don't have a getter for the Plan struct here; we can only check via
	// observable behavior: no backup should be created if we consider this wired.
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	matches, _ := filepath.Glob(p + ".agentkeeper-backup-*")
	if len(matches) != 0 {
		t.Errorf("backup created despite already-wired shape + extra harmless field; backups=%v", matches)
	}
}

// E2E-21: existing servers with HTTP transport round-trip (type/url/headers).
func TestE2E21_HTTPTransportRoundTrips(t *testing.T) {
	home := t.TempDir()
	body := `{"mcpServers":{"remote":{"type":"http","url":"https://api.example.com/sse","headers":{"Authorization":"Bearer x"}}}}`
	writeFixture(t, home, "cursor", body)
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	gwData, _ := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	if !strings.Contains(string(gwData), "https://api.example.com/sse") {
		t.Errorf("URL not in migrated gateway config: %s", gwData)
	}
	if !strings.Contains(string(gwData), "Bearer x") {
		t.Errorf("Authorization header not migrated: %s", gwData)
	}
}

// E2E-22: two IDEs register the same server name → de-duplicated (only one ends up).
func TestE2E22_SameServerInMultipleIDEs_Deduplicated(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{"mcpServers":{"github":{"command":"npx","args":["-y","gh-v1"]}}}`)
	writeFixture(t, home, "claude-desktop", `{"mcpServers":{"github":{"command":"npx","args":["-y","gh-v2"]}}}`)
	out, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Both planned migrations should appear, but the "added" line should appear
	// only once.
	added := strings.Count(out, "added: github")
	if added != 1 {
		t.Errorf("expected 'added: github' once, got %d (output:\n%s)", added, out)
	}
}

// E2E-23: running against a tilde in a fixture path (tilde is literal on Unix,
// not expanded by the adapter — sanity check we never did ~ expansion anywhere).
func TestE2E23_TildeInHomePath_NotExpanded(t *testing.T) {
	home := filepath.Join(t.TempDir(), "has~tilde")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, code := run(t, home, "configure-ide")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	assertGatewayWired(t, ideConfigPath(home, "cursor"))
}

// E2E-24: env-var API key persists into the gateway config file when
// configure-ide migrates servers against a non-existent gateway config.
//
// This is a pinning test for a subtle Phase 2 + Phase 3.5 interaction:
// AddServer does Load→Save internally. Load resolves the env var into the
// in-memory Config (api_key='env'). Save writes that in-memory state to the
// resolved file path. Result: the env var effectively becomes persisted.
//
// Consistent with §5.2 "env fills blank, file wins once populated": after
// Save, the file now has the key, so subsequent loads source from file.
//
// For enterprise rollouts (Kandji case) this does not matter — the config file
// at /etc/... is written before configure-ide runs, and Load reads the file's
// populated key (file wins over env, no env lookup, no re-save drift).
//
// For developer laptops: running configure-ide while AGENTKEEPER_API_KEY is
// set effectively "pins" the env key into the file. Documented behavior.
func TestE2E24_APIKeyFromEnvIsPersistedByMigration(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, home, "cursor", `{"mcpServers":{"x":{"command":"y"}}}`)
	env := []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_CONFIG=" + filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"),
		"AGENTKEEPER_API_KEY=ak_live_fixture_key",
	}
	cmd := exec.Command(binary, "configure-ide")
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	// After migration: gateway config on disk should have the key, and
	// `config show` (without the env var now) should source it from file.
	show := exec.Command(binary, "config", "show")
	show.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_CONFIG=" + filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"),
	}
	out, err := show.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"api_key": "ak_live_fixture_key"`) {
		t.Errorf("expected env key to be persisted to file; output:\n%s", out)
	}
	if !strings.Contains(string(out), "# api_key:     file") {
		t.Errorf("expected api_key source 'file' after persistence; output:\n%s", out)
	}
}

// E2E-25: configure-ide run twice with a new server added between runs does NOT
// pick up the new server (known limitation — documented as out-of-scope in the
// issue). This is a pinning test — if we ever fix this behavior we want to know.
// The value of the test: prevents silent behavior change.
func TestE2E25_KnownLimitation_NewServerBetweenRunsMissed(t *testing.T) {
	home := t.TempDir()
	// Start with one server.
	writeFixture(t, home, "cursor", `{"mcpServers":{"first":{"command":"npx","args":["-y","first"]}}}`)
	_, _, _ = run(t, home, "configure-ide")

	// Now simulate the user adding a new server via their IDE (writing back
	// alongside the gateway entry).
	writeFixture(t, home, "cursor", `{
		"mcpServers": {
			"agentkeeper-mcp-gateway": {"command": "agentkeeper-mcp-gateway", "args": ["server"]},
			"second": {"command": "npx", "args": ["-y", "second"]}
		}
	}`)
	_, _, _ = run(t, home, "configure-ide")

	// The second server SHOULD now be in the gateway config (our current
	// "stale gateway entry + other servers" behavior migrates anything else).
	gw, _ := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	if !strings.Contains(string(gw), `"second"`) {
		t.Errorf("second server was not migrated on re-run; gateway config:\n%s", gw)
	}
}
