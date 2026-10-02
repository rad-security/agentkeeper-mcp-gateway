// E2E tests for commands that rewrite the gateway config. Shares the test
// binary built by configure_ide_e2e_test.go's TestMain.
package cmd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// brokenGatewayConfig carries a trailing comma, the kind of syntax error a
// hand edit leaves behind, around settings a refused write must not destroy.
const brokenGatewayConfig = `{
  "mode": "enforce",
  "api_key": "ak_test_synthetic",
  "servers": [{"name": "keep", "command": "python3 keep.py"},]
}
`

func assertFileUnchanged(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s was rewritten:\n%s", path, got)
	}
}

func TestMutatingCommandsRefuseUnparseableGatewayConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		success string
	}{
		{"add", []string{"add", "newone", "python3", "x.py"}, "Added server"},
		{"remove", []string{"remove", "keep"}, "Removed server"},
		{"auth logout", []string{"auth", "logout"}, "Logged out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := writeGatewayConfig(t, home, brokenGatewayConfig)

			stdout, stderr, code := run(t, home, tc.args...)
			if code == 0 {
				t.Fatalf("expected non-zero exit, stdout: %s", stdout)
			}
			if !strings.Contains(stderr, path) || !strings.Contains(stderr, "invalid character") {
				t.Fatalf("stderr must name the file and the parse error, got: %s", stderr)
			}
			if strings.Contains(stdout, tc.success) {
				t.Fatalf("command reported success: %s", stdout)
			}
			assertFileUnchanged(t, path, brokenGatewayConfig)
		})
	}
}

func TestConfigureIDEProjectMigrationRefusesUnparseableGatewayConfig(t *testing.T) {
	home := t.TempDir()
	path := writeGatewayConfig(t, home, brokenGatewayConfig)
	project := t.TempDir()
	const projectMCP = `{"mcpServers":{"proj":{"command":"python3","args":["server.py"]}}}`
	projectPath := filepath.Join(project, ".mcp.json")
	if err := os.WriteFile(projectPath, []byte(projectMCP), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, home, "configure-ide", "--ide=claude-code", "--cwd", project, "--scope=project")
	if code == 0 {
		t.Fatalf("expected non-zero exit, stdout: %s", stdout)
	}
	if !strings.Contains(stderr, path) || !strings.Contains(stderr, "invalid character") {
		t.Fatalf("stderr must name the file and the parse error, got: %s", stderr)
	}
	assertFileUnchanged(t, path, brokenGatewayConfig)
	// The client must not be routed to a gateway that never got its server.
	assertFileUnchanged(t, projectPath, projectMCP)
}

func TestAddCreatesConfigWhenMissing(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := run(t, home, "add", "first", "python3", "x.py")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	servers := readAddedServers(t, home)
	if len(servers) != 1 || servers[0]["name"] != "first" || servers[0]["command"] != "python3 x.py" {
		t.Fatalf("servers = %v", servers)
	}
}

func TestRemoveUnknownServerFailsWithoutRewritingConfig(t *testing.T) {
	home := t.TempDir()
	// Not the layout the gateway writes, so any rewrite would change the bytes.
	const original = `{"mode":"enforce","servers":[{"name":"keep","command":"python3 keep.py"}]}`
	path := writeGatewayConfig(t, home, original)

	stdout, stderr, code := run(t, home, "remove", "nope")
	if code == 0 {
		t.Fatalf("expected non-zero exit, stdout: %s", stdout)
	}
	if want := `no server named "nope" in ` + path; !strings.Contains(stderr, want) {
		t.Fatalf("stderr %q does not contain %q", stderr, want)
	}
	if strings.Contains(stdout, "Removed server") {
		t.Fatalf("command reported success: %s", stdout)
	}
	assertFileUnchanged(t, path, original)

	stdout, stderr, code = run(t, home, "remove", "keep")
	if code != 0 || !strings.Contains(stdout, "Removed server: keep") {
		t.Fatalf("removing a registered server: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if servers := readAddedServers(t, home); len(servers) != 0 {
		t.Fatalf("servers = %v", servers)
	}
}

// An error is reported once: by cobra, or by Execute for a command that
// silences cobra's own reporting (scan).
func TestCLIErrorsPrintOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		config  string
		message string
	}{
		{"command error", []string{"remove", "nope"}, `{"servers":[]}`, `no server named "nope"`},
		{"flag error", []string{"remove", "--bogus", "nope"}, "", "unknown flag: --bogus"},
		{"unknown command", []string{"nosuchcommand"}, "", `unknown command "nosuchcommand"`},
		{"silenced command", []string{"scan"}, brokenGatewayConfig, "parsing config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.config != "" {
				writeGatewayConfig(t, home, tc.config)
			}
			_, stderr, code := run(t, home, tc.args...)
			if code == 0 {
				t.Fatalf("expected non-zero exit")
			}
			if got := strings.Count(stderr, tc.message); got != 1 {
				t.Fatalf("error printed %d times, want once:\n%s", got, stderr)
			}
		})
	}
}
