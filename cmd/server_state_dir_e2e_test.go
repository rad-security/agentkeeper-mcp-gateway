package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func localObserveConfig() map[string]interface{} {
	return map[string]interface{}{
		"mode":    "audit",
		"servers": []map[string]interface{}{crashableFixtureServer(nil)},
	}
}

func serveOneEcho(t *testing.T, gw *gatewayProcess) {
	t.Helper()
	gw.handshake(t)
	response := gw.request(t, 100, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}})
	if !strings.Contains(response, "FIXTURE_ECHO_OK") {
		t.Fatalf("call was not forwarded: %s\nstderr=%s", response, gw.stderrText())
	}
	gw.closeStdinAndWait(t, 10*time.Second)
}

// A fleet-managed config lives in a directory the developer cannot write (the
// README's /etc/agentkeeper-mcp-gateway/config.json layout). Gateway state
// must then live in the per-user directory beside the event log; refusing to
// start takes every routed MCP server away from an Observe user.
func TestObserveServesWhenConfigDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home := t.TempDir()
	systemDir := filepath.Join(t.TempDir(), "etc", "agentkeeper-mcp-gateway")
	if err := os.MkdirAll(systemDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(localObserveConfig())
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(systemDir, "config.json")
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(systemDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(systemDir, 0o755) })

	// Two launches: the first establishes state, the second must restore it.
	for launch := 1; launch <= 2; launch++ {
		gw := startGatewayProcessWithConfigPath(t, home, configPath)
		serveOneEcho(t, gw)
		if stderr := gw.stderrText(); !strings.Contains(stderr, "starting in observe mode") {
			t.Fatalf("launch %d did not start in Observe:\n%s", launch, stderr)
		}
	}

	signers, err := filepath.Glob(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "state", "*", "receipts-v2", "signing-key.json"))
	if err != nil || len(signers) != 1 {
		t.Fatalf("gateway state was not kept in one per-user directory: %v %v", signers, err)
	}
	entries, err := os.ReadDir(systemDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("read-only config directory was modified: %v", entries)
	}
}

// A home directory restored onto a replacement laptop carries the previous
// machine's Observe state. In local mode nothing can re-acknowledge it, so the
// Gateway must re-establish Observe for the new machine instead of exiting on
// every launch.
func TestLocalObserveRouteSurvivesMachineIdentityChange(t *testing.T) {
	home := t.TempDir()
	cfg := localObserveConfig()
	cfg["log_path"] = filepath.Join(home, "events.jsonl")

	serveOneEcho(t, startGatewayProcess(t, home, cfg, "AGENTKEEPER_MACHINE_ID=synthetic-previous-laptop"))
	for launch := 1; launch <= 2; launch++ {
		gw := startGatewayProcess(t, home, cfg, "AGENTKEEPER_MACHINE_ID=synthetic-replacement-laptop")
		serveOneEcho(t, gw)
		if stderr := gw.stderrText(); !strings.Contains(stderr, "starting in observe mode") {
			t.Fatalf("launch %d on the replacement machine did not start in Observe:\n%s", launch, stderr)
		}
	}
}
