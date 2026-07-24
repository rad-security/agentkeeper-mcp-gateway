package managedrouting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/runtimebroker"
)

func TestManagedConfigureIsIdempotentAndRemovalPreservesLaterChanges(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	t.Setenv(gatewayentry.EnvBinary, "/usr/bin/agentkeeper-mcp-gateway")
	clientPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(clientPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte(`{"theme":"dark","mcpServers":{"github":{"command":"github-mcp","args":["one"]}}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	managed := runtimebroker.ManagedConfig{
		SchemaVersion: 1, OwnershipID: "agentkeeper.universal.v1",
		Protocol: runtimebroker.Protocol, CredentialMode: runtimebroker.CredentialMode,
		RuntimeSocket: "/run/agentkeeper/runtime.sock",
	}
	manifestPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "managed-routing.json")
	first, err := configure(managed, "/etc/agentkeeper/mcp-gateway.json", manifestPath, Options{})
	if err != nil || !first.Changed || len(first.Configured) != 1 {
		t.Fatalf("initial managed configure failed: report=%+v err=%v", first, err)
	}
	manifestInfo, err := os.Stat(manifestPath)
	if err != nil || manifestInfo.Mode().Perm() != 0o600 {
		t.Fatalf("manifest is not private: info=%v err=%v", manifestInfo, err)
	}
	if info, err := os.Stat(config.CurrentConfigPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("gateway config containing migrated server credentials is not private: info=%v err=%v", info, err)
	}
	second, err := configure(managed, "/etc/agentkeeper/mcp-gateway.json", manifestPath, Options{})
	if err != nil || second.Changed {
		t.Fatalf("idempotent reconcile rewrote state: report=%+v err=%v", second, err)
	}

	// A server added after enrollment is migrated on the next reconcile and
	// remains represented in the ownership manifest for safe uninstall.
	rawClient, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	var clientRoot map[string]json.RawMessage
	if err := json.Unmarshal(rawClient, &clientRoot); err != nil {
		t.Fatal(err)
	}
	var clientServers map[string]json.RawMessage
	if err := json.Unmarshal(clientRoot["mcpServers"], &clientServers); err != nil {
		t.Fatal(err)
	}
	clientServers["later"] = json.RawMessage(`{"command":"later-mcp","args":["initial"]}`)
	clientRoot["mcpServers"], _ = json.Marshal(clientServers)
	updatedClient, _ := json.Marshal(clientRoot)
	if err := os.WriteFile(clientPath, updatedClient, 0o640); err != nil {
		t.Fatal(err)
	}
	third, err := configure(managed, "/etc/agentkeeper/mcp-gateway.json", manifestPath, Options{})
	if err != nil || !third.Changed {
		t.Fatalf("later server was not reconciled: report=%+v err=%v", third, err)
	}

	gatewayConfig, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	for index := range gatewayConfig.Servers {
		if gatewayConfig.Servers[index].Name == "later" {
			gatewayConfig.Servers[index].Args = []string{"customer-modified"}
		}
	}
	if err := config.Save(gatewayConfig); err != nil {
		t.Fatal(err)
	}
	report, err := remove(managed, manifestPath, false)
	if err != nil || !report.Changed {
		t.Fatalf("managed removal failed: report=%+v err=%v", report, err)
	}
	rawClient, err = os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawClient, &clientRoot); err != nil {
		t.Fatal(err)
	}
	clientServers = nil
	if err := json.Unmarshal(clientRoot["mcpServers"], &clientServers); err != nil {
		t.Fatal(err)
	}
	if clientServers["agentkeeper-mcp-gateway"] != nil || clientServers["github"] == nil || clientServers["later"] == nil {
		t.Fatalf("managed removal lost customer servers: %s", rawClient)
	}
	var later struct {
		Args []string `json:"args"`
	}
	if err := json.Unmarshal(clientServers["later"], &later); err != nil || len(later.Args) != 1 || later.Args[0] != "customer-modified" {
		t.Fatalf("post-install customer change was not preserved: %+v err=%v", later, err)
	}
	if info, err := os.Stat(clientPath); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("customer file mode was not preserved: info=%v err=%v", info, err)
	}
}

func TestManagedConfigureRoutesClaudeUserServerAddedAfterEnrollmentAndRestoresIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	t.Setenv(gatewayentry.EnvBinary, "/usr/bin/agentkeeper-mcp-gateway")
	managed := runtimebroker.ManagedConfig{
		SchemaVersion: 1, OwnershipID: "agentkeeper.universal.v1",
		Protocol: runtimebroker.Protocol, CredentialMode: runtimebroker.CredentialMode,
		RuntimeSocket: "/run/agentkeeper/runtime.sock",
	}
	manifestPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "managed-routing.json")
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{
  "mcpServers": {
    "existing-server": {
      "command": "existing-mcp"
    }
  }
}`), 0o640); err != nil {
		t.Fatal(err)
	}

	first, err := configure(managed, "/etc/agentkeeper/mcp-gateway.json", manifestPath, Options{Targets: []string{"claude-code"}})
	if err != nil || !first.Changed {
		t.Fatalf("initial managed configure failed: report=%+v err=%v", first, err)
	}

	claudeJSON := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(claudeJSON, []byte(`{
  "theme": "dark",
  "mcpServers": {
    "agentkeeper-mcp-gateway": {
      "command": "/usr/bin/agentkeeper-mcp-gateway",
      "args": ["server"]
    },
    "agentkeeper-e2e-everything": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"]
    }
  }
}`), 0o640); err != nil {
		t.Fatal(err)
	}

	second, err := configure(managed, "/etc/agentkeeper/mcp-gateway.json", manifestPath, Options{Targets: []string{"claude-code"}})
	if err != nil || !second.Changed {
		t.Fatalf("late Claude user server with a legacy managed entry was not adopted and routed: report=%+v err=%v", second, err)
	}
	raw, err := os.ReadFile(claudeJSON)
	if err != nil {
		t.Fatal(err)
	}
	var routed struct {
		Theme      string                     `json:"theme"`
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &routed); err != nil {
		t.Fatal(err)
	}
	if routed.Theme != "dark" || routed.MCPServers["agentkeeper-mcp-gateway"] == nil ||
		routed.MCPServers["agentkeeper-e2e-everything"] != nil {
		t.Fatalf("Claude user config was not structurally routed: %s", raw)
	}
	gatewayConfig, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, server := range gatewayConfig.Servers {
		if server.Name == "agentkeeper-e2e-everything" &&
			server.Command == "npx" &&
			len(server.Args) == 2 &&
			server.Args[1] == "@modelcontextprotocol/server-everything" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gateway config did not receive the late Claude user server: %+v", gatewayConfig.Servers)
	}

	removed, err := remove(managed, manifestPath, false)
	if err != nil || !removed.Changed {
		t.Fatalf("managed removal failed: report=%+v err=%v", removed, err)
	}
	raw, err = os.ReadFile(claudeJSON)
	if err != nil {
		t.Fatal(err)
	}
	routed.MCPServers = nil
	if err := json.Unmarshal(raw, &routed); err != nil {
		t.Fatal(err)
	}
	if routed.MCPServers["agentkeeper-mcp-gateway"] != nil ||
		routed.MCPServers["agentkeeper-e2e-everything"] == nil {
		t.Fatalf("managed removal did not restore the customer server: %s", raw)
	}
	if info, err := os.Stat(claudeJSON); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("Claude user config mode changed: info=%v err=%v", info, err)
	}
}

func TestRemoveWithoutManifestIsSafeOnlyWhenNoGatewayEntryExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	t.Setenv(gatewayentry.EnvBinary, "/usr/bin/agentkeeper-mcp-gateway")
	managed := runtimebroker.ManagedConfig{
		SchemaVersion: 1, OwnershipID: "agentkeeper.universal.v1",
		Protocol: runtimebroker.Protocol, CredentialMode: runtimebroker.CredentialMode,
		RuntimeSocket: "/run/agentkeeper/runtime.sock",
	}
	manifestPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "managed-routing.json")
	report, err := remove(managed, manifestPath, false)
	if err != nil || report.Result != "not_configured" {
		t.Fatalf("absent routing should remove idempotently: report=%+v err=%v", report, err)
	}
	clientPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(clientPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte(`{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"/usr/bin/agentkeeper-mcp-gateway","args":["server"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := remove(managed, manifestPath, false); err == nil {
		t.Fatal("missing ownership manifest must block destructive cleanup of a routed client")
	}
}

func TestRestoreClientRemovesOnlyOwnedGatewayAndPreservesCustomerChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	current := `{
  "theme": "dark",
  "mcpServers": {
    "agentkeeper-mcp-gateway": {"command":"/usr/bin/agentkeeper-mcp-gateway","args":["server"]},
    "added-after-install": {"command":"new-server"}
  }
}`
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := clientSnapshot{
		Name: "claude-code", Path: path,
		OriginalServers: map[string]json.RawMessage{
			"customer-original": json.RawMessage(`{"command":"original-server","env":{"TOKEN":"local-only"}}`),
		},
	}
	if err := restoreClient(snapshot, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Theme      string                     `json:"theme"`
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	if root.Theme != "dark" || root.MCPServers["agentkeeper-mcp-gateway"] != nil {
		t.Fatalf("owned entry or customer settings were not handled safely: %s", raw)
	}
	if root.MCPServers["customer-original"] == nil || root.MCPServers["added-after-install"] == nil {
		t.Fatalf("customer MCP entries were not preserved: %s", raw)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode changed: info=%v err=%v", info, err)
	}
}

func TestRestoreClientRefusesDriftedGatewayEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := []byte(`{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"/tmp/not-agentkeeper","args":["server"]}}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreClient(clientSnapshot{Name: "cursor", Path: path}, nil); err == nil {
		t.Fatal("drifted gateway entry should block removal")
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(original) {
		t.Fatalf("drifted customer file was modified: %s err=%v", current, err)
	}
}
