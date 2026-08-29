package manualrouting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
)

func testAdapter(name, path string) *ideconfig.Adapter {
	return &ideconfig.Adapter{Name: name, PathResolver: func() (string, error) { return path, nil }}
}

func setupTest(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "gateway", "config.json")
	t.Setenv("AGENTKEEPER_CONFIG", configPath)
	t.Setenv(gatewayentry.EnvBinary, "/opt/agentkeeper/agentkeeper-mcp-gateway")
	return root, configPath
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func readDocument(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func readServers(t *testing.T, path string) map[string]ideconfig.ServerEntry {
	t.Helper()
	document := readDocument(t, path)
	servers := map[string]ideconfig.ServerEntry{}
	if err := json.Unmarshal(document["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	return servers
}

func TestConfigureAndRemoveRestoresExactBytesAndPriorGatewayServer(t *testing.T) {
	_, configPath := setupTest(t)
	clientPath := filepath.Join(filepath.Dir(configPath), "client.json")
	original := []byte("{\n  \"theme\": \"dark\",\n  \"mcpServers\": {\"fixture\": {\"command\": \"old-client\"}}\n}\n")
	writeFile(t, clientPath, original, 0o640)
	previous := config.ServerEntry{Name: "fixture", Command: "previous-gateway", Args: []string{"--keep"}}
	if err := config.Save(config.Config{Mode: "audit", Servers: []config.ServerEntry{previous}}); err != nil {
		t.Fatal(err)
	}
	adapter := testAdapter("claude-code", clientPath)

	configured, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}})
	if err != nil {
		t.Fatal(err)
	}
	if !configured.Changed || !reflect.DeepEqual(configured.MigratedServers, []string{"fixture"}) {
		t.Fatalf("unexpected configure report: %+v", configured)
	}
	manifestPath, _ := ManifestPath()
	if info, err := os.Stat(manifestPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode: info=%v err=%v", info, err)
	}
	installed, _ := config.Load()
	if installed.Servers[0].Command != "old-client" {
		t.Fatalf("migrated gateway server = %+v", installed.Servers)
	}

	removed, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed.ExactRestored, []string{"claude-code"}) || len(removed.StructuralRestored) != 0 {
		t.Fatalf("unexpected removal report: %+v", removed)
	}
	got, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("client bytes not restored\n got: %s\nwant: %s", got, original)
	}
	if info, _ := os.Stat(clientPath); info.Mode().Perm() != 0o640 {
		t.Fatalf("client mode = %o, want 640", info.Mode().Perm())
	}
	restored, _ := config.Load()
	if !reflect.DeepEqual(restored.Servers, []config.ServerEntry{previous}) {
		t.Fatalf("prior gateway server not restored: %+v", restored.Servers)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("manual manifest remains: %v", err)
	}
}

func TestRemovePreservesPostRouteDriftAndRestoresMigratedServer(t *testing.T) {
	root, _ := setupTest(t)
	clientPath := filepath.Join(root, "client.json")
	writeFile(t, clientPath, []byte(`{"mcpServers":{"fixture":{"command":"fixture"}},"theme":"dark"}`), 0o600)
	adapter := testAdapter("cursor", clientPath)
	if _, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}}); err != nil {
		t.Fatal(err)
	}
	document := readDocument(t, clientPath)
	servers := readServers(t, clientPath)
	servers["late"] = ideconfig.ServerEntry{Command: "late-server"}
	encodedServers, _ := json.Marshal(servers)
	document["mcpServers"] = encodedServers
	document["customer_added"] = json.RawMessage(`{"enabled":true}`)
	drifted, _ := json.MarshalIndent(document, "", "  ")
	writeFile(t, clientPath, append(drifted, '\n'), 0o600)

	report, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.StructuralRestored, []string{"cursor"}) {
		t.Fatalf("unexpected structural report: %+v", report)
	}
	got := readServers(t, clientPath)
	if _, ok := got[ideconfig.GatewayServerName]; ok {
		t.Fatal("owned gateway entry remains")
	}
	if got["fixture"].Command != "fixture" || got["late"].Command != "late-server" {
		t.Fatalf("servers not preserved/restored: %+v", got)
	}
	if _, ok := readDocument(t, clientPath)["customer_added"]; !ok {
		t.Fatal("post-route top-level setting was lost")
	}
}

func TestRemoveRefusesModifiedOwnedRouteAndGatewayDrift(t *testing.T) {
	t.Run("client route identity", func(t *testing.T) {
		root, _ := setupTest(t)
		clientPath := filepath.Join(root, "client.json")
		writeFile(t, clientPath, []byte(`{"mcpServers":{"fixture":{"command":"fixture"}}}`), 0o600)
		adapter := testAdapter("claude-code", clientPath)
		if _, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}}); err != nil {
			t.Fatal(err)
		}
		document := readDocument(t, clientPath)
		servers := readServers(t, clientPath)
		gateway := servers[ideconfig.GatewayServerName]
		gateway.Env[gatewayentry.EnvRouteRevision] = "route:tampered"
		servers[ideconfig.GatewayServerName] = gateway
		encoded, _ := json.Marshal(servers)
		document["mcpServers"] = encoded
		tampered, _ := json.MarshalIndent(document, "", "  ")
		writeFile(t, clientPath, append(tampered, '\n'), 0o600)
		before, _ := os.ReadFile(clientPath)

		_, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}})
		if err == nil || !strings.Contains(err.Error(), "route identity") {
			t.Fatalf("expected route identity refusal, got %v", err)
		}
		after, _ := os.ReadFile(clientPath)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("refused rollback changed the client config")
		}
	})

	t.Run("gateway server", func(t *testing.T) {
		root, _ := setupTest(t)
		clientPath := filepath.Join(root, "client.json")
		writeFile(t, clientPath, []byte(`{"mcpServers":{"fixture":{"command":"fixture"}}}`), 0o600)
		adapter := testAdapter("cursor", clientPath)
		if _, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}}); err != nil {
			t.Fatal(err)
		}
		cfg, _ := config.Load()
		cfg.Servers[0].Args = []string{"drifted"}
		if err := config.Save(cfg); err != nil {
			t.Fatal(err)
		}
		clientBefore, _ := os.ReadFile(clientPath)
		_, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}})
		if err == nil || !strings.Contains(err.Error(), "drifted") {
			t.Fatalf("expected gateway drift refusal, got %v", err)
		}
		clientAfter, _ := os.ReadFile(clientPath)
		if !reflect.DeepEqual(clientBefore, clientAfter) {
			t.Fatal("gateway drift refusal changed client route")
		}
	})
}

func TestDryRunAndAbsentConfigAreNonDestructive(t *testing.T) {
	root, _ := setupTest(t)
	clientPath := filepath.Join(root, "new-client.json")
	adapter := testAdapter("cursor", clientPath)
	report, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed {
		t.Fatalf("dry-run reported a durable change: %+v", report)
	}
	if _, err := os.Stat(clientPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run created client config: %v", err)
	}
	manifestPath, _ := ManifestPath()
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run created manifest: %v", err)
	}

	if _, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{adapter}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(clientPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(clientPath); !os.IsNotExist(err) {
		t.Fatalf("rollback did not restore file absence: %v", err)
	}
}

func TestPartialRemovalKeepsSharedMigratedServerUntilLastOwner(t *testing.T) {
	root, _ := setupTest(t)
	firstPath := filepath.Join(root, "first.json")
	secondPath := filepath.Join(root, "second.json")
	fixture := []byte(`{"mcpServers":{"shared":{"command":"shared-server"}}}`)
	writeFile(t, firstPath, fixture, 0o600)
	writeFile(t, secondPath, fixture, 0o600)
	first := testAdapter("claude-code", firstPath)
	second := testAdapter("cursor", secondPath)
	if _, err := Configure(ConfigureOptions{Adapters: []*ideconfig.Adapter{first, second}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{first}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load()
	if server, exists := findGatewayServer(cfg.Servers, "shared"); !exists || server.Command != "shared-server" {
		t.Fatalf("shared server removed before last owner: %+v", cfg.Servers)
	}
	if _, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{second}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load()
	if _, exists := findGatewayServer(cfg.Servers, "shared"); exists {
		t.Fatalf("shared server remains after final owner removal: %+v", cfg.Servers)
	}
}

func TestRemoveRefusesUnmanifestedRoute(t *testing.T) {
	root, _ := setupTest(t)
	clientPath := filepath.Join(root, "client.json")
	writeFile(t, clientPath, []byte(`{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"/opt/agentkeeper/agentkeeper-mcp-gateway","args":["server"]}}}`), 0o600)
	adapter := testAdapter("claude-code", clientPath)
	_, err := Remove(RemoveOptions{Adapters: []*ideconfig.Adapter{adapter}})
	if err == nil || !strings.Contains(err.Error(), "ownership manifest is missing") {
		t.Fatalf("expected missing ownership refusal, got %v", err)
	}
}
