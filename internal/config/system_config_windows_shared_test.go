package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeRaw writes body at path and fails the test on error.
func writeRaw(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// The AgentKeeper runtime writes this shape to the Windows system location
// on every install. A Gateway installed beside it runs on its credential.
const runtimeOnlyConfig = `{
  "api_key": "ak_live_example",
  "api_url": "https://app.example.test",
  "machine_id": "winmg:0123456789abcdef0123456789abcdef",
  "platform": "windows",
  "target_user": "EXAMPLE\\alex",
  "os_username": "alex"
}`

// windowsHome points the home directory at a scratch folder and returns the
// shared system config path and the developer's own config path under it.
func windowsHome(t *testing.T) (system, homeCfg string) {
	t.Helper()
	isolateEnv(t)
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	system = filepath.Join(tmp, "ProgramData", "AgentKeeper", "config.json")
	homeCfg = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	return system, homeCfg
}

func TestResolveConfigPathForGOOS_WindowsStillReadsTheRuntimeConfig(t *testing.T) {
	// A Gateway installed beside the runtime has no config of its own and
	// runs on the credential in the shared file. Upgrading must not cut it
	// off from that credential.
	system, _ := windowsHome(t)
	writeRaw(t, system, runtimeOnlyConfig)

	if got := ResolveConfigPathForGOOS("", system, "windows"); got != system {
		t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, system)
	}
}

func TestResolveConfigPathForGOOS_WindowsUnreadableSystemConfigIsSkipped(t *testing.T) {
	// The runtime grants read access to one account. Another account on the
	// same machine can see the file but not open it, and every command
	// failed loading it.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root account")
	}
	system, homeCfg := windowsHome(t)
	writeRaw(t, system, `{"mode":"audit"}`)
	if err := os.Chmod(system, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if got := ResolveConfigPathForGOOS("", system, "windows"); got != homeCfg {
		t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, homeCfg)
	}
	if got := ResolveConfigPathForGOOS("", system, "linux"); got != system {
		t.Fatalf("POSIX resolution changed: %q, want %q", got, system)
	}
}

func TestSavePathForGOOS_WindowsSystemLocation(t *testing.T) {
	tests := []struct {
		name       string
		system     string
		beside     string // a file to create beside the system config
		wantSystem bool
	}{
		{
			name:   "runtime config is not the developer's to write",
			system: runtimeOnlyConfig,
		},
		{
			name:   "runtime config with a byte order mark",
			system: "\xef\xbb\xbf" + runtimeOnlyConfig,
		},
		{
			name: "fleet config written by the Gateway installer",
			system: `{"api_key":"ak_live_example","api_url":"https://app.example.test",` +
				`"machine_id":"winmg:0123456789abcdef0123456789abcdef","platform":"windows",` +
				`"mode":"audit","require_durable_events":true}`,
			wantSystem: true,
		},
		{
			name:       "config saved by the Gateway itself",
			system:     `{"mode":"enforce","verbose":false,"log_path":"","detection":{"threat":"warn","sensitive_data":"warn"},"servers":null}`,
			wantSystem: true,
		},
		{
			name:       "managed runtime transport is a Gateway setting",
			system:     `{"managed_runtime_socket":"\\\\.\\pipe\\example","credential_mode":"brokered"}`,
			wantSystem: true,
		},
		{
			// encoding/json matches field names without regard to case, so
			// this file's mode is in force.
			name:       "Gateway setting spelled in another case",
			system:     `{"api_key":"ak_live_example","Mode":"enforce"}`,
			wantSystem: true,
		},
		{
			// A damaged fleet config must be reported by the save, not
			// papered over with a new per-user one.
			name:       "malformed file",
			system:     `{"mode": `,
			wantSystem: true,
		},
		{
			// An administrator routed clients from here with an earlier
			// release. That setup keeps its manifest and its config together.
			name:       "manual routing manifest beside the runtime config",
			system:     runtimeOnlyConfig,
			beside:     "manual-routing.json",
			wantSystem: true,
		},
		{
			name:       "managed routing manifest beside the runtime config",
			system:     runtimeOnlyConfig,
			beside:     "managed-routing.json",
			wantSystem: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			system, homeCfg := windowsHome(t)
			writeRaw(t, system, tc.system)
			if tc.beside != "" {
				writeRaw(t, filepath.Join(filepath.Dir(system), tc.beside), `{}`)
			}

			want := homeCfg
			if tc.wantSystem {
				want = system
			}
			if got := SavePathForGOOS("", system, "windows"); got != want {
				t.Fatalf("SavePathForGOOS = %q, want %q", got, want)
			}
		})
	}
}

func TestSavePathForGOOS_ExplicitSelectionIsHonoured(t *testing.T) {
	// --config and AGENTKEEPER_CONFIG are authoritative, even when they name
	// the shared file.
	system, _ := windowsHome(t)
	writeRaw(t, system, runtimeOnlyConfig)

	if got := SavePathForGOOS(system, system, "windows"); got != system {
		t.Fatalf("flag: SavePathForGOOS = %q, want %q", got, system)
	}
	t.Setenv(envConfigPath, system)
	if got := SavePathForGOOS("", system, "windows"); got != system {
		t.Fatalf("env: SavePathForGOOS = %q, want %q", got, system)
	}
}

func TestSavePathForGOOS_DeveloperConfigIsWhereItSaves(t *testing.T) {
	system, homeCfg := windowsHome(t)
	writeRaw(t, system, runtimeOnlyConfig)
	writeJSON(t, homeCfg, Config{})

	if got := SavePathForGOOS("", system, "windows"); got != homeCfg {
		t.Fatalf("SavePathForGOOS = %q, want %q", got, homeCfg)
	}
}

func TestSavePathForGOOS_PosixSavesBesideTheSystemConfig(t *testing.T) {
	// /etc/agentkeeper-mcp-gateway holds nothing but the Gateway's config. A
	// save there still fails for a developer, by design.
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			system, _ := windowsHome(t)
			writeRaw(t, system, `{"api_key":"ak_live_example","api_url":"https://app.example.test"}`)

			if got := ResolveConfigPathForGOOS("", system, goos); got != system {
				t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, system)
			}
			if got := SavePathForGOOS("", system, goos); got != system {
				t.Fatalf("SavePathForGOOS = %q, want %q", got, system)
			}
		})
	}
}

// useSystemConfig makes Load, Save and the path helpers treat system as the
// Windows system config for the rest of the test.
func useSystemConfig(t *testing.T, system string) {
	t.Helper()
	restore := systemConfigLocation
	systemConfigLocation = func() (string, string) { return system, "windows" }
	t.Cleanup(func() { systemConfigLocation = restore })
}

func TestSaveAPIKey_WindowsRuntimeConfigIsLeftAlone(t *testing.T) {
	// Signing in beside the runtime writes the developer's own config, keeps
	// the API URL the machine was set up with, and leaves the runtime's file
	// byte for byte as it was.
	system, homeCfg := windowsHome(t)
	writeRaw(t, system, runtimeOnlyConfig)
	useSystemConfig(t, system)

	if err := SaveAPIKey("ak_live_developer"); err != nil {
		t.Fatalf("SaveAPIKey: %v", err)
	}

	saved, err := LoadWithPath(homeCfg)
	if err != nil {
		t.Fatalf("load developer config: %v", err)
	}
	if saved.APIKey != "ak_live_developer" || saved.APIURL != "https://app.example.test" {
		t.Fatalf("developer config api_key = %q, api_url = %q", saved.APIKey, saved.APIURL)
	}
	after, err := os.ReadFile(system)
	if err != nil {
		t.Fatalf("read runtime config: %v", err)
	}
	if string(after) != runtimeOnlyConfig {
		t.Fatalf("runtime config was rewritten:\n%s", after)
	}
	if got := CurrentConfigPath(); got != homeCfg {
		t.Fatalf("CurrentConfigPath = %q, want %q", got, homeCfg)
	}
}

func TestAddServer_WindowsKeepsTheRuntimeCredential(t *testing.T) {
	// Adding a server before signing in must not sign the Gateway out: the
	// developer's new config carries the credential it was running on.
	system, homeCfg := windowsHome(t)
	writeRaw(t, system, runtimeOnlyConfig)
	useSystemConfig(t, system)

	if err := AddServer(ServerEntry{Name: "notes", Command: "notes-server"}); err != nil {
		t.Fatalf("AddServer: %v", err)
	}

	if got := CurrentConfigPath(); got != homeCfg {
		t.Fatalf("CurrentConfigPath = %q, want %q", got, homeCfg)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "notes" {
		t.Fatalf("servers = %+v", cfg.Servers)
	}
	if cfg.APIKey != "ak_live_example" || cfg.APIURL != "https://app.example.test" {
		t.Fatalf("api_key = %q, api_url = %q", cfg.APIKey, cfg.APIURL)
	}
	after, _ := os.ReadFile(system)
	if string(after) != runtimeOnlyConfig {
		t.Fatalf("runtime config was rewritten:\n%s", after)
	}
}
