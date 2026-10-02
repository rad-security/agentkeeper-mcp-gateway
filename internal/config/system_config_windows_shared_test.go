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
// on every install. It is not a Gateway config.
const runtimeOnlyConfig = `{
  "api_key": "ak_live_example",
  "api_url": "https://www.agentkeeper.dev",
  "machine_id": "winmg:0123456789abcdef0123456789abcdef",
  "platform": "windows",
  "target_user": "EXAMPLE\\alex",
  "os_username": "alex"
}`

func TestResolveConfigPathForGOOS_WindowsSystemLocation(t *testing.T) {
	tests := []struct {
		name       string
		system     string
		wantSystem bool
	}{
		{
			name:       "runtime config without Gateway settings is not the Gateway's",
			system:     runtimeOnlyConfig,
			wantSystem: false,
		},
		{
			name:       "runtime config with a byte order mark is not the Gateway's",
			system:     "\xef\xbb\xbf" + runtimeOnlyConfig,
			wantSystem: false,
		},
		{
			name: "fleet config written by the Gateway installer is used",
			system: `{"api_key":"ak_live_example","api_url":"https://www.agentkeeper.dev",` +
				`"machine_id":"winmg:0123456789abcdef0123456789abcdef","platform":"windows",` +
				`"mode":"audit","require_durable_events":true}`,
			wantSystem: true,
		},
		{
			name:       "config saved by the Gateway itself is used",
			system:     `{"mode":"enforce","verbose":false,"log_path":"","detection":{"threat":"warn","sensitive_data":"warn"},"servers":null}`,
			wantSystem: true,
		},
		{
			name:       "managed runtime transport is a Gateway setting",
			system:     `{"managed_runtime_socket":"\\\\.\\pipe\\example","credential_mode":"brokered"}`,
			wantSystem: true,
		},
		{
			// A damaged fleet config must be reported, not silently replaced
			// by an empty per-user one.
			name:       "malformed file stays selected so loading reports it",
			system:     `{"mode": `,
			wantSystem: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			tmp := t.TempDir()
			home := filepath.Join(tmp, "home")
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			system := filepath.Join(tmp, "ProgramData", "AgentKeeper", "config.json")
			writeRaw(t, system, tc.system)

			want := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
			if tc.wantSystem {
				want = system
			}
			if got := ResolveConfigPathForGOOS("", system, "windows"); got != want {
				t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, want)
			}
		})
	}
}

func TestResolveConfigPathForGOOS_WindowsUnreadableSystemConfigIsSkipped(t *testing.T) {
	// The runtime grants read access to one account. Another account on the
	// same machine can see the file but not open it.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root account")
	}
	isolateEnv(t)
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	system := filepath.Join(tmp, "ProgramData", "AgentKeeper", "config.json")
	writeRaw(t, system, `{"mode":"audit"}`)
	if err := os.Chmod(system, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	want := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	if got := ResolveConfigPathForGOOS("", system, "windows"); got != want {
		t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, want)
	}
}

func TestResolveConfigPathForGOOS_UserConfigStillWinsOnWindows(t *testing.T) {
	isolateEnv(t)
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	system := filepath.Join(tmp, "ProgramData", "AgentKeeper", "config.json")
	writeRaw(t, system, `{"mode":"enforce"}`)
	homeCfg := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	writeJSON(t, homeCfg, Config{})

	if got := ResolveConfigPathForGOOS("", system, "windows"); got != homeCfg {
		t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, homeCfg)
	}
}

func TestResolveConfigPathForGOOS_PosixSystemLocationIsGatewayOnly(t *testing.T) {
	// /etc/agentkeeper-mcp-gateway holds nothing but the Gateway's config, so
	// a fleet config that carries only the credential still applies.
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			isolateEnv(t)
			tmp := t.TempDir()
			t.Setenv("HOME", filepath.Join(tmp, "home"))
			t.Setenv("USERPROFILE", filepath.Join(tmp, "home"))
			system := filepath.Join(tmp, "etc", "agentkeeper-mcp-gateway", "config.json")
			writeRaw(t, system, `{"api_key":"ak_live_example","api_url":"https://www.agentkeeper.dev"}`)

			if got := ResolveConfigPathForGOOS("", system, goos); got != system {
				t.Fatalf("ResolveConfigPathForGOOS = %q, want %q", got, system)
			}
		})
	}
}

func TestSaveAPIKey_WindowsRuntimeConfigIsLeftAlone(t *testing.T) {
	// Signing in on a machine that has only the runtime's config must write
	// the developer's own config and leave the runtime's file as it was.
	isolateEnv(t)
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	system := filepath.Join(tmp, "ProgramData", "AgentKeeper", "config.json")
	writeRaw(t, system, runtimeOnlyConfig)
	restore := systemConfigLocation
	systemConfigLocation = func() (string, string) { return system, "windows" }
	t.Cleanup(func() { systemConfigLocation = restore })

	if err := SaveAPIKey("ak_live_developer"); err != nil {
		t.Fatalf("SaveAPIKey: %v", err)
	}

	homeCfg := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	saved, err := LoadWithPath(homeCfg)
	if err != nil {
		t.Fatalf("load developer config: %v", err)
	}
	if saved.APIKey != "ak_live_developer" {
		t.Fatalf("developer config api_key = %q", saved.APIKey)
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
