package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeJSON writes a config JSON file at path and fails the test on error.
func writeJSON(t *testing.T, path string, cfg Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// isolateEnv clears and restores the env vars this package reads.
// Tests run with t.Setenv so they auto-restore, but we want a clean slate.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		envConfigPath, envAPIKey, envAPIURL,
		"XDG_CONFIG_HOME", "HOME",
	} {
		t.Setenv(k, "")
	}
}

func TestResolveConfigPath(t *testing.T) {
	// Build a scratch tree with all four possible config locations populated,
	// then turn each source off one at a time to verify priority.
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	xdg := filepath.Join(tmp, "xdg")
	etc := filepath.Join(tmp, "etc", "agentkeeper-mcp-gateway", "config.json")
	xdgCfg := filepath.Join(xdg, "agentkeeper-mcp-gateway", "config.json")
	homeCfg := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	flagCfg := filepath.Join(tmp, "flag.json")
	envCfg := filepath.Join(tmp, "env.json")

	for _, p := range []string{flagCfg, envCfg, xdgCfg, homeCfg, etc} {
		writeJSON(t, p, Config{})
	}

	tests := []struct {
		name       string
		flag       string
		env        string
		useXDG     bool
		useHome    bool
		systemPath string
		want       string
	}{
		{
			name:       "flag beats everything",
			flag:       flagCfg,
			env:        envCfg,
			useXDG:     true,
			useHome:    true,
			systemPath: etc,
			want:       flagCfg,
		},
		{
			name:       "env beats XDG and home when no flag",
			env:        envCfg,
			useXDG:     true,
			useHome:    true,
			systemPath: etc,
			want:       envCfg,
		},
		{
			name:       "XDG beats home when no flag or env",
			useXDG:     true,
			useHome:    true,
			systemPath: etc,
			want:       xdgCfg,
		},
		{
			name:       "home beats system when XDG not set",
			useHome:    true,
			systemPath: etc,
			want:       homeCfg,
		},
		{
			name:       "system path used when no flag/env/XDG/home",
			systemPath: etc,
			want:       etc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			if tc.useXDG {
				t.Setenv("XDG_CONFIG_HOME", xdg)
			}
			if tc.useHome {
				t.Setenv("HOME", home)
			}
			if tc.env != "" {
				t.Setenv(envConfigPath, tc.env)
			}

			got := ResolveConfigPath(tc.flag, tc.systemPath)
			if got != tc.want {
				t.Fatalf("ResolveConfigPath(%q, %q) = %q, want %q",
					tc.flag, tc.systemPath, got, tc.want)
			}
		})
	}
}

func TestResolveConfigPath_FallbackWhenNothingExists(t *testing.T) {
	// When no file exists at any known location and no flag/env is set,
	// the resolver must still return a usable default path (for writes).
	isolateEnv(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	got := ResolveConfigPath("", "/etc/agentkeeper-mcp-gateway/config.json")
	want := filepath.Join(tmp, ".config", "agentkeeper-mcp-gateway", "config.json")
	if got != want {
		t.Fatalf("fallback = %q, want %q", got, want)
	}
}

func TestLoadWithPath_FileWinsOverEnv(t *testing.T) {
	// If the file has a populated api_key, AGENTKEEPER_API_KEY must not
	// shadow it — rotation happens by re-rendering the file.
	isolateEnv(t)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	writeJSON(t, path, Config{APIKey: "file-key", APIURL: "https://file.example"})
	t.Setenv(envAPIKey, "env-key")
	t.Setenv(envAPIURL, "https://env.example")

	cfg, err := LoadWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "file-key" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "file-key")
	}
	if cfg.APIURL != "https://file.example" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "https://file.example")
	}
}

func TestLoadWithPath_EnvFillsBlankField(t *testing.T) {
	// File exists but leaves api_key blank; env must populate it.
	// APIURL defaults to https://www.agentkeeper.dev and is treated as "blank"
	// for override purposes.
	isolateEnv(t)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	writeJSON(t, path, Config{}) // empty file — no API key, default URL
	t.Setenv(envAPIKey, "env-key")
	t.Setenv(envAPIURL, "https://env.example")

	cfg, err := LoadWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "env-key" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "env-key")
	}
	if cfg.APIURL != "https://env.example" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "https://env.example")
	}
}

func TestLoadWithPath_MissingFileUsesDefaults(t *testing.T) {
	isolateEnv(t)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "does-not-exist.json")

	cfg, err := LoadWithPath(path)
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if cfg.Mode != "audit" {
		t.Errorf("expected default mode audit, got %q", cfg.Mode)
	}
}

func TestLoadWithSource_LabelsFieldOrigins(t *testing.T) {
	// LoadWithSource reports where each overridable field came from.
	// Required by ARB condition C4 (source-labeled `config show`).
	isolateEnv(t)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	writeJSON(t, path, Config{APIKey: "file-key"}) // file sets key, not URL
	t.Setenv(envAPIURL, "https://env.example")

	res, err := LoadWithSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != path {
		t.Errorf("Path = %q, want %q", res.Path, path)
	}
	if res.APIKeySource != SourceFile {
		t.Errorf("APIKeySource = %q, want %q", res.APIKeySource, SourceFile)
	}
	if res.APIURLSource != SourceEnv {
		t.Errorf("APIURLSource = %q, want %q", res.APIURLSource, SourceEnv)
	}
}
