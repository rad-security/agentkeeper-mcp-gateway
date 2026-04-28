// Package config handles loading, merging, and validating the
// gateway configuration from files, environment variables, and
// CLI flags.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the merged gateway configuration.
type Config struct {
	// Gateway settings
	Mode    string `json:"mode" yaml:"mode"` // "audit" or "enforce"
	Verbose bool   `json:"verbose" yaml:"verbose"`
	LogPath string `json:"log_path" yaml:"log_path"`

	// Detection settings
	Detection DetectionConfig `json:"detection" yaml:"detection"`

	// Server configs
	Servers []ServerEntry `json:"servers" yaml:"servers"`

	// API connection (set by auth login)
	APIKey string `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	APIURL string `json:"api_url,omitempty" yaml:"api_url,omitempty"`

	// Dashboard policy (fetched, not configured locally)
	DashboardPolicy *DashboardPolicy `json:"-" yaml:"-"`
}

// DetectionConfig controls detection behavior.
type DetectionConfig struct {
	Threat         string   `json:"threat" yaml:"threat"`                   // "warn", "block", "monitor"
	SensitiveData  string   `json:"sensitive_data" yaml:"sensitive_data"`   // "warn", "block", "monitor"
	CustomKeywords []string `json:"custom_keywords,omitempty" yaml:"custom_keywords,omitempty"`
}

// ServerEntry is a server in the config file.
type ServerEntry struct {
	Name      string            `json:"name" yaml:"name"`
	Command   string            `json:"command" yaml:"command"`
	Args      []string          `json:"args,omitempty" yaml:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
	Transport string            `json:"transport,omitempty" yaml:"transport,omitempty"`
	URL       string            `json:"url,omitempty" yaml:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// Server is an alias for ServerEntry for backward compatibility.
type Server = ServerEntry

// DashboardPolicy represents policy fetched from the AgentKeeper dashboard.
type DashboardPolicy struct {
	Mode           string              `json:"mode"`
	BlockedServers []string            `json:"blocked_servers"`
	BlockedTools   map[string][]string `json:"blocked_tools"` // server -> tools
	CustomKeywords []string            `json:"custom_keywords"`
	Detection      DetectionConfig     `json:"detection"`
}

// Environment variable names the config layer reads.
const (
	envConfigPath = "AGENTKEEPER_CONFIG"
	envAPIKey     = "AGENTKEEPER_API_KEY"
	envAPIURL     = "AGENTKEEPER_API_URL"
)

// SystemConfigPath is the well-known fleet-deploy location. Configuration-
// management tools (Kanji, Ansible, Jamf, MDM) drop the gateway config here
// because they do not know any individual developer's home directory.
const SystemConfigPath = "/etc/agentkeeper-mcp-gateway/config.json"

// defaultAPIURL is treated as "blank" for env-override purposes — a config
// file that leaves APIURL at the factory default does not block the env var.
const defaultAPIURL = "https://www.agentkeeper.dev"

// Source labels where a resolved field came from. Used by LoadWithSource to
// power `config show` output. (ARB condition C4.)
type Source string

const (
	SourceFile    Source = "file"
	SourceEnv     Source = "env"
	SourceDefault Source = "default"
)

// LoadResult is the output of LoadWithSource: config plus per-field provenance.
type LoadResult struct {
	Config       Config
	Path         string // resolved config file path (may not exist)
	APIKeySource Source
	APIURLSource Source
}

// pathOverride is set by the root cobra command from --config.
// It is an in-process global to avoid threading an argument through every
// config function (Load/Save/AddServer/RemoveServer/SaveAPIKey) and every
// cobra handler. Tests call ResolveConfigPath directly and do not touch it.
var pathOverride string

// SetPathOverride wires the --config flag into the resolver.
func SetPathOverride(p string) { pathOverride = p }

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Mode:    "audit",
		Verbose: false,
		APIURL:  defaultAPIURL,
		Detection: DetectionConfig{
			Threat:        "warn",
			SensitiveData: "warn",
		},
	}
}

// ResolveConfigPath picks the config file path from (in order):
//  1. flag (--config)
//  2. $AGENTKEEPER_CONFIG
//  3. $XDG_CONFIG_HOME/agentkeeper-mcp-gateway/config.json  (if file exists)
//  4. ~/.config/agentkeeper-mcp-gateway/config.json          (if file exists)
//  5. systemFallback (typically SystemConfigPath)           (if file exists)
//  6. fallback to ~/.config/... (used for writes when nothing exists yet)
func ResolveConfigPath(flag, systemFallback string) string {
	if flag != "" {
		return flag
	}
	if p := os.Getenv(envConfigPath); p != "" {
		return p
	}

	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		p := filepath.Join(xdg, "agentkeeper-mcp-gateway", "config.json")
		if fileExists(p) {
			return p
		}
	}

	homeCfg := ""
	if home, err := os.UserHomeDir(); err == nil {
		homeCfg = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
		if fileExists(homeCfg) {
			return homeCfg
		}
	}

	if systemFallback != "" && fileExists(systemFallback) {
		return systemFallback
	}

	// Nothing exists yet — return a default path usable for Save.
	if homeCfg != "" {
		return homeCfg
	}
	return systemFallback
}

// fileExists reports whether path names a regular file readable by this process.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// LoadWithPath reads configuration from path and applies env-var overrides.
// A missing file is not an error — defaults plus env overrides are returned.
func LoadWithPath(path string) (Config, error) {
	res, err := LoadWithSource(path)
	return res.Config, err
}

// LoadWithSource is LoadWithPath plus per-field provenance for `config show`.
func LoadWithSource(path string) (LoadResult, error) {
	cfg := DefaultConfig()
	res := LoadResult{
		Path:         path,
		APIKeySource: SourceDefault,
		APIURLSource: SourceDefault,
	}

	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &cfg); err != nil {
				return res, fmt.Errorf("parsing config: %w", err)
			}
			if cfg.APIKey != "" {
				res.APIKeySource = SourceFile
			}
			if cfg.APIURL != "" && cfg.APIURL != defaultAPIURL {
				res.APIURLSource = SourceFile
			}
		case os.IsNotExist(err):
			// Fall through — defaults + env overrides still apply.
		default:
			return res, fmt.Errorf("reading config: %w", err)
		}
	}

	// Env overrides: file wins when set; env fills blanks or the factory URL.
	if cfg.APIKey == "" {
		if v := os.Getenv(envAPIKey); v != "" {
			cfg.APIKey = v
			res.APIKeySource = SourceEnv
		}
	}
	if cfg.APIURL == "" || cfg.APIURL == defaultAPIURL {
		if v := os.Getenv(envAPIURL); v != "" {
			cfg.APIURL = v
			res.APIURLSource = SourceEnv
		} else if cfg.APIURL == "" {
			cfg.APIURL = defaultAPIURL
		}
	}

	res.Config = cfg
	return res, nil
}

// Load reads configuration using the resolved path (--config / env / XDG /
// home / /etc / default fallback). Preserves the legacy signature so existing
// callers (cmd/*, internal/auth) need no changes.
func Load() (Config, error) {
	return LoadWithPath(ResolveConfigPath(pathOverride, SystemConfigPath))
}

// Save writes cfg to the resolved config path, creating the parent directory
// if needed. In a fleet deploy where the resolved path is /etc/..., a non-root
// developer will get EACCES — that is intentional. The fix is to re-render
// via the config-management tool, not to silently write to a different path.
func Save(cfg Config) error {
	path := ResolveConfigPath(pathOverride, SystemConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SaveAPIKey stores the API key from auth login.
func SaveAPIKey(apiKey string) error {
	cfg, err := Load()
	if err != nil {
		cfg = DefaultConfig()
	}
	cfg.APIKey = apiKey
	return Save(cfg)
}

// AddServer adds a server to the config.
func AddServer(entry ServerEntry) error {
	cfg, err := Load()
	if err != nil {
		cfg = DefaultConfig()
	}

	// Remove existing server with same name
	filtered := make([]ServerEntry, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		if s.Name != entry.Name {
			filtered = append(filtered, s)
		}
	}
	cfg.Servers = append(filtered, entry)

	return Save(cfg)
}

// RemoveServer removes a server from the config.
func RemoveServer(name string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}

	filtered := make([]ServerEntry, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		if s.Name != name {
			filtered = append(filtered, s)
		}
	}
	cfg.Servers = filtered

	return Save(cfg)
}

// MergeWithDashboard applies dashboard policy (additive-only: dashboard wins).
func (c *Config) MergeWithDashboard(policy DashboardPolicy) {
	c.DashboardPolicy = &policy

	// Dashboard mode overrides local
	if policy.Mode != "" {
		c.Mode = policy.Mode
	}

	// Dashboard detection settings override local (can only be stricter)
	if isStricter(policy.Detection.Threat, c.Detection.Threat) {
		c.Detection.Threat = policy.Detection.Threat
	}
	if isStricter(policy.Detection.SensitiveData, c.Detection.SensitiveData) {
		c.Detection.SensitiveData = policy.Detection.SensitiveData
	}

	// Merge custom keywords (additive)
	if len(policy.CustomKeywords) > 0 {
		seen := make(map[string]bool)
		for _, k := range c.Detection.CustomKeywords {
			seen[k] = true
		}
		for _, k := range policy.CustomKeywords {
			if !seen[k] {
				c.Detection.CustomKeywords = append(c.Detection.CustomKeywords, k)
			}
		}
	}
}

// isStricter returns true if a is stricter than b.
// block > warn > monitor > ""
func isStricter(a, b string) bool {
	rank := map[string]int{"": 0, "monitor": 1, "warn": 2, "block": 3}
	return rank[a] > rank[b]
}
