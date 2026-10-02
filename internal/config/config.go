// Package config handles loading, merging, and validating the
// gateway configuration from files, environment variables, and
// CLI flags.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config represents the merged gateway configuration.
type Config struct {
	// Gateway settings
	Mode    string `json:"mode" yaml:"mode"` // "audit" or "enforce"
	Verbose bool   `json:"verbose" yaml:"verbose"`
	LogPath string `json:"log_path" yaml:"log_path"`
	// Fleet evidence durability. Enforce deployments can refuse upstream calls
	// when the local event spool cannot accept another terminal event.
	RequireDurableEvents bool  `json:"require_durable_events,omitempty" yaml:"require_durable_events,omitempty"`
	EventQueueMaxEvents  int   `json:"event_queue_max_events,omitempty" yaml:"event_queue_max_events,omitempty"`
	EventQueueMaxBytes   int64 `json:"event_queue_max_bytes,omitempty" yaml:"event_queue_max_bytes,omitempty"`

	// Detection settings
	Detection DetectionConfig `json:"detection" yaml:"detection"`

	// Server configs
	Servers []ServerEntry `json:"servers" yaml:"servers"`

	// API connection (set by auth login)
	APIKey string `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	APIURL string `json:"api_url,omitempty" yaml:"api_url,omitempty"`

	// Managed Linux runtime transport. These fields contain no credential; the
	// machine broker authenticates the gateway process with SO_PEERCRED and owns
	// the device credential.
	ManagedRuntimeSocket   string `json:"managed_runtime_socket,omitempty" yaml:"managed_runtime_socket,omitempty"`
	ManagedRuntimeProtocol string `json:"managed_runtime_protocol,omitempty" yaml:"managed_runtime_protocol,omitempty"`
	CredentialMode         string `json:"credential_mode,omitempty" yaml:"credential_mode,omitempty"`

	// Dashboard policy (fetched, not configured locally)
	DashboardPolicy *DashboardPolicy `json:"-" yaml:"-"`
}

// DetectionConfig controls detection behavior.
type DetectionConfig struct {
	Threat         string   `json:"threat" yaml:"threat"`                 // "warn", "block", "monitor"
	SensitiveData  string   `json:"sensitive_data" yaml:"sensitive_data"` // "warn", "block", "monitor"
	CustomKeywords []string `json:"custom_keywords,omitempty" yaml:"custom_keywords,omitempty"`
}

// ServerEntry is a server in the config file.
type ServerEntry struct {
	Type      string                     `json:"type,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
	Name      string                     `json:"name,omitempty" yaml:"name"`
	Command   string                     `json:"command,omitempty" yaml:"command"`
	Args      []string                   `json:"args,omitempty" yaml:"args,omitempty"`
	Env       map[string]string          `json:"env,omitempty" yaml:"env,omitempty"`
	Transport string                     `json:"transport,omitempty" yaml:"transport,omitempty"`
	URL       string                     `json:"url,omitempty" yaml:"url,omitempty"`
	Headers   map[string]string          `json:"headers,omitempty" yaml:"headers,omitempty"`
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

const (
	// SystemConfigPath is the POSIX well-known fleet-deploy location.
	// Configuration-management tools (Kandji, Ansible, Jamf, MDM) drop the
	// gateway config here because they do not know any individual developer's
	// home directory. Kept for backward compatibility with existing callers.
	SystemConfigPath = "/etc/agentkeeper-mcp-gateway/config.json"

	// WindowsSystemConfigPath is the Windows fleet-deploy location used by
	// Intune Win32 apps and remediations.
	WindowsSystemConfigPath = `C:\ProgramData\AgentKeeper\config.json`
)

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

func DefaultSystemConfigPathForGOOS(goos string) string {
	if goos == "windows" {
		return WindowsSystemConfigPath
	}
	return SystemConfigPath
}

func DefaultSystemConfigPath() string {
	return DefaultSystemConfigPathForGOOS(runtime.GOOS)
}

// systemConfigLocation returns the system config path and the operating
// system whose rules apply to it. Tests replace it.
var systemConfigLocation = func() (string, string) {
	return DefaultSystemConfigPath(), runtime.GOOS
}

func CurrentConfigPath() string {
	system, goos := systemConfigLocation()
	return ResolveConfigPathForGOOS(pathOverride, system, goos)
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Mode:                "audit",
		Verbose:             false,
		APIURL:              defaultAPIURL,
		EventQueueMaxEvents: 100000,
		EventQueueMaxBytes:  256 * 1024 * 1024,
		Detection: DetectionConfig{
			Threat:        "warn",
			SensitiveData: "warn",
		},
	}
}

func HasUsableAPIKey(apiKey string) bool {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return false
	}
	switch key {
	case "ak_live_YOURKEY", "ak_live_YOUR_KEY", "YOUR_API_KEY", "YOURKEY":
		return false
	default:
		return true
	}
}

// ResolveConfigPath picks the config file path from (in order):
//  1. flag (--config)
//  2. $AGENTKEEPER_CONFIG
//  3. $XDG_CONFIG_HOME/agentkeeper-mcp-gateway/config.json  (if file exists)
//  4. ~/.config/agentkeeper-mcp-gateway/config.json          (if file exists)
//  5. systemFallback (typically SystemConfigPath)           (if it is the
//     Gateway's fleet config; see isGatewaySystemConfig)
//  6. fallback to ~/.config/... (used for writes when nothing exists yet)
func ResolveConfigPath(flag, systemFallback string) string {
	return ResolveConfigPathForGOOS(flag, systemFallback, runtime.GOOS)
}

// ResolveConfigPathForGOOS is ResolveConfigPath with the operating system
// whose rules apply to systemFallback stated by the caller.
func ResolveConfigPathForGOOS(flag, systemFallback, goos string) string {
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

	if systemFallback != "" && isGatewaySystemConfig(systemFallback, goos) {
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

// gatewaySettingKeys are the config keys only the Gateway reads. api_key and
// api_url are left out: the AgentKeeper runtime stores its own under the same
// names.
var gatewaySettingKeys = []string{
	"mode", "verbose", "log_path",
	"require_durable_events", "event_queue_max_events", "event_queue_max_bytes",
	"detection", "servers",
	"managed_runtime_socket", "managed_runtime_protocol", "credential_mode",
}

// Routing manifests the Gateway writes beside its config.
const (
	ManualRoutingManifestName  = "manual-routing.json"
	ManagedRoutingManifestName = "managed-routing.json"
)

// isGatewaySystemConfig reports whether the file at the system location is
// this Gateway's fleet config.
//
// /etc/agentkeeper-mcp-gateway holds nothing else, so there the file's
// existence is the answer. The Windows location is shared: the AgentKeeper
// runtime writes its own config.json to C:\ProgramData\AgentKeeper on every
// install, readable by the developer and writable only by administrators.
// Selecting that file made every command that saves (auth login,
// configure-ide, add) fail with "Access is denied" for a developer, and
// rewrite the runtime's config for an administrator. On Windows the file is
// the Gateway's only when it holds a Gateway setting; the fleet installer and
// the Gateway's own Save both write one. A routing manifest beside the file
// also keeps it selected: an earlier release routed clients from there, and
// the routed Gateway has been running on that file's credential. A file this
// account cannot open is not its config either. A file that does not parse
// stays selected, so loading reports the damage instead of starting from an
// empty config.
func isGatewaySystemConfig(path, goos string) bool {
	if !fileExists(path) {
		return false
	}
	if goos != "windows" {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(stripUTF8BOM(data), &keys); err != nil {
		return true
	}
	for _, key := range gatewaySettingKeys {
		if _, ok := keys[key]; ok {
			return true
		}
	}
	for _, manifest := range []string{ManualRoutingManifestName, ManagedRoutingManifestName} {
		if fileExists(filepath.Join(filepath.Dir(path), manifest)) {
			return true
		}
	}
	return false
}

func stripUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		return data[3:]
	}
	return data
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
			data = stripUTF8BOM(data)
			if err := json.Unmarshal(data, &cfg); err != nil {
				return res, fmt.Errorf("parsing config %s: %w", path, err)
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
// home / system / default fallback). Preserves the legacy signature so existing
// callers (cmd/*, internal/auth) need no changes.
func Load() (Config, error) {
	return LoadWithPath(CurrentConfigPath())
}

// Save writes cfg to the resolved config path, creating the parent directory
// if needed. In a fleet deploy where the resolved path is /etc/..., a non-root
// developer will get EACCES — that is intentional. The fix is to re-render
// via the config-management tool, not to silently write to a different path.
func Save(cfg Config) error {
	path := CurrentConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentkeeper-config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// SaveAPIKey stores the API key from auth login. Like every mutator below, it
// refuses to save when the existing file cannot be read or parsed: writing
// defaults over it would silently discard the mode, key and servers it holds.
// A missing file is not an error (Load returns defaults), so a first run
// still creates the config.
func SaveAPIKey(apiKey string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	cfg.APIKey = apiKey
	return Save(cfg)
}

// AddServer adds a server to the config.
func AddServer(entry ServerEntry) error {
	cfg, err := Load()
	if err != nil {
		return err
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

// RemoveServer removes a server from the config. A name that is not
// registered is an error and leaves the config file untouched.
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
	if len(filtered) == len(cfg.Servers) {
		return fmt.Errorf("no server named %q in %s", name, CurrentConfigPath())
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
