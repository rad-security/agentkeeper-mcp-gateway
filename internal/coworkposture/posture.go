// Package coworkposture collects read-only Claude Desktop / Cowork posture
// checks and packages them for AgentKeeper's scan upload endpoint.
package coworkposture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	Source = "cowork_desktop_posture"

	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusSkipped = "SKIPPED"

	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var (
	dangerousTools = map[string]bool{
		"execute_javascript": true,
		"write_file":         true,
		"edit_file":          true,
		"run_command":        true,
		"execute_sql":        true,
		"bash":               true,
		"shell":              true,
	}

	riskyHookTerms = []string{
		"bash", "sh ", "zsh", "powershell", "cmd.exe", "curl", "wget",
		"invoke-webrequest", "net.webclient", "nc ", "ncat", "socat",
		"python -c", "node -e",
	}

	sensitiveKeyTerms = []string{
		"token", "secret", "password", "passwd", "api_key", "apikey",
		"authorization", "cookie", "oauth", "private_key", "privatekey",
		"client_secret", "access_key", "refresh",
	}
)

// ScanOptions controls local collection. OS is injectable so tests can cover
// Windows path layouts from non-Windows runners.
type ScanOptions struct {
	Home         string
	OS           string
	Now          time.Time
	MachineID    string
	AgentVersion string
}

// ScanPayload is accepted by AgentKeeper's POST /api/v1/scans route.
type ScanPayload struct {
	Source       string      `json:"source"`
	Hostname     string      `json:"hostname"`
	MachineID    string      `json:"machine_id,omitempty"`
	Platform     string      `json:"platform"`
	OSVersion    string      `json:"os_version,omitempty"`
	Score        int         `json:"score"`
	Grade        string      `json:"grade"`
	Passed       int         `json:"passed"`
	Failed       int         `json:"failed"`
	Fixed        int         `json:"fixed"`
	Skipped      int         `json:"skipped"`
	Checks       []ScanCheck `json:"checks"`
	RawReport    RawReport   `json:"raw_report"`
	ScannedAt    string      `json:"scanned_at,omitempty"`
	AgentVersion string      `json:"agent_version,omitempty"`
}

// Detected reports whether this payload found a Claude Desktop / Cowork data
// tree worth uploading. Missing/unsupported scans are useful in dry-run output
// but should not create dashboard noise for Claude Code-only hosts.
func (p ScanPayload) Detected() bool {
	return p.RawReport.ClaudeDesktopPresent
}

// ScanCheck is one dashboard-ready posture check.
type ScanCheck struct {
	Status    string         `json:"status"`
	CheckName string         `json:"check_name"`
	Detail    string         `json:"detail,omitempty"`
	Source    string         `json:"source,omitempty"`
	Category  string         `json:"category,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Evidence  map[string]any `json:"evidence,omitempty"`
}

// RawReport stores structured, redacted posture facts. It intentionally avoids
// raw config blobs, secret values, cookie contents, and absolute user paths.
type RawReport struct {
	ClaudeDesktopPresent bool                  `json:"claude_desktop_present"`
	Platform             string                `json:"platform"`
	AppDataKind          string                `json:"app_data_kind,omitempty"`
	Files                map[string]FileStatus `json:"files,omitempty"`
	Preferences          PreferenceSummary     `json:"preferences,omitempty"`
	MCPServers           []MCPServerSummary    `json:"mcp_servers,omitempty"`
	Dispatch             DispatchSummary       `json:"dispatch,omitempty"`
	Egress               EgressSummary         `json:"egress,omitempty"`
	Extensions           ExtensionSummary      `json:"extensions,omitempty"`
	Plugins              PluginSummary         `json:"plugins,omitempty"`
	Hooks                HookSummary           `json:"hooks,omitempty"`
	Connectors           ConnectorSummary      `json:"connectors,omitempty"`
	Skills               SkillSummary          `json:"skills,omitempty"`
	ScheduledTasks       ScheduledTaskSummary  `json:"scheduled_tasks,omitempty"`
	Runtime              RuntimeSummary        `json:"runtime,omitempty"`
	Cookies              CookieSummary         `json:"cookies,omitempty"`
	Unreadable           []string              `json:"unreadable,omitempty"`
}

type FileStatus struct {
	Present bool   `json:"present"`
	Status  string `json:"status,omitempty"`
}

type PreferenceSummary struct {
	KeepAwakeEnabled             *bool `json:"keep_awake_enabled,omitempty"`
	CoworkScheduledTasksEnabled  *bool `json:"cowork_scheduled_tasks_enabled,omitempty"`
	CodeDesktopScheduledTasks    *bool `json:"code_desktop_scheduled_tasks_enabled,omitempty"`
	CoworkWebSearchEnabled       *bool `json:"cowork_web_search_enabled,omitempty"`
	AllowAllBrowserActions       *bool `json:"allow_all_browser_actions,omitempty"`
	MenuBarEnabled               *bool `json:"menu_bar_enabled,omitempty"`
	SidebarModeObserved          bool  `json:"sidebar_mode_observed,omitempty"`
	QuickEntryShortcutConfigured bool  `json:"quick_entry_shortcut_configured,omitempty"`
}

type MCPServerSummary struct {
	NameHash          string   `json:"name_hash"`
	Type              string   `json:"type,omitempty"`
	CommandBasename   string   `json:"command_basename,omitempty"`
	ArgsCount         int      `json:"args_count,omitempty"`
	EnvKeys           []string `json:"env_keys,omitempty"`
	SensitiveEnvNames []string `json:"sensitive_env_names,omitempty"`
}

type DispatchSummary struct {
	BridgeConfigured      bool `json:"bridge_configured"`
	BridgeEntries         int  `json:"bridge_entries,omitempty"`
	ActiveSessionCount    int  `json:"active_session_count,omitempty"`
	UserConsentedEntries  int  `json:"user_consented_entries,omitempty"`
	BridgeStateFileFound  bool `json:"bridge_state_file_found"`
	SessionStateFilesSeen int  `json:"session_state_files_seen,omitempty"`
}

type EgressSummary struct {
	Observed         bool     `json:"observed"`
	Unrestricted     bool     `json:"unrestricted"`
	AllowedDomains   []string `json:"allowed_domains,omitempty"`
	SessionFilesSeen int      `json:"session_files_seen,omitempty"`
}

type ExtensionSummary struct {
	InstalledCount          int                 `json:"installed_count"`
	UnsignedCount           int                 `json:"unsigned_count,omitempty"`
	DangerousToolCount      int                 `json:"dangerous_tool_count,omitempty"`
	GovernancePresent       bool                `json:"governance_present"`
	AllowlistEnabled        bool                `json:"allowlist_enabled"`
	AllowlistKeys           int                 `json:"allowlist_keys,omitempty"`
	BlocklistEntries        int                 `json:"blocklist_entries,omitempty"`
	SettingsFiles           int                 `json:"settings_files,omitempty"`
	BroadAllowedDirectories int                 `json:"broad_allowed_directories,omitempty"`
	Examples                []ExtensionEvidence `json:"examples,omitempty"`
}

type ExtensionEvidence struct {
	IDHash         string   `json:"id_hash"`
	Name           string   `json:"name,omitempty"`
	Signature      string   `json:"signature,omitempty"`
	DangerousTools []string `json:"dangerous_tools,omitempty"`
}

type PluginSummary struct {
	EnabledCount            int      `json:"enabled_count,omitempty"`
	RemotePluginDirs        int      `json:"remote_plugin_dirs,omitempty"`
	CustomMarketplaceCount  int      `json:"custom_marketplace_count,omitempty"`
	PluginCacheDirs         int      `json:"plugin_cache_dirs,omitempty"`
	EnabledPluginNameHashes []string `json:"enabled_plugin_name_hashes,omitempty"`
	CustomMarketplaceHashes []string `json:"custom_marketplace_hashes,omitempty"`
}

type HookSummary struct {
	HookCount      int      `json:"hook_count,omitempty"`
	RiskyHookCount int      `json:"risky_hook_count,omitempty"`
	HookNames      []string `json:"hook_names,omitempty"`
}

type ConnectorSummary struct {
	Count      int      `json:"count,omitempty"`
	NameHashes []string `json:"name_hashes,omitempty"`
}

type SkillSummary struct {
	Count          int                 `json:"count,omitempty"`
	ScheduledCount int                 `json:"scheduled_count,omitempty"`
	Examples       []SkillFileEvidence `json:"examples,omitempty"`
}

type SkillFileEvidence struct {
	NameHash string `json:"name_hash"`
	Source   string `json:"source,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

type ScheduledTaskSummary struct {
	Definitions     int      `json:"definitions,omitempty"`
	SensitiveCount  int      `json:"sensitive_count,omitempty"`
	CronExpressions int      `json:"cron_expressions,omitempty"`
	TaskNameHashes  []string `json:"task_name_hashes,omitempty"`
	SourceFileCount int      `json:"source_file_count,omitempty"`
}

type RuntimeSummary struct {
	StartupEntries            int  `json:"startup_entries,omitempty"`
	SleepPreventionConfigured bool `json:"sleep_prevention_configured,omitempty"`
}

type CookieSummary struct {
	Present bool     `json:"present"`
	Files   []string `json:"files,omitempty"`
}

type scanner struct {
	home   string
	osName string
	now    time.Time
	appDir string
	raw    RawReport
	checks []ScanCheck
}

// Scan reads Claude Desktop / Cowork state from known current-user app-data
// paths. It never modifies local files and never reads cookie contents.
func Scan(opts ScanOptions) (ScanPayload, error) {
	home := opts.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return ScanPayload{}, fmt.Errorf("resolving home dir: %w", err)
		}
		home = h
	}
	osName := opts.OS
	if osName == "" {
		osName = runtime.GOOS
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	hostname, _ := os.Hostname()
	s := &scanner{
		home:   home,
		osName: osName,
		now:    now,
		appDir: appSupportDir(home, osName),
		raw: RawReport{
			Platform: osName,
			Files:    map[string]FileStatus{},
		},
	}
	s.raw.AppDataKind = appDataKind(osName)

	if s.appDir == "" {
		s.addCheck(StatusSkipped, "Claude Desktop & Cowork Support", "Claude Desktop posture collection is supported on macOS and Windows in this release.", "claude_desktop_cowork", SeverityInfo, nil)
		return s.finish(hostname, opts), nil
	}

	if !dirExists(s.appDir) {
		s.raw.Files["app_data_dir"] = FileStatus{Present: false, Status: "missing"}
		s.addCheck(StatusSkipped, "Claude Desktop Data Directory", "Claude Desktop app-data directory was not found for the current user.", "claude_desktop_cowork", SeverityInfo, nil)
		return s.finish(hostname, opts), nil
	}
	s.raw.ClaudeDesktopPresent = true
	s.raw.Files["app_data_dir"] = FileStatus{Present: true}

	desktopConfig := s.readJSON(filepath.Join(s.appDir, "claude_desktop_config.json"), "claude_desktop_config")
	configMap, _ := desktopConfig.(map[string]any)
	sessionDocs := s.readSessionJSON()
	allDocs := append([]any{}, desktopConfig)
	allDocs = append(allDocs, sessionDocs...)

	s.collectDesktopPreferences(configMap, allDocs)
	s.collectMCPServers(configMap)
	s.collectDispatch(allDocs)
	s.collectEgress(allDocs)
	s.collectExtensions(configMap)
	s.collectPlugins(allDocs)
	s.collectConnectors(allDocs)
	s.collectSkills()
	s.collectScheduledTasks(allDocs)
	s.collectRuntime()
	s.collectCookies()
	s.addDesktopSummary()

	return s.finish(hostname, opts), nil
}

func (s *scanner) finish(hostname string, opts ScanOptions) ScanPayload {
	score, grade := scoreChecks(s.checks)
	p := ScanPayload{
		Source:       Source,
		Hostname:     hostname,
		MachineID:    opts.MachineID,
		Platform:     s.osName,
		OSVersion:    runtime.GOOS + "/" + runtime.GOARCH,
		Score:        score,
		Grade:        grade,
		Checks:       s.checks,
		RawReport:    s.raw,
		ScannedAt:    s.now.UTC().Format(time.RFC3339),
		AgentVersion: opts.AgentVersion,
	}
	for _, c := range s.checks {
		switch c.Status {
		case StatusPass:
			p.Passed++
		case StatusFail:
			p.Failed++
		case StatusSkipped:
			p.Skipped++
		case "FIXED":
			p.Fixed++
		}
	}
	return p
}

func (s *scanner) addCheck(status, name, detail, category, severity string, evidence map[string]any) {
	if severity == "" {
		severity = SeverityInfo
	}
	s.checks = append(s.checks, ScanCheck{
		Status:    status,
		CheckName: name,
		Detail:    detail,
		Source:    Source,
		Category:  category,
		Severity:  severity,
		Evidence:  evidence,
	})
}

func (s *scanner) readJSON(path, label string) any {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.raw.Files[label] = FileStatus{Present: false, Status: "missing"}
		} else {
			s.raw.Files[label] = FileStatus{Present: false, Status: "unreadable"}
			s.raw.Unreadable = appendUnique(s.raw.Unreadable, label)
		}
		return nil
	}
	if info.IsDir() {
		s.raw.Files[label] = FileStatus{Present: true, Status: "directory"}
		return nil
	}
	if info.Size() > 5*1024*1024 {
		s.raw.Files[label] = FileStatus{Present: true, Status: "too_large"}
		s.raw.Unreadable = appendUnique(s.raw.Unreadable, label)
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.raw.Files[label] = FileStatus{Present: true, Status: "unreadable"}
		s.raw.Unreadable = appendUnique(s.raw.Unreadable, label)
		return nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		s.raw.Files[label] = FileStatus{Present: true, Status: "invalid_json"}
		s.raw.Unreadable = appendUnique(s.raw.Unreadable, label)
		return nil
	}
	s.raw.Files[label] = FileStatus{Present: true}
	return v
}

func (s *scanner) readSessionJSON() []any {
	root := filepath.Join(s.appDir, "local-agent-mode-sessions")
	if !dirExists(root) {
		s.raw.Files["local_agent_mode_sessions"] = FileStatus{Present: false, Status: "missing"}
		return nil
	}
	s.raw.Files["local_agent_mode_sessions"] = FileStatus{Present: true}

	var docs []any
	filesSeen := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil && strings.Count(rel, string(filepath.Separator)) > 8 {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			return nil
		}
		if filesSeen >= 400 {
			return filepath.SkipAll
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		if !looksLikeCoworkStateJSON(name) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			return nil
		}
		filesSeen++
		docs = append(docs, v)
		return nil
	})
	s.raw.Dispatch.SessionStateFilesSeen = filesSeen
	s.raw.Egress.SessionFilesSeen = filesSeen
	return docs
}

func looksLikeCoworkStateJSON(name string) bool {
	lower := strings.ToLower(name)
	return lower == "cowork_settings.json" ||
		lower == "settings.json" ||
		lower == "config.json" ||
		strings.HasPrefix(lower, "local_") ||
		strings.Contains(lower, "session") ||
		strings.Contains(lower, "task") ||
		strings.Contains(lower, "plugin")
}

func (s *scanner) collectDesktopPreferences(config map[string]any, docs []any) {
	prefs, _ := config["preferences"].(map[string]any)
	if prefs == nil {
		prefs = map[string]any{}
	}
	if v, ok := boolPointer(prefs["keepAwakeEnabled"]); ok {
		s.raw.Preferences.KeepAwakeEnabled = v
	}
	if v, ok := boolPointer(firstValue(docs, "coworkScheduledTasksEnabled", prefs)); ok {
		s.raw.Preferences.CoworkScheduledTasksEnabled = v
	}
	if v, ok := boolPointer(firstValue(docs, "ccdScheduledTasksEnabled", prefs)); ok {
		s.raw.Preferences.CodeDesktopScheduledTasks = v
	}
	if v, ok := boolPointer(firstValue(docs, "coworkWebSearchEnabled", prefs)); ok {
		s.raw.Preferences.CoworkWebSearchEnabled = v
	}
	if v, ok := boolPointer(firstValue(docs, "allowAllBrowserActions", prefs)); ok {
		s.raw.Preferences.AllowAllBrowserActions = v
	}
	if v, ok := boolPointer(prefs["menuBarEnabled"]); ok {
		s.raw.Preferences.MenuBarEnabled = v
	}
	if _, ok := prefs["sidebarMode"]; ok {
		s.raw.Preferences.SidebarModeObserved = true
	}
	if v, ok := prefs["quickEntryShortcut"].(string); ok && v != "" {
		s.raw.Preferences.QuickEntryShortcutConfigured = true
	}

	if truthy(s.raw.Preferences.KeepAwakeEnabled) {
		s.raw.Runtime.SleepPreventionConfigured = true
		s.addCheck(StatusFail, "Claude Desktop Sleep Prevention", "Claude Desktop is configured to keep the workstation awake.", "runtime", SeverityLow, map[string]any{
			"setting": "keepAwakeEnabled",
		})
	}
	if truthy(s.raw.Preferences.CoworkScheduledTasksEnabled) || truthy(s.raw.Preferences.CodeDesktopScheduledTasks) {
		s.addCheck(StatusFail, "Cowork Scheduled Tasks Enabled", "Claude Desktop scheduled task execution is enabled.", "scheduled_tasks", SeverityMedium, map[string]any{
			"cowork_scheduled_tasks_enabled": truthy(s.raw.Preferences.CoworkScheduledTasksEnabled),
			"ccd_scheduled_tasks_enabled":    truthy(s.raw.Preferences.CodeDesktopScheduledTasks),
		})
	}
	if truthy(s.raw.Preferences.CoworkWebSearchEnabled) {
		s.addCheck(StatusFail, "Cowork Web Search Enabled", "Cowork can autonomously use web search during task execution.", "egress", SeverityLow, map[string]any{
			"setting": "coworkWebSearchEnabled",
		})
	}
	if truthy(s.raw.Preferences.AllowAllBrowserActions) {
		s.addCheck(StatusFail, "Cowork Browser Actions", "Browser actions are fully allowed without per-action approval.", "browser", SeverityHigh, map[string]any{
			"setting": "allowAllBrowserActions",
		})
	} else if s.raw.Preferences.AllowAllBrowserActions != nil {
		s.addCheck(StatusPass, "Cowork Browser Actions", "Browser actions are not fully allowed.", "browser", SeverityInfo, map[string]any{
			"setting": "allowAllBrowserActions",
		})
	}
}

func (s *scanner) collectMCPServers(config map[string]any) {
	servers, _ := config["mcpServers"].(map[string]any)
	if len(servers) == 0 {
		s.addCheck(StatusPass, "Cowork MCP Servers", "No Claude Desktop MCP servers were configured.", "mcp_servers", SeverityInfo, nil)
		return
	}

	summaries := make([]MCPServerSummary, 0, len(servers))
	sensitiveNames := []string{}
	for name, raw := range servers {
		obj, _ := raw.(map[string]any)
		envKeys, sensitiveEnv := envKeysFromAny(obj["env"])
		sensitiveNames = append(sensitiveNames, sensitiveEnv...)
		argsCount := len(stringSliceFromAny(obj["args"]))
		cmdBase := commandBasename(stringValue(obj["command"]))
		serverType := stringValue(obj["type"])
		if serverType == "" {
			if stringValue(obj["url"]) != "" {
				serverType = "http"
			} else {
				serverType = "stdio"
			}
		}
		summaries = append(summaries, MCPServerSummary{
			NameHash:          stableHash(name),
			Type:              serverType,
			CommandBasename:   cmdBase,
			ArgsCount:         argsCount,
			EnvKeys:           envKeys,
			SensitiveEnvNames: sensitiveEnv,
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].NameHash < summaries[j].NameHash })
	s.raw.MCPServers = summaries

	evidence := map[string]any{
		"count": len(summaries),
	}
	if len(sensitiveNames) > 0 {
		sort.Strings(sensitiveNames)
		evidence["sensitive_env_names"] = uniqueStrings(sensitiveNames)
		s.addCheck(StatusFail, "Cowork MCP Sensitive Environment", "Claude Desktop MCP servers reference sensitive environment variable names.", "mcp_servers", SeverityMedium, evidence)
		return
	}
	s.addCheck(StatusPass, "Cowork MCP Servers", "Claude Desktop MCP servers were inventoried without secret values.", "mcp_servers", SeverityInfo, evidence)
}

func (s *scanner) collectDispatch(docs []any) {
	bridge := s.readJSON(filepath.Join(s.appDir, "bridge-state.json"), "bridge_state")
	if bridge != nil {
		s.raw.Dispatch.BridgeStateFileFound = true
	}
	entries, consented, configured := bridgeStateCounts(bridge)
	s.raw.Dispatch.BridgeEntries = entries
	s.raw.Dispatch.UserConsentedEntries = consented
	s.raw.Dispatch.BridgeConfigured = configured

	active := countTruthyKey(docs, "hostLoopMode")
	s.raw.Dispatch.ActiveSessionCount = active

	if active > 0 {
		s.addCheck(StatusFail, "Cowork Active Dispatch", "Cowork is actively accepting dispatched work from another device.", "dispatch", SeverityHigh, map[string]any{
			"active_session_count": active,
		})
		return
	}
	if configured {
		s.addCheck(StatusFail, "Cowork Dispatch Bridge", "Cowork dispatch bridge is configured for this desktop.", "dispatch", SeverityHigh, map[string]any{
			"bridge_entries":         entries,
			"user_consented_entries": consented,
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Dispatch", "Cowork dispatch bridge and active host loop were not detected.", "dispatch", SeverityInfo, nil)
}

func (s *scanner) collectEgress(docs []any) {
	domains := []string{}
	for _, v := range findValues(docs, "egressAllowedDomains") {
		domains = append(domains, stringSliceFromAny(v)...)
	}
	domains = uniqueStrings(domains)
	sort.Strings(domains)
	s.raw.Egress.Observed = len(domains) > 0
	s.raw.Egress.AllowedDomains = redactDomains(domains)
	s.raw.Egress.Unrestricted = containsWildcard(domains)

	if s.raw.Egress.Unrestricted {
		s.addCheck(StatusFail, "Cowork Egress Policy", "Cowork egress allows all destinations.", "egress", SeverityCritical, map[string]any{
			"unrestricted": true,
			"domains":      s.raw.Egress.AllowedDomains,
		})
		return
	}
	if len(domains) > 0 {
		s.addCheck(StatusPass, "Cowork Egress Policy", "Cowork egress is constrained to an allowlist.", "egress", SeverityInfo, map[string]any{
			"domain_count": len(domains),
			"domains":      s.raw.Egress.AllowedDomains,
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Egress Policy", "Unrestricted Cowork egress was not detected.", "egress", SeverityInfo, nil)
}

func (s *scanner) collectExtensions(config map[string]any) {
	installations := s.readJSON(filepath.Join(s.appDir, "extensions-installations.json"), "extensions_installations")
	extensions := extensionObjects(installations)
	s.raw.Extensions.InstalledCount = len(extensions)

	for _, ext := range extensions {
		id := firstString(ext, "id", "uuid", "identifier", "extensionId", "packageName")
		name := firstString(ext, "name", "displayName", "title")
		if id == "" {
			id = name
		}
		signature := signatureStatus(ext)
		dangerous := extensionDangerousTools(ext)
		if strings.EqualFold(signature, "unsigned") {
			s.raw.Extensions.UnsignedCount++
		}
		s.raw.Extensions.DangerousToolCount += len(dangerous)
		if len(s.raw.Extensions.Examples) < 20 {
			s.raw.Extensions.Examples = append(s.raw.Extensions.Examples, ExtensionEvidence{
				IDHash:         stableHash(id),
				Name:           safeDisplayName(name),
				Signature:      signature,
				DangerousTools: dangerous,
			})
		}
	}

	s.collectExtensionSettings()
	s.collectExtensionGovernance(config)

	if s.raw.Extensions.InstalledCount > 0 && !s.raw.Extensions.GovernancePresent {
		s.addCheck(StatusFail, "DXT Extension Governance", "Extensions are installed without local allowlist or blocklist governance evidence.", "extensions", SeverityHigh, map[string]any{
			"installed_count": s.raw.Extensions.InstalledCount,
		})
	} else if s.raw.Extensions.InstalledCount > 0 {
		s.addCheck(StatusPass, "DXT Extension Governance", "Extension governance evidence was found for installed extensions.", "extensions", SeverityInfo, map[string]any{
			"installed_count":    s.raw.Extensions.InstalledCount,
			"allowlist_enabled":  s.raw.Extensions.AllowlistEnabled,
			"blocklist_entries":  s.raw.Extensions.BlocklistEntries,
			"governance_present": s.raw.Extensions.GovernancePresent,
		})
	}

	if s.raw.Extensions.UnsignedCount > 0 || s.raw.Extensions.DangerousToolCount > 0 || s.raw.Extensions.BroadAllowedDirectories > 0 {
		s.addCheck(StatusFail, "DXT Extension Risk", "Installed extensions include unsigned packages, dangerous tools, or broad directory grants.", "extensions", SeverityMedium, map[string]any{
			"unsigned_count":            s.raw.Extensions.UnsignedCount,
			"dangerous_tool_count":      s.raw.Extensions.DangerousToolCount,
			"broad_allowed_directories": s.raw.Extensions.BroadAllowedDirectories,
		})
	} else if s.raw.Extensions.InstalledCount > 0 {
		s.addCheck(StatusPass, "DXT Extensions", "Installed DXT extensions were inventoried without high-risk local indicators.", "extensions", SeverityInfo, map[string]any{
			"installed_count": s.raw.Extensions.InstalledCount,
		})
	} else {
		s.addCheck(StatusPass, "DXT Extensions", "No installed DXT extensions were detected.", "extensions", SeverityInfo, nil)
	}
}

func (s *scanner) collectExtensionSettings() {
	settingsDir := filepath.Join(s.appDir, "Claude Extensions Settings")
	if !dirExists(settingsDir) {
		s.raw.Files["extension_settings_dir"] = FileStatus{Present: false, Status: "missing"}
		return
	}
	s.raw.Files["extension_settings_dir"] = FileStatus{Present: true}
	_ = filepath.WalkDir(settingsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if s.raw.Extensions.SettingsFiles >= 200 {
			return filepath.SkipAll
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 1024*1024 {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			return nil
		}
		s.raw.Extensions.SettingsFiles++
		for _, dirs := range findValues([]any{v}, "allowed_directories") {
			s.raw.Extensions.BroadAllowedDirectories += countBroadDirs(stringSliceFromAny(dirs), s.home)
		}
		for _, dirs := range findValues([]any{v}, "allowedDirectories") {
			s.raw.Extensions.BroadAllowedDirectories += countBroadDirs(stringSliceFromAny(dirs), s.home)
		}
		return nil
	})
}

func (s *scanner) collectExtensionGovernance(config map[string]any) {
	blocklist := s.readJSON(filepath.Join(s.appDir, "extensions-blocklist.json"), "extensions_blocklist")
	s.raw.Extensions.BlocklistEntries = countCollectionItems(blocklist)

	for key, val := range flattenMap(config) {
		if strings.Contains(strings.ToLower(key), "dxt:allowlistenabled") {
			s.raw.Extensions.AllowlistKeys++
			if boolValue(val) {
				s.raw.Extensions.AllowlistEnabled = true
			}
		}
	}
	s.raw.Extensions.GovernancePresent = s.raw.Extensions.AllowlistEnabled || s.raw.Extensions.BlocklistEntries > 0
}

func (s *scanner) collectPlugins(docs []any) {
	enabled := []string{}
	for _, v := range findValues(docs, "enabledPlugins") {
		enabled = append(enabled, pluginNamesFromAny(v)...)
	}
	enabled = uniqueStrings(enabled)
	sort.Strings(enabled)
	s.raw.Plugins.EnabledCount = len(enabled)
	for _, name := range enabled {
		if len(s.raw.Plugins.EnabledPluginNameHashes) < 50 {
			s.raw.Plugins.EnabledPluginNameHashes = append(s.raw.Plugins.EnabledPluginNameHashes, stableHash(name))
		}
	}

	marketplaces := []string{}
	for _, key := range []string{"extraKnownMarketplaces", "marketplaces", "customMarketplaces"} {
		for _, v := range findValues(docs, key) {
			marketplaces = append(marketplaces, stringSliceFromAny(v)...)
		}
	}
	marketplaces = uniqueStrings(marketplaces)
	sort.Strings(marketplaces)
	s.raw.Plugins.CustomMarketplaceCount = len(marketplaces)
	for _, marketplace := range marketplaces {
		if len(s.raw.Plugins.CustomMarketplaceHashes) < 50 {
			s.raw.Plugins.CustomMarketplaceHashes = append(s.raw.Plugins.CustomMarketplaceHashes, stableHash(marketplace))
		}
	}

	s.walkPluginDirs()
	s.collectHooks(docs)

	if s.raw.Hooks.RiskyHookCount > 0 {
		s.addCheck(StatusFail, "Cowork Plugin Hooks", "Plugin hooks can execute shell or network actions.", "plugins_hooks", SeverityHigh, map[string]any{
			"risky_hook_count": s.raw.Hooks.RiskyHookCount,
			"hook_count":       s.raw.Hooks.HookCount,
		})
	} else if s.raw.Hooks.HookCount > 0 {
		s.addCheck(StatusFail, "Cowork Plugin Hooks", "Plugin hooks are configured and should be reviewed.", "plugins_hooks", SeverityMedium, map[string]any{
			"hook_count": s.raw.Hooks.HookCount,
			"hook_names": s.raw.Hooks.HookNames,
		})
	} else {
		s.addCheck(StatusPass, "Cowork Plugin Hooks", "Risky Cowork plugin hooks were not detected.", "plugins_hooks", SeverityInfo, nil)
	}

	if s.raw.Plugins.RemotePluginDirs > 0 || s.raw.Plugins.CustomMarketplaceCount > 0 {
		s.addCheck(StatusFail, "Cowork Plugins And Marketplaces", "Remote plugins or custom marketplaces were detected.", "plugins", SeverityLow, map[string]any{
			"remote_plugin_dirs":       s.raw.Plugins.RemotePluginDirs,
			"custom_marketplace_count": s.raw.Plugins.CustomMarketplaceCount,
		})
		return
	}
	if s.raw.Plugins.EnabledCount > 0 || s.raw.Plugins.PluginCacheDirs > 0 {
		s.addCheck(StatusPass, "Cowork Plugins", "Cowork plugins were inventoried without remote marketplace indicators.", "plugins", SeverityInfo, map[string]any{
			"enabled_count":     s.raw.Plugins.EnabledCount,
			"plugin_cache_dirs": s.raw.Plugins.PluginCacheDirs,
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Plugins", "No Cowork plugin inventory was detected.", "plugins", SeverityInfo, nil)
}

func (s *scanner) walkPluginDirs() {
	root := filepath.Join(s.appDir, "local-agent-mode-sessions")
	if !dirExists(root) {
		return
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && strings.Count(rel, string(filepath.Separator)) > 8 {
			return filepath.SkipDir
		}
		name := strings.ToLower(d.Name())
		switch name {
		case "remote_cowork_plugins", "org-plugins", "org_plugins":
			s.raw.Plugins.RemotePluginDirs++
		case "plugins", "cowork_plugins":
			s.raw.Plugins.PluginCacheDirs++
		}
		return nil
	})
}

func (s *scanner) collectHooks(docs []any) {
	for _, v := range findValues(docs, "hooks") {
		hooks, risky, names := summarizeHooks(v)
		s.raw.Hooks.HookCount += hooks
		s.raw.Hooks.RiskyHookCount += risky
		for _, name := range names {
			if len(s.raw.Hooks.HookNames) < 30 {
				s.raw.Hooks.HookNames = appendUnique(s.raw.Hooks.HookNames, name)
			}
		}
	}
}

func (s *scanner) collectConnectors(docs []any) {
	names := []string{}
	for _, key := range []string{"connectors", "enabledConnectors", "oauthConnectors", "desktopIntegrations"} {
		for _, v := range findValues(docs, key) {
			names = append(names, connectorNamesFromAny(v)...)
		}
	}
	names = uniqueStrings(names)
	sort.Strings(names)
	s.raw.Connectors.Count = len(names)
	for _, name := range names {
		if len(s.raw.Connectors.NameHashes) < 50 {
			s.raw.Connectors.NameHashes = append(s.raw.Connectors.NameHashes, stableHash(name))
		}
	}
	if len(names) > 0 {
		s.addCheck(StatusFail, "Cowork Connectors", "OAuth or desktop connectors were detected.", "connectors", SeverityLow, map[string]any{
			"count": len(names),
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Connectors", "No Cowork connectors were detected in local settings.", "connectors", SeverityInfo, nil)
}

func (s *scanner) collectSkills() {
	root := filepath.Join(s.appDir, "local-agent-mode-sessions")
	if !dirExists(root) {
		s.addCheck(StatusPass, "Cowork Skills", "No Cowork skill directories were detected.", "skills", SeverityInfo, nil)
		return
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil && strings.Count(rel, string(filepath.Separator)) > 10 {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "SKILL.md" {
			return nil
		}
		s.raw.Skills.Count++
		source := "session"
		if strings.Contains(path, string(filepath.Separator)+"skills-plugin"+string(filepath.Separator)) {
			source = "plugin"
		}
		if strings.Contains(strings.ToLower(path), "scheduled") {
			source = "scheduled"
			s.raw.Skills.ScheduledCount++
		}
		if len(s.raw.Skills.Examples) < 30 {
			name := filepath.Base(filepath.Dir(path))
			s.raw.Skills.Examples = append(s.raw.Skills.Examples, SkillFileEvidence{
				NameHash: stableHash(name),
				Source:   source,
				Hash:     fileHash(path),
			})
		}
		return nil
	})

	if s.raw.Skills.Count > 0 {
		s.addCheck(StatusPass, "Cowork Skills", "Cowork skill files were inventoried by hash only.", "skills", SeverityInfo, map[string]any{
			"count":           s.raw.Skills.Count,
			"scheduled_count": s.raw.Skills.ScheduledCount,
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Skills", "No Cowork skill files were detected.", "skills", SeverityInfo, nil)
}

func (s *scanner) collectScheduledTasks(docs []any) {
	for _, v := range findValues(docs, "scheduledTasks") {
		s.summarizeScheduledValue(v)
	}
	for _, v := range findValues(docs, "tasks") {
		s.summarizeScheduledValue(v)
	}
	for _, v := range findValues(docs, "cron") {
		if stringValue(v) != "" {
			s.raw.ScheduledTasks.CronExpressions++
			s.raw.ScheduledTasks.Definitions++
		}
	}
	s.walkScheduledTaskFiles()

	if s.raw.ScheduledTasks.SensitiveCount > 0 {
		s.addCheck(StatusFail, "Cowork Scheduled Task Definitions", "Scheduled tasks have broad filesystem, browser, network, or command access indicators.", "scheduled_tasks", SeverityHigh, map[string]any{
			"definitions":     s.raw.ScheduledTasks.Definitions,
			"sensitive_count": s.raw.ScheduledTasks.SensitiveCount,
		})
		return
	}
	if s.raw.ScheduledTasks.Definitions > 0 {
		s.addCheck(StatusFail, "Cowork Scheduled Task Definitions", "Scheduled task definitions were detected and should be reviewed.", "scheduled_tasks", SeverityMedium, map[string]any{
			"definitions":      s.raw.ScheduledTasks.Definitions,
			"cron_expressions": s.raw.ScheduledTasks.CronExpressions,
		})
		return
	}
	s.addCheck(StatusPass, "Cowork Scheduled Task Definitions", "No Cowork scheduled task definitions were detected.", "scheduled_tasks", SeverityInfo, nil)
}

func (s *scanner) summarizeScheduledValue(v any) {
	switch typed := v.(type) {
	case []any:
		for _, item := range typed {
			s.summarizeScheduledValue(item)
		}
	case map[string]any:
		if looksLikeScheduledTask(typed) {
			s.raw.ScheduledTasks.Definitions++
			if cron := firstString(typed, "cron", "schedule", "cronExpression"); cron != "" {
				s.raw.ScheduledTasks.CronExpressions++
			}
			if name := firstString(typed, "name", "title", "id"); name != "" && len(s.raw.ScheduledTasks.TaskNameHashes) < 50 {
				s.raw.ScheduledTasks.TaskNameHashes = append(s.raw.ScheduledTasks.TaskNameHashes, stableHash(name))
			}
			if scheduledTaskLooksSensitive(typed) {
				s.raw.ScheduledTasks.SensitiveCount++
			}
		}
	case string:
		if strings.Contains(strings.ToLower(typed), "cron") {
			s.raw.ScheduledTasks.Definitions++
		}
	}
}

func (s *scanner) walkScheduledTaskFiles() {
	root := s.appDir
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && strings.Count(rel, string(filepath.Separator)) > 8 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		if d.IsDir() {
			return nil
		}
		if !(strings.Contains(name, "scheduled") || strings.Contains(name, "task")) {
			return nil
		}
		if !(strings.HasSuffix(name, ".json") || name == "skill.md" || strings.HasSuffix(name, ".md")) {
			return nil
		}
		if s.raw.ScheduledTasks.SourceFileCount >= 100 {
			return filepath.SkipAll
		}
		s.raw.ScheduledTasks.SourceFileCount++
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 512*1024 {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lower := strings.ToLower(string(data))
		if containsAny(lower, []string{"websearch", "webfetch", "browser", "bash", "run_command", "write_file", "edit_file", "network", "filesystem"}) {
			s.raw.ScheduledTasks.SensitiveCount++
		}
		return nil
	})
}

func (s *scanner) collectRuntime() {
	switch s.osName {
	case "darwin":
		launchAgents := filepath.Join(s.home, "Library", "LaunchAgents")
		s.raw.Runtime.StartupEntries = countNameMatches(launchAgents, []string{"claude", "anthropic"})
	case "windows":
		startup := filepath.Join(s.home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
		s.raw.Runtime.StartupEntries = countNameMatches(startup, []string{"claude", "anthropic"})
	}
	if s.raw.Runtime.StartupEntries > 0 || s.raw.Runtime.SleepPreventionConfigured {
		s.addCheck(StatusFail, "Claude Runtime State", "Claude startup or sleep-prevention state was detected.", "runtime", SeverityLow, map[string]any{
			"startup_entries":             s.raw.Runtime.StartupEntries,
			"sleep_prevention_configured": s.raw.Runtime.SleepPreventionConfigured,
		})
		return
	}
	s.addCheck(StatusPass, "Claude Runtime State", "Claude startup entries and sleep-prevention settings were not detected.", "runtime", SeverityInfo, nil)
}

func (s *scanner) collectCookies() {
	cookieNames := []string{}
	for _, name := range []string{"Cookies", "Cookies-journal"} {
		path := filepath.Join(s.appDir, name)
		if fileExists(path) {
			cookieNames = append(cookieNames, name)
		}
	}
	partitions := filepath.Join(s.appDir, "Partitions")
	if dirExists(partitions) {
		_ = filepath.WalkDir(partitions, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == "Cookies" || d.Name() == "Cookies-journal" {
				cookieNames = appendUnique(cookieNames, filepath.Base(filepath.Dir(path))+"/"+d.Name())
			}
			return nil
		})
	}
	sort.Strings(cookieNames)
	s.raw.Cookies.Files = cookieNames
	s.raw.Cookies.Present = len(cookieNames) > 0
	if s.raw.Cookies.Present {
		s.addCheck(StatusFail, "Claude Cookies Present", "Claude cookie database files are present; contents were not read.", "cookies", SeverityLow, map[string]any{
			"files": cookieNames,
		})
		return
	}
	s.addCheck(StatusPass, "Claude Cookies Present", "Claude cookie database files were not detected.", "cookies", SeverityInfo, nil)
}

func (s *scanner) addDesktopSummary() {
	if s.raw.Preferences.KeepAwakeEnabled != nil ||
		s.raw.Preferences.MenuBarEnabled != nil ||
		s.raw.Preferences.SidebarModeObserved ||
		s.raw.Preferences.QuickEntryShortcutConfigured {
		s.addCheck(StatusPass, "Claude Desktop Preferences", "Claude Desktop preference state was inventoried.", "claude_desktop_cowork", SeverityInfo, map[string]any{
			"menu_bar_observed":               s.raw.Preferences.MenuBarEnabled != nil,
			"sidebar_mode_observed":           s.raw.Preferences.SidebarModeObserved,
			"quick_entry_shortcut_configured": s.raw.Preferences.QuickEntryShortcutConfigured,
		})
	}
}

// Send POSTs the scan payload to {apiURL}/api/v1/scans.
func Send(apiURL, apiKey, machineID string, payload ScanPayload) ([]byte, error) {
	if apiURL == "" {
		apiURL = "https://www.agentkeeper.dev"
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/api/v1/scans"
	if payload.MachineID == "" {
		payload.MachineID = machineID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encoding scan payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building scan request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if machineID != "" {
		req.Header.Set("X-Machine-Id", machineID)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST scan: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBody, fmt.Errorf("scan HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	return respBody, nil
}

func scoreChecks(checks []ScanCheck) (int, string) {
	categoryMax := map[string]int{}
	for _, c := range checks {
		if c.Status != StatusFail {
			continue
		}
		points := severityDeduction(c.Severity)
		if points == 0 {
			continue
		}
		category := c.Category
		if category == "" {
			category = c.CheckName
		}
		if points > categoryMax[category] {
			categoryMax[category] = points
		}
	}
	score := 100
	for _, points := range categoryMax {
		score -= points
	}
	if score < 0 {
		score = 0
	}
	return score, gradeForScore(score)
}

func severityDeduction(severity string) int {
	switch strings.ToLower(severity) {
	case SeverityCritical:
		return 20
	case SeverityHigh:
		return 12
	case SeverityMedium:
		return 6
	case SeverityLow:
		return 3
	default:
		return 0
	}
}

func gradeForScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func appSupportDir(home, osName string) string {
	switch osName {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	}
	return ""
}

func appDataKind(osName string) string {
	switch osName {
	case "darwin":
		return "macos_current_user"
	case "windows":
		return "windows_current_user"
	default:
		return "unsupported"
	}
}

func boolPointer(v any) (*bool, bool) {
	switch typed := v.(type) {
	case bool:
		return &typed, true
	case string:
		lower := strings.ToLower(strings.TrimSpace(typed))
		if lower == "true" {
			b := true
			return &b, true
		}
		if lower == "false" {
			b := false
			return &b, true
		}
	}
	return nil, false
}

func truthy(v *bool) bool {
	return v != nil && *v
}

func boolValue(v any) bool {
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func firstValue(docs []any, key string, fallback map[string]any) any {
	if fallback != nil {
		if v, ok := fallback[key]; ok {
			return v
		}
	}
	values := findValues(docs, key)
	if len(values) > 0 {
		return values[0]
	}
	return nil
}

func findValues(docs []any, key string) []any {
	var out []any
	for _, doc := range docs {
		walkValue(doc, 0, func(k string, v any) {
			if k == key {
				out = append(out, v)
			}
		})
	}
	return out
}

func walkValue(v any, depth int, visit func(string, any)) {
	if depth > 12 {
		return
	}
	switch typed := v.(type) {
	case map[string]any:
		for k, val := range typed {
			visit(k, val)
			walkValue(val, depth+1, visit)
		}
	case []any:
		for _, item := range typed {
			walkValue(item, depth+1, visit)
		}
	}
}

func countTruthyKey(docs []any, key string) int {
	count := 0
	for _, v := range findValues(docs, key) {
		if boolValue(v) {
			count++
		}
	}
	return count
}

func stringValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringValue(m[key]); v != "" {
			return v
		}
	}
	return ""
}

func stringSliceFromAny(v any) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := stringValue(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(typed))
		for key, val := range typed {
			if boolValue(val) {
				out = append(out, key)
			}
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func envKeysFromAny(v any) ([]string, []string) {
	envMap, _ := v.(map[string]any)
	keys := make([]string, 0, len(envMap))
	sensitive := []string{}
	for key := range envMap {
		keys = append(keys, key)
		if isSensitiveKey(key) {
			sensitive = append(sensitive, key)
		}
	}
	sort.Strings(keys)
	sort.Strings(sensitive)
	return keys, sensitive
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, term := range sensitiveKeyTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func commandBasename(command string) string {
	if command == "" {
		return ""
	}
	return filepath.Base(command)
}

func bridgeStateCounts(v any) (entries, consented int, configured bool) {
	m, _ := v.(map[string]any)
	for _, raw := range m {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		entries++
		if boolValue(entry["userConsented"]) {
			consented++
		}
		if boolValue(entry["enabled"]) {
			configured = true
		}
	}
	return entries, consented, configured
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "*" || v == "0.0.0.0/0" || v == "::/0" {
			return true
		}
	}
	return false
}

func redactDomains(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if isSensitiveString(v) {
			out = append(out, "[REDACTED]")
		} else {
			out = append(out, v)
		}
	}
	return out
}

func extensionObjects(v any) []map[string]any {
	switch typed := v.(type) {
	case []any:
		out := []map[string]any{}
		for _, item := range typed {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		if installs, ok := typed["installations"]; ok {
			return extensionObjects(installs)
		}
		if extensions, ok := typed["extensions"]; ok {
			return extensionObjects(extensions)
		}
		out := []map[string]any{}
		for key, item := range typed {
			if m, ok := item.(map[string]any); ok {
				if _, hasID := m["id"]; !hasID {
					m["id"] = key
				}
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func signatureStatus(ext map[string]any) string {
	if s := firstString(ext, "signatureStatus", "signature_status"); s != "" {
		return s
	}
	if sig, ok := ext["signatureInfo"].(map[string]any); ok {
		return firstString(sig, "status", "signatureStatus")
	}
	return ""
}

func extensionDangerousTools(ext map[string]any) []string {
	tools := []string{}
	for _, v := range findValues([]any{ext}, "tools") {
		for _, tool := range toolNamesFromAny(v) {
			if dangerousTools[strings.ToLower(tool)] {
				tools = appendUnique(tools, strings.ToLower(tool))
			}
		}
	}
	sort.Strings(tools)
	return tools
}

func toolNamesFromAny(v any) []string {
	switch typed := v.(type) {
	case []any:
		out := []string{}
		for _, item := range typed {
			switch t := item.(type) {
			case string:
				out = append(out, t)
			case map[string]any:
				if name := firstString(t, "name", "tool", "id"); name != "" {
					out = append(out, name)
				}
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(typed))
		for key := range typed {
			out = append(out, key)
		}
		return out
	default:
		return nil
	}
}

func flattenMap(m map[string]any) map[string]any {
	out := map[string]any{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch typed := v.(type) {
		case map[string]any:
			for key, val := range typed {
				next := key
				if prefix != "" {
					next = prefix + "." + key
				}
				out[next] = val
				walk(next, val)
			}
		}
	}
	walk("", m)
	return out
}

func countCollectionItems(v any) int {
	switch typed := v.(type) {
	case []any:
		return len(typed)
	case map[string]any:
		if items, ok := typed["items"]; ok {
			return countCollectionItems(items)
		}
		if entries, ok := typed["entries"]; ok {
			return countCollectionItems(entries)
		}
		return len(typed)
	default:
		return 0
	}
}

func countBroadDirs(dirs []string, home string) int {
	count := 0
	for _, dir := range dirs {
		cleaned := strings.TrimSpace(filepath.Clean(strings.ReplaceAll(dir, "\\", "/")))
		lower := strings.ToLower(cleaned)
		switch {
		case cleaned == "/" || cleaned == "~" || cleaned == ".":
			count++
		case strings.EqualFold(cleaned, filepath.Clean(home)):
			count++
		case lower == "c:" || lower == "c:/" || lower == "%userprofile%":
			count++
		case strings.HasSuffix(lower, "/documents") || strings.HasSuffix(lower, "/desktop"):
			count++
		}
	}
	return count
}

func pluginNamesFromAny(v any) []string {
	switch typed := v.(type) {
	case []any:
		out := []string{}
		for _, item := range typed {
			if s := stringValue(item); s != "" {
				out = append(out, s)
			}
			if m, ok := item.(map[string]any); ok {
				if name := firstString(m, "name", "id", "plugin"); name != "" {
					out = append(out, name)
				}
			}
		}
		return out
	case map[string]any:
		out := []string{}
		for key, val := range typed {
			if boolValue(val) {
				out = append(out, key)
			}
		}
		return out
	default:
		return stringSliceFromAny(v)
	}
}

func summarizeHooks(v any) (count int, risky int, names []string) {
	switch typed := v.(type) {
	case map[string]any:
		for key, val := range typed {
			names = appendUnique(names, key)
			c, r, childNames := summarizeHookEntries(val)
			count += c
			risky += r
			for _, name := range childNames {
				names = appendUnique(names, name)
			}
		}
	case []any:
		c, r, childNames := summarizeHookEntries(typed)
		count += c
		risky += r
		for _, name := range childNames {
			names = appendUnique(names, name)
		}
	}
	sort.Strings(names)
	return count, risky, names
}

func summarizeHookEntries(v any) (count int, risky int, names []string) {
	switch typed := v.(type) {
	case []any:
		for _, item := range typed {
			c, r, childNames := summarizeHookEntries(item)
			count += c
			risky += r
			names = append(names, childNames...)
		}
	case map[string]any:
		count++
		if name := firstString(typed, "name", "event", "type"); name != "" {
			names = appendUnique(names, name)
		}
		if hookLooksRisky(typed) {
			risky++
		}
	case string:
		count++
		if stringLooksRiskyHook(typed) {
			risky++
		}
	}
	return count, risky, names
}

func hookLooksRisky(m map[string]any) bool {
	for _, val := range m {
		switch typed := val.(type) {
		case string:
			if stringLooksRiskyHook(typed) {
				return true
			}
		case []any, map[string]any:
			b, _ := json.Marshal(typed)
			if stringLooksRiskyHook(string(b)) {
				return true
			}
		}
	}
	return false
}

func stringLooksRiskyHook(s string) bool {
	lower := strings.ToLower(s)
	return containsAny(lower, riskyHookTerms)
}

func connectorNamesFromAny(v any) []string {
	switch typed := v.(type) {
	case map[string]any:
		out := []string{}
		for key, val := range typed {
			if boolValue(val) {
				out = append(out, key)
				continue
			}
			if m, ok := val.(map[string]any); ok {
				if boolValue(m["enabled"]) || boolValue(m["connected"]) || boolValue(m["authenticated"]) {
					out = append(out, key)
				}
			}
		}
		return out
	case []any:
		out := []string{}
		for _, item := range typed {
			if s := stringValue(item); s != "" {
				out = append(out, s)
			}
			if m, ok := item.(map[string]any); ok {
				if name := firstString(m, "name", "id", "service"); name != "" {
					out = append(out, name)
				}
			}
		}
		return out
	default:
		return stringSliceFromAny(v)
	}
}

func looksLikeScheduledTask(m map[string]any) bool {
	if _, ok := m["cron"]; ok {
		return true
	}
	if _, ok := m["cronExpression"]; ok {
		return true
	}
	if _, ok := m["schedule"]; ok {
		return true
	}
	if _, ok := m["prompt"]; ok {
		return true
	}
	return false
}

func scheduledTaskLooksSensitive(m map[string]any) bool {
	b, _ := json.Marshal(redactValue(m))
	lower := strings.ToLower(string(b))
	return containsAny(lower, []string{"websearch", "webfetch", "browser", "bash", "run_command", "write_file", "edit_file", "network", "filesystem", "mcp"})
}

func redactValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, val := range typed {
			if isSensitiveKey(key) {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = redactValue(val)
		}
		return out
	case []any:
		limit := len(typed)
		if limit > 20 {
			limit = 20
		}
		out := make([]any, 0, limit)
		for i := 0; i < limit; i++ {
			out = append(out, redactValue(typed[i]))
		}
		return out
	case string:
		if isSensitiveString(typed) {
			return "[REDACTED]"
		}
		if len(typed) > 256 {
			return typed[:256] + "..."
		}
		return typed
	default:
		return typed
	}
}

func isSensitiveString(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "sk-") ||
		strings.Contains(lower, "token=") ||
		strings.Contains(lower, "secret=") ||
		strings.Contains(lower, "password=") ||
		strings.Contains(lower, "authorization:")
}

func safeDisplayName(s string) string {
	if s == "" {
		return ""
	}
	if isSensitiveString(s) {
		return "[REDACTED]"
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func stableHash(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func containsAny(s string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func countNameMatches(dir string, terms []string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		lower := strings.ToLower(entry.Name())
		if containsAny(lower, terms) {
			count++
		}
	}
	return count
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
