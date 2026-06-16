// Package discovery finds MCP servers configured in local AI clients without
// relying on AgentKeeper runtime hooks.
package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/configbackup"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
)

const (
	ClientClaudeCode    = "claude-code"
	ClientClaudeDesktop = "claude-desktop"
	ClientCowork        = "cowork"
	ClientCursor        = "cursor"

	RouteDirect  = "direct"
	RouteRouted  = "routed"
	RouteUnknown = "unknown"

	RouteabilityLocalRoutable         = "local_routable"
	RouteabilityCoworkLocalDesktop    = "cowork_local_desktop_config_routable"
	RouteabilityCoworkLocalPlugin     = "cowork_local_plugin_mcp_routable"
	RouteabilityCoworkRemoteMCP       = "cowork_remote_mcp_routable"
	RouteabilityRemoteNotLocal        = "cowork_remote_connector_not_local_routable"
	RouteabilityUnknownRequiresReview = "cowork_unknown_requires_review"
)

// Options controls local discovery.
type Options struct {
	Home   string
	CWD    string
	Client string
}

// Result is the JSON-safe output from discovery commands.
type Result struct {
	Home    string             `json:"home,omitempty"`
	CWD     string             `json:"cwd,omitempty"`
	Servers []DiscoveredServer `json:"servers"`
}

// DiscoveredServer is a redacted view of an MCP server found on disk. Secret
// values are deliberately omitted; Entry carries the full local config for
// in-process migration and is never serialized.
type DiscoveredServer struct {
	Name           string   `json:"name"`
	Client         string   `json:"client"`
	Scope          string   `json:"scope"`
	SourceKind     string   `json:"source_kind"`
	SourcePath     string   `json:"source_path,omitempty"`
	SourceHash     string   `json:"source_hash,omitempty"`
	Transport      string   `json:"transport"`
	Command        string   `json:"command,omitempty"`
	URL            string   `json:"url,omitempty"`
	ArgsCount      int      `json:"args_count,omitempty"`
	EnvKeys        []string `json:"env_keys,omitempty"`
	HeaderKeys     []string `json:"header_keys,omitempty"`
	RemoteID       string   `json:"remote_id,omitempty"`
	RouteState     string   `json:"route_state"`
	Routeability   string   `json:"routeability"`
	Routable       bool     `json:"routable"`
	GatewayCovered bool     `json:"gateway_covered,omitempty"`
	GatewayName    string   `json:"gateway_name,omitempty"`

	Entry config.ServerEntry `json:"-"`
}

// Discover returns MCP servers configured for the requested client. Client may
// be "all", "claude-code", "claude-desktop", "cowork", or "cursor".
func Discover(opts Options) (Result, error) {
	home := opts.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Result{}, err
		}
	}
	cwd := opts.CWD
	if cwd != "" {
		abs, err := filepath.Abs(expandHome(cwd, home))
		if err == nil {
			cwd = abs
		}
	}
	client := strings.ToLower(strings.TrimSpace(opts.Client))
	if client == "" || client == "all" {
		client = "all"
	}

	res := Result{Home: home, CWD: cwd}
	var servers []DiscoveredServer
	add := func(s []DiscoveredServer) { servers = append(servers, s...) }

	switch client {
	case "all":
		add(discoverClaudeCode(home, cwd))
		add(discoverClaudeDesktop(home))
		add(discoverCowork(home))
		add(discoverCursor(home))
	case ClientClaudeCode:
		add(discoverClaudeCode(home, cwd))
	case ClientClaudeDesktop:
		add(discoverClaudeDesktop(home))
	case ClientCowork:
		add(discoverCowork(home))
	case ClientCursor:
		add(discoverCursor(home))
	default:
		return Result{}, fmt.Errorf("unknown client %q", opts.Client)
	}

	res.Servers = dedupeAndSort(servers)
	return res, nil
}

func discoverClaudeCode(home, cwd string) []DiscoveredServer {
	var out []DiscoveredServer
	if cwd != "" {
		out = append(out, readMCPServers(filepath.Join(cwd, ".mcp.json"), ClientClaudeCode, "project", "project_mcp_json", RouteabilityLocalRoutable)...)
		out = append(out, readClaudeJSONProject(home, cwd)...)
	}
	out = append(out, readMCPServers(filepath.Join(home, ".claude", "settings.json"), ClientClaudeCode, "global", "claude_code_settings", RouteabilityLocalRoutable)...)
	out = append(out, readClaudeJSONUser(home)...)
	return out
}

func discoverClaudeDesktop(home string) []DiscoveredServer {
	path := claudeDesktopConfigPath(home)
	if path == "" {
		return nil
	}
	return readMCPServers(path, ClientClaudeDesktop, "global", "claude_desktop_config", RouteabilityLocalRoutable)
}

func discoverCursor(home string) []DiscoveredServer {
	return readMCPServers(filepath.Join(home, ".cursor", "mcp.json"), ClientCursor, "global", "cursor_mcp_json", RouteabilityLocalRoutable)
}

func discoverCowork(home string) []DiscoveredServer {
	var out []DiscoveredServer
	if path := claudeDesktopConfigPath(home); path != "" {
		out = append(out, readMCPServers(path, ClientCowork, "global", "claude_desktop_config", RouteabilityCoworkLocalDesktop)...)
	}

	root := coworkAppSupportDir(home)
	if root == "" {
		return out
	}
	sessions := filepath.Join(root, "local-agent-mode-sessions")
	_ = filepath.WalkDir(sessions, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == "node_modules" || base == ".git" || base == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) == ".mcp.json" {
			out = append(out, readMCPServers(path, ClientCowork, "plugin", "cowork_plugin_mcp", RouteabilityCoworkLocalPlugin)...)
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), "local_") && strings.HasSuffix(path, ".json") {
			out = append(out, readCoworkRemoteMCPServers(path)...)
		}
		return nil
	})
	return out
}

func readCoworkRemoteMCPServers(path string) []DiscoveredServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		RemoteMCPServers []struct {
			UUID    string            `json:"uuid"`
			Name    string            `json:"name"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"remoteMcpServersConfig"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	out := make([]DiscoveredServer, 0, len(doc.RemoteMCPServers))
	for _, remote := range doc.RemoteMCPServers {
		if strings.TrimSpace(remote.URL) == "" {
			continue
		}
		name := remoteMCPServerName(remote.Name, remote.URL, remote.UUID)
		entry := config.ServerEntry{
			Name:      name,
			Transport: "http",
			URL:       remote.URL,
			Headers:   remote.Headers,
		}
		covered, gatewayName := gatewayCoverage(entry)
		out = append(out, DiscoveredServer{
			Name:           name,
			Client:         ClientCowork,
			Scope:          "remote",
			SourceKind:     "cowork_remote_mcp_config",
			SourcePath:     path,
			SourceHash:     shortHash(filepath.Clean(path) + "|" + remote.UUID),
			Transport:      "http",
			URL:            remote.URL,
			HeaderKeys:     sortedKeys(remote.Headers),
			RemoteID:       remote.UUID,
			RouteState:     RouteDirect,
			Routeability:   RouteabilityCoworkRemoteMCP,
			Routable:       true,
			GatewayCovered: covered,
			GatewayName:    gatewayName,
			Entry:          entry,
		})
	}
	return out
}

func readClaudeJSONUser(home string) []DiscoveredServer {
	path := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return readServersRaw(doc["mcpServers"], path, ClientClaudeCode, "user", "claude_json_user", RouteabilityLocalRoutable)
}

func readClaudeJSONProject(home, cwd string) []DiscoveredServer {
	path := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Projects map[string]map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if len(doc.Projects) == 0 {
		return nil
	}
	matches := projectKeysForCWD(doc.Projects, cwd)
	var out []DiscoveredServer
	for _, key := range matches {
		out = append(out, readServersRaw(doc.Projects[key]["mcpServers"], path, ClientClaudeCode, "local", "claude_json_project", RouteabilityLocalRoutable)...)
	}
	return out
}

func projectKeysForCWD(projects map[string]map[string]json.RawMessage, cwd string) []string {
	cleanCWD := filepath.Clean(cwd)
	var exact []string
	var contained []string
	for key := range projects {
		cleanKey := filepath.Clean(expandHome(key, ""))
		if cleanKey == cleanCWD {
			exact = append(exact, key)
			continue
		}
		if strings.HasPrefix(cleanCWD, cleanKey+string(os.PathSeparator)) || strings.HasPrefix(cleanKey, cleanCWD+string(os.PathSeparator)) {
			contained = append(contained, key)
		}
	}
	if len(exact) > 0 {
		sort.Strings(exact)
		return exact
	}
	sort.Strings(contained)
	return contained
}

func readMCPServers(path, client, scope, sourceKind, routeability string) []DiscoveredServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return readServersRaw(doc["mcpServers"], path, client, scope, sourceKind, routeability)
}

func readServersRaw(raw json.RawMessage, path, client, scope, sourceKind, routeability string) []DiscoveredServer {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var servers map[string]config.ServerEntry
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil
	}
	out := make([]DiscoveredServer, 0, len(servers))
	for name, entry := range servers {
		if name == "" {
			continue
		}
		entry.Name = name
		transport := normalizeTransport(entry)
		routeState := RouteDirect
		entryRouteability := routeability
		routable := true
		if isGatewayEntry(entry) {
			routeState = RouteRouted
			entryRouteability = RouteabilityLocalRoutable
			routable = false
		} else {
			entryRouteability, routable = routeabilityForEntry(entry, entryRouteability)
		}
		covered, gatewayName := false, ""
		if routeState != RouteRouted {
			covered, gatewayName = gatewayCoverage(entry)
		}
		out = append(out, DiscoveredServer{
			Name:           name,
			Client:         client,
			Scope:          scope,
			SourceKind:     sourceKind,
			SourcePath:     path,
			SourceHash:     sourceHash(path),
			Transport:      transport,
			Command:        entry.Command,
			URL:            entry.URL,
			ArgsCount:      len(entry.Args),
			EnvKeys:        sortedKeys(entry.Env),
			HeaderKeys:     sortedKeys(entry.Headers),
			RouteState:     routeState,
			Routeability:   entryRouteability,
			Routable:       routable,
			GatewayCovered: covered,
			GatewayName:    gatewayName,
			Entry:          entry,
		})
	}
	return out
}

// MigrateProjectMCP migrates direct servers from cwd/.mcp.json into the gateway
// config and rewrites that project file so Claude Code launches the gateway.
func MigrateProjectMCP(cwd string, dryRun bool) (MigrationPlan, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return MigrationPlan{}, err
	}
	if cwd == "" {
		return MigrationPlan{}, errors.New("--cwd is required for project MCP migration")
	}
	abs, err := filepath.Abs(expandHome(cwd, home))
	if err != nil {
		return MigrationPlan{}, err
	}
	path := filepath.Join(abs, ".mcp.json")
	return MigrateMCPFile(path, ClientClaudeCode, "project", "project_mcp_json", RouteabilityLocalRoutable, dryRun)
}

// MigrateClaudeJSONUser migrates Claude Code user-scoped MCP servers from
// ~/.claude.json into the gateway config and rewrites that user config so
// Claude Code launches the gateway instead of calling those servers directly.
func MigrateClaudeJSONUser(dryRun bool) (MigrationPlan, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return MigrationPlan{}, err
	}
	path := filepath.Join(home, ".claude.json")
	return MigrateMCPFile(path, ClientClaudeCode, "user", "claude_json_user", RouteabilityLocalRoutable, dryRun)
}

// MigrateClaudeJSONProjects migrates every project-scoped MCP server nested
// under ~/.claude.json projects into the gateway config. This closes the gap
// where enterprise setup discovered project entries only when run from that
// exact project directory.
func MigrateClaudeJSONProjects(dryRun bool) (MigrationPlan, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return MigrationPlan{}, err
	}
	path := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return MigrationPlan{Client: ClientClaudeCode, Scope: "projects", ConfigPath: path}, nil
		}
		return MigrationPlan{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return MigrationPlan{}, err
	}
	var projects map[string]map[string]json.RawMessage
	if len(raw["projects"]) > 0 && string(raw["projects"]) != "null" {
		if err := json.Unmarshal(raw["projects"], &projects); err != nil {
			return MigrationPlan{}, err
		}
	}

	plan := MigrationPlan{Client: ClientClaudeCode, Scope: "projects", ConfigPath: path}
	if len(projects) == 0 {
		return plan, nil
	}

	projectKeys := make([]string, 0, len(projects))
	for project := range projects {
		projectKeys = append(projectKeys, project)
	}
	sort.Strings(projectKeys)

	directByProject := map[string][]DiscoveredServer{}
	rewriteByProject := map[string]bool{}
	for _, project := range projectKeys {
		servers := readServersRaw(projects[project]["mcpServers"], path, ClientClaudeCode, "project", "claude_json_project", RouteabilityLocalRoutable)
		for i := range servers {
			servers[i].SourceHash = shortHash(filepath.Clean(path) + "|" + project + "|" + servers[i].Name)
		}
		plan.Servers = append(plan.Servers, servers...)
		for _, s := range servers {
			if isStaleGatewayEntry(s) {
				rewriteByProject[project] = true
				continue
			}
			if s.RouteState == RouteRouted || !s.Routable {
				continue
			}
			directByProject[project] = append(directByProject[project], s)
			rewriteByProject[project] = true
		}
	}
	if len(rewriteByProject) == 0 {
		plan.AlreadyRouted = allRouted(plan.Servers)
		return plan, nil
	}
	if dryRun {
		return plan, nil
	}

	backup, err := configbackup.Write(path, data)
	if err != nil {
		return plan, err
	}
	plan.BackupPath = backup

	for _, project := range projectKeys {
		if !rewriteByProject[project] {
			continue
		}
		direct := directByProject[project]
		for _, s := range direct {
			entry := s.Entry
			entry.Name = s.Name
			if entry.Transport == "" {
				entry.Transport = normalizeTransport(entry)
			}
			gatewayName, err := addServerWithoutClobber(entry, s.SourceHash)
			if err != nil {
				return plan, fmt.Errorf("adding %s to gateway config: %w", s.Name, err)
			}
			if gatewayName != s.Name {
				s.GatewayName = gatewayName
			}
			plan.Migrated = append(plan.Migrated, s)
		}
		encoded, err := json.Marshal(map[string]config.ServerEntry{
			"agentkeeper-mcp-gateway": gatewayServerEntry(),
		})
		if err != nil {
			return plan, err
		}
		projects[project]["mcpServers"] = encoded
	}

	encodedProjects, err := json.Marshal(projects)
	if err != nil {
		return plan, err
	}
	raw["projects"] = encodedProjects
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return plan, err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return plan, err
	}
	return plan, nil
}

// CoworkMigrationResult summarizes Cowork MCP source rewrites.
type CoworkMigrationResult struct {
	Plans             []MigrationPlan `json:"plans"`
	GatewayEntrypoint *MigrationPlan  `json:"gateway_entrypoint,omitempty"`
}

// MigrateCoworkMCP migrates every discovered Cowork local/plugin MCP source,
// or a specific source path when provided, into the gateway config.
func MigrateCoworkMCP(sourcePath string, dryRun bool) (CoworkMigrationResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return CoworkMigrationResult{}, err
	}
	return MigrateCoworkMCPForHome(home, sourcePath, dryRun)
}

func MigrateCoworkMCPForHome(home, sourcePath string, dryRun bool) (CoworkMigrationResult, error) {
	servers := discoverCowork(home)
	sourceFilter := ""
	var err error
	if strings.TrimSpace(sourcePath) != "" {
		sourceFilter, err = filepath.Abs(expandHome(sourcePath, home))
		if err != nil {
			return CoworkMigrationResult{}, err
		}
	}

	grouped := map[string][]DiscoveredServer{}
	for _, s := range servers {
		if s.SourcePath == "" || !s.Routable || s.RouteState == RouteRouted {
			continue
		}
		if sourceFilter != "" && filepath.Clean(s.SourcePath) != filepath.Clean(sourceFilter) {
			continue
		}
		grouped[s.SourcePath] = append(grouped[s.SourcePath], s)
	}
	paths := make([]string, 0, len(grouped))
	for path := range grouped {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	result := CoworkMigrationResult{Plans: make([]MigrationPlan, 0, len(paths))}
	migratedAny := false
	for _, path := range paths {
		servers := grouped[path]
		if len(servers) == 0 {
			continue
		}
		if servers[0].SourceKind == "cowork_remote_mcp_config" {
			plan, err := MigrateDiscoveredServers(servers, dryRun)
			if err != nil {
				return result, err
			}
			if len(plan.Migrated) > 0 || dryRunHasMigratable(plan) {
				migratedAny = true
			}
			result.Plans = append(result.Plans, plan)
			continue
		}
		plan, err := MigrateMCPFile(path, ClientCowork, servers[0].Scope, servers[0].SourceKind, servers[0].Routeability, dryRun)
		if err != nil {
			return result, err
		}
		if len(plan.Migrated) > 0 || dryRunHasMigratable(plan) {
			migratedAny = true
		}
		result.Plans = append(result.Plans, plan)
	}
	if migratedAny {
		plan, err := ensureCoworkGatewayEntrypoint(home, dryRun)
		if err != nil {
			return result, err
		}
		if plan.ConfigPath != "" {
			result.GatewayEntrypoint = &plan
		}
	}
	return result, nil
}

func dryRunHasMigratable(plan MigrationPlan) bool {
	for _, s := range plan.Servers {
		if s.RouteState != RouteRouted && s.Routable {
			return true
		}
	}
	return false
}

func ensureCoworkGatewayEntrypoint(home string, dryRun bool) (MigrationPlan, error) {
	path := claudeDesktopConfigPath(home)
	plan := MigrationPlan{
		Client:     ClientCowork,
		Scope:      "global",
		ConfigPath: path,
		Servers: []DiscoveredServer{{
			Name:         "agentkeeper-mcp-gateway",
			Client:       ClientCowork,
			Scope:        "global",
			SourceKind:   "claude_desktop_config",
			SourcePath:   path,
			Transport:    "stdio",
			Command:      gatewayentry.Command(),
			ArgsCount:    1,
			RouteState:   RouteRouted,
			Routeability: RouteabilityCoworkLocalDesktop,
			Routable:     false,
		}},
	}

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return plan, err
	}

	raw := map[string]json.RawMessage{}
	exists := err == nil
	if exists && len(data) > 0 {
		if err := json.Unmarshal(data, &raw); err != nil {
			return plan, err
		}
	}

	servers := map[string]config.ServerEntry{}
	if existing := raw["mcpServers"]; len(existing) > 0 && string(existing) != "null" {
		if err := json.Unmarshal(existing, &servers); err != nil {
			return plan, err
		}
	}
	for _, entry := range servers {
		if isGatewayEntry(entry) {
			plan.AlreadyRouted = true
			return plan, nil
		}
	}
	if dryRun {
		return plan, nil
	}

	if exists {
		backup, err := configbackup.Write(path, data)
		if err != nil {
			return plan, err
		}
		plan.BackupPath = backup
	}

	servers["agentkeeper-mcp-gateway"] = gatewayServerEntry()
	encoded, err := json.Marshal(servers)
	if err != nil {
		return plan, err
	}
	raw["mcpServers"] = encoded
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return plan, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return plan, err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return plan, err
	}
	return plan, nil
}

// MigrateDiscoveredServers imports discovered MCP backends that do not have a
// local mcpServers map to rewrite, such as Cowork's remoteMcpServersConfig
// entries. For Cowork remote MCP config files, it also removes the native direct
// entries after import so normal Cowork tool selection is forced through the
// gateway-backed MCP server.
func MigrateDiscoveredServers(servers []DiscoveredServer, dryRun bool) (MigrationPlan, error) {
	plan := MigrationPlan{}
	if len(servers) == 0 {
		return plan, nil
	}
	plan = MigrationPlan{
		Client:     servers[0].Client,
		Scope:      servers[0].Scope,
		ConfigPath: servers[0].SourcePath,
		Servers:    servers,
	}
	direct := make([]DiscoveredServer, 0, len(servers))
	for _, s := range servers {
		if s.RouteState == RouteRouted || !s.Routable {
			continue
		}
		direct = append(direct, s)
	}
	if len(direct) == 0 || dryRun {
		return plan, nil
	}
	for _, s := range direct {
		entry := s.Entry
		entry.Name = s.Name
		if entry.Transport == "" {
			entry.Transport = normalizeTransport(entry)
		}
		gatewayName, err := addServerWithoutClobber(entry, s.SourceHash)
		if err != nil {
			return plan, fmt.Errorf("adding %s to gateway config: %w", s.Name, err)
		}
		if gatewayName != s.Name {
			s.GatewayName = gatewayName
		}
		s.GatewayCovered = true
		plan.Migrated = append(plan.Migrated, s)
	}
	if servers[0].SourceKind == "cowork_remote_mcp_config" {
		backup, disabled, err := disableCoworkRemoteMCPEntries(plan.ConfigPath, direct)
		if err != nil {
			return plan, err
		}
		plan.BackupPath = backup
		plan.NativeDisabled = disabled
	}
	return plan, nil
}

func disableCoworkRemoteMCPEntries(path string, direct []DiscoveredServer) (string, []DiscoveredServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, err
	}
	remoteRaw := raw["remoteMcpServersConfig"]
	if len(remoteRaw) == 0 || string(remoteRaw) == "null" {
		return "", nil, nil
	}
	var remotes []map[string]json.RawMessage
	if err := json.Unmarshal(remoteRaw, &remotes); err != nil {
		return "", nil, err
	}

	byID := map[string]DiscoveredServer{}
	byNameURL := map[string]DiscoveredServer{}
	for _, s := range direct {
		if strings.TrimSpace(s.RemoteID) != "" {
			byID[s.RemoteID] = s
		}
		byNameURL[strings.ToLower(strings.TrimSpace(s.Name))+"\x00"+strings.TrimSpace(s.URL)] = s
	}

	removedIDs := map[string]bool{}
	disabled := []DiscoveredServer{}
	remaining := make([]map[string]json.RawMessage, 0, len(remotes))
	for _, remote := range remotes {
		uuid := remoteString(remote, "uuid")
		name := remoteMCPServerName(remoteString(remote, "name"), remoteString(remote, "url"), uuid)
		url := remoteString(remote, "url")
		match, ok := byID[uuid]
		if !ok {
			match, ok = byNameURL[strings.ToLower(strings.TrimSpace(name))+"\x00"+strings.TrimSpace(url)]
		}
		if !ok {
			remaining = append(remaining, remote)
			continue
		}
		if uuid != "" {
			removedIDs[uuid] = true
		}
		disabled = append(disabled, match)
	}
	if len(disabled) == 0 {
		return "", nil, nil
	}

	encodedRemotes, err := json.Marshal(remaining)
	if err != nil {
		return "", nil, err
	}
	raw["remoteMcpServersConfig"] = encodedRemotes
	if len(removedIDs) > 0 && len(raw["enabledMcpTools"]) > 0 && string(raw["enabledMcpTools"]) != "null" {
		var enabled map[string]json.RawMessage
		if err := json.Unmarshal(raw["enabledMcpTools"], &enabled); err == nil {
			for key := range enabled {
				for uuid := range removedIDs {
					if strings.HasPrefix(key, uuid+":") {
						delete(enabled, key)
					}
				}
			}
			if encodedEnabled, err := json.Marshal(enabled); err == nil {
				raw["enabledMcpTools"] = encodedEnabled
			}
		}
	}

	backup, err := configbackup.Write(path, data)
	if err != nil {
		return "", nil, err
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return "", nil, err
	}
	return backup, disabled, nil
}

func remoteString(remote map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(remote[key], &value)
	return value
}

// MigrateMCPFile migrates direct MCP servers from path into the gateway config
// and rewrites path so the local client launches the gateway. Unknown top-level
// keys in the source file are preserved.
func MigrateMCPFile(path, client, scope, sourceKind, routeability string, dryRun bool) (MigrationPlan, error) {
	servers := readMCPServers(path, client, scope, sourceKind, routeability)
	plan := MigrationPlan{Client: client, Scope: scope, ConfigPath: path, Servers: servers}
	if len(servers) == 0 {
		return plan, nil
	}
	direct := make([]DiscoveredServer, 0, len(servers))
	needsRewrite := false
	for _, s := range servers {
		if isStaleGatewayEntry(s) {
			needsRewrite = true
			continue
		}
		if s.RouteState == RouteRouted || !s.Routable {
			continue
		}
		direct = append(direct, s)
	}
	if len(direct) == 0 {
		if !needsRewrite {
			plan.AlreadyRouted = allRouted(servers)
			return plan, nil
		}
	}
	if dryRun {
		return plan, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return plan, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return plan, err
	}
	backup, err := configbackup.Write(path, data)
	if err != nil {
		return plan, err
	}
	plan.BackupPath = backup

	for _, s := range direct {
		entry := s.Entry
		entry.Name = s.Name
		if entry.Transport == "" {
			entry.Transport = normalizeTransport(entry)
		}
		gatewayName, err := addServerWithoutClobber(entry, s.SourceHash)
		if err != nil {
			return plan, fmt.Errorf("adding %s to gateway config: %w", s.Name, err)
		}
		if gatewayName != s.Name {
			s.GatewayName = gatewayName
		}
		plan.Migrated = append(plan.Migrated, s)
	}

	encoded, err := json.Marshal(map[string]config.ServerEntry{
		"agentkeeper-mcp-gateway": gatewayServerEntry(),
	})
	if err != nil {
		return plan, err
	}
	raw["mcpServers"] = encoded
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return plan, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return plan, err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return plan, err
	}
	return plan, nil
}

// MigrationPlan describes what configure-client/configure-ide changed or would
// change.
type MigrationPlan struct {
	Client         string             `json:"client"`
	Scope          string             `json:"scope"`
	ConfigPath     string             `json:"config_path"`
	BackupPath     string             `json:"backup_path,omitempty"`
	Servers        []DiscoveredServer `json:"servers"`
	Migrated       []DiscoveredServer `json:"migrated,omitempty"`
	NativeDisabled []DiscoveredServer `json:"native_disabled,omitempty"`
	AlreadyRouted  bool               `json:"already_routed,omitempty"`
}

func gatewayServerEntry() config.ServerEntry {
	return config.ServerEntry{
		Command: gatewayentry.Command(),
		Args:    []string{"server"},
	}
}

func addServerWithoutClobber(entry config.ServerEntry, sourceKey string) (string, error) {
	if entry.Name == "" {
		return "", errors.New("server name is required")
	}

	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	baseName := entry.Name
	for _, existing := range cfg.Servers {
		if existing.Name != baseName {
			continue
		}
		if sameServerEntry(existing, entry) {
			return existing.Name, nil
		}
		entry.Name = uniqueServerName(cfg.Servers, baseName, sourceKey)
		break
	}

	filtered := make([]config.ServerEntry, 0, len(cfg.Servers)+1)
	for _, existing := range cfg.Servers {
		if existing.Name != entry.Name {
			filtered = append(filtered, existing)
		}
	}
	filtered = append(filtered, entry)
	cfg.Servers = filtered
	if err := config.Save(cfg); err != nil {
		return "", err
	}
	return entry.Name, nil
}

func sameServerEntry(a, b config.ServerEntry) bool {
	a.Name = ""
	b.Name = ""
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

func gatewayCoverage(entry config.ServerEntry) (bool, string) {
	cfg, err := config.Load()
	if err != nil {
		return false, ""
	}
	for _, existing := range cfg.Servers {
		if sameServerEntry(existing, entry) {
			return true, existing.Name
		}
	}
	return false, ""
}

func remoteMCPServerName(name, url, uuid string) string {
	cleanName := strings.ToLower(sanitizeName(strings.ReplaceAll(strings.TrimSpace(name), " ", "-")))
	if cleanName != "" {
		return cleanName
	}
	if strings.TrimSpace(url) != "" {
		host := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
		host = strings.Split(host, "/")[0]
		if host != "" {
			return strings.ToLower(sanitizeName(host))
		}
	}
	if strings.TrimSpace(uuid) != "" {
		return "remote-" + shortHash(uuid)
	}
	return "remote-mcp"
}

func uniqueServerName(existing []config.ServerEntry, baseName, sourceKey string) string {
	suffix := shortHash(baseName + "|" + sourceKey)
	cleanName := sanitizeName(baseName)
	if cleanName == "" {
		cleanName = "mcp"
	}
	candidate := fmt.Sprintf("%s-%s", cleanName, suffix)
	if !serverNameExists(existing, candidate) {
		return candidate
	}
	for i := 2; ; i++ {
		next := fmt.Sprintf("%s-%s-%d", cleanName, suffix, i)
		if !serverNameExists(existing, next) {
			return next
		}
	}
}

func serverNameExists(existing []config.ServerEntry, name string) bool {
	for _, s := range existing {
		if s.Name == name {
			return true
		}
	}
	return false
}

func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func isGatewayEntry(entry config.ServerEntry) bool {
	return gatewayentry.IsCurrentGatewayCommand(entry.Command) && len(entry.Args) > 0 && entry.Args[0] == "server"
}

func isStaleGatewayEntry(server DiscoveredServer) bool {
	if server.RouteState == RouteRouted {
		return false
	}
	if server.Name != "agentkeeper-mcp-gateway" {
		return false
	}
	return gatewayentry.IsGatewayCommand(server.Entry.Command) && len(server.Entry.Args) > 0 && server.Entry.Args[0] == "server"
}

func normalizeTransport(entry config.ServerEntry) string {
	if entry.Transport != "" {
		switch entry.Transport {
		case "streamable-http", "sse":
			return "http"
		}
		return entry.Transport
	}
	if entry.URL != "" {
		return "http"
	}
	return "stdio"
}

func routeabilityForEntry(entry config.ServerEntry, defaultRouteability string) (string, bool) {
	if defaultRouteability == RouteabilityRemoteNotLocal {
		return defaultRouteability, false
	}
	switch normalizeTransport(entry) {
	case "http":
		if strings.TrimSpace(entry.URL) == "" {
			return RouteabilityUnknownRequiresReview, false
		}
		return defaultRouteability, true
	case "stdio", "local":
		if strings.TrimSpace(entry.Command) == "" {
			return RouteabilityUnknownRequiresReview, false
		}
		return defaultRouteability, true
	default:
		if strings.TrimSpace(entry.Command) == "" && strings.TrimSpace(entry.URL) == "" {
			return RouteabilityUnknownRequiresReview, false
		}
		return defaultRouteability, true
	}
}

func allRouted(servers []DiscoveredServer) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		if s.RouteState != RouteRouted {
			return false
		}
	}
	return true
}

func dedupeAndSort(in []DiscoveredServer) []DiscoveredServer {
	seen := map[string]bool{}
	out := make([]DiscoveredServer, 0, len(in))
	for _, s := range in {
		key := discoveryDedupeKey(s)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.SourceKind != b.SourceKind {
			return a.SourceKind < b.SourceKind
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Name < b.Name
	})
	return out
}

func discoveryDedupeKey(s DiscoveredServer) string {
	if s.SourceKind == "cowork_remote_mcp_config" {
		return strings.Join([]string{s.Client, s.Scope, s.SourceKind, s.Name, s.URL}, "\x00")
	}
	return strings.Join([]string{s.Client, s.Scope, s.SourceKind, s.SourcePath, s.Name}, "\x00")
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func expandHome(path, home string) string {
	if path == "~" {
		if home == "" {
			if h, err := os.UserHomeDir(); err == nil {
				return h
			}
		}
		return home
	}
	if strings.HasPrefix(path, "~/") {
		if home == "" {
			if h, err := os.UserHomeDir(); err == nil {
				home = h
			}
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}

func classifyCoworkSource(path, home string) (scope, sourceKind, routeability string) {
	cleanPath := filepath.Clean(path)
	if cleanPath == filepath.Clean(claudeDesktopConfigPath(home)) {
		return "global", "claude_desktop_config", RouteabilityCoworkLocalDesktop
	}
	root := filepath.Clean(filepath.Join(coworkAppSupportDir(home), "local-agent-mode-sessions"))
	if strings.HasPrefix(cleanPath, root+string(os.PathSeparator)) {
		return "plugin", "cowork_plugin_mcp", RouteabilityCoworkLocalPlugin
	}
	return "unknown", "cowork_mcp_json", RouteabilityUnknownRequiresReview
}

func sourceHash(path string) string {
	return shortHash(filepath.Clean(path))
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func claudeDesktopConfigPath(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

func coworkAppSupportDir(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	default:
		return filepath.Join(home, ".config", "Claude")
	}
}
