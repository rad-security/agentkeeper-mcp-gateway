package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
)

// SourceKindClaudeCodePlugin is the source kind of an MCP server bundled with
// an installed Claude Code plugin.
const SourceKindClaudeCodePlugin = "claude_code_plugin_mcp"

// RouteabilityClaudeCodePlugin marks a server an installed Claude Code plugin
// provides. Claude Code starts it from the plugin, so rewriting the client
// config cannot move it behind the Gateway.
const RouteabilityClaudeCodePlugin = "claude_code_plugin_not_local_routable"

// Bounds for reading plugin files, which are customer-controlled.
const (
	maxPluginFileBytes      = 1 << 20
	maxPluginInstalls       = 200
	maxPluginServersPerFile = 100
)

// ClientConfigFile is one client config document configure-ide routes.
type ClientConfigFile struct {
	Client     string
	Path       string
	Scope      string
	SourceKind string
	// ClaudeJSON marks Claude Code's ~/.claude.json: its top-level servers are
	// user-scoped and every project under `projects` has servers of its own.
	ClaudeJSON bool
}

// ClientSourceKind returns the scope and source kind Discover reports for the
// one config file of a client that keeps its servers in a top-level
// `mcpServers` map. Claude Code, whose servers span several files, and Cowork
// are not such clients.
func ClientSourceKind(client string) (scope, sourceKind string, ok bool) {
	switch client {
	case ClientClaudeDesktop:
		return "global", "claude_desktop_config", true
	case ClientCursor:
		return "global", "cursor_mcp_json", true
	}
	for _, optional := range optionalClientConfigs {
		if optional.client == client {
			return "global", optional.sourceKind, true
		}
	}
	return "", "", false
}

// ProjectMCPFile is the project-scoped .mcp.json Claude Code reads in cwd.
func ProjectMCPFile(cwd string) ClientConfigFile {
	return ClientConfigFile{Client: ClientClaudeCode, Path: filepath.Join(cwd, ".mcp.json"), Scope: "project", SourceKind: "project_mcp_json"}
}

// ClaudeJSONFile is Claude Code's ~/.claude.json under home.
func ClaudeJSONFile(home string) ClientConfigFile {
	return ClientConfigFile{Client: ClientClaudeCode, Path: filepath.Join(home, ".claude.json"), Scope: "user", SourceKind: "claude_json_user", ClaudeJSON: true}
}

// ParseClientConfig returns every MCP server in data, the bytes of file, with
// the identity and classification Discover reports, including the AgentKeeper
// Gateway entries (RouteState routed). For ~/.claude.json it includes the
// servers of every project under `projects`, each carrying its project key.
// Unlike Discover, a document that is not JSON, or a server map that does not
// parse, is an error, so a caller can tell a malformed file from an empty one.
func ParseClientConfig(file ClientConfigFile, data []byte) ([]DiscoveredServer, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file.Path, err)
	}
	coverage := loadedGatewayCoverage()
	var out []DiscoveredServer
	if !file.ClaudeJSON {
		servers, err := parseServerMap(doc["mcpServers"], file.Path, file.Client, file.Scope, file.SourceKind, coverage)
		if err != nil {
			return nil, err
		}
		return sortParsed(servers), nil
	}
	user, err := parseServerMap(doc["mcpServers"], file.Path, ClientClaudeCode, "user", "claude_json_user", coverage)
	if err != nil {
		return nil, err
	}
	out = append(out, user...)
	if raw := doc["projects"]; len(raw) > 0 && string(raw) != "null" {
		var projects map[string]map[string]json.RawMessage
		if err := json.Unmarshal(raw, &projects); err != nil {
			return nil, fmt.Errorf("parsing projects in %s: %w", file.Path, err)
		}
		for project, settings := range projects {
			servers, err := parseServerMap(settings["mcpServers"], file.Path, ClientClaudeCode, "local", "claude_json_project", coverage)
			if err != nil {
				return nil, fmt.Errorf("project %s: %w", project, err)
			}
			for i := range servers {
				servers[i].Project = project
			}
			out = append(out, servers...)
		}
	}
	return sortParsed(out), nil
}

func parseServerMap(raw json.RawMessage, path, client, scope, sourceKind string, coverage func(config.ServerEntry) (bool, string)) ([]DiscoveredServer, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var servers map[string]config.ServerEntry
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil, fmt.Errorf("parsing mcpServers in %s: %w", path, err)
	}
	return readServersRawWith(raw, path, client, scope, sourceKind, RouteabilityLocalRoutable, coverage), nil
}

func sortParsed(servers []DiscoveredServer) []DiscoveredServer {
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Project != servers[j].Project {
			return servers[i].Project < servers[j].Project
		}
		return servers[i].Name < servers[j].Name
	})
	return servers
}

// loadedGatewayCoverage loads the Gateway config once for a batch of
// coverage lookups.
func loadedGatewayCoverage() func(config.ServerEntry) (bool, string) {
	cfg, err := config.Load()
	return func(entry config.ServerEntry) (bool, string) {
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
}

// GatewayCoverage reports whether the Gateway config already serves a server
// with exactly this client entry, and under which name.
func GatewayCoverage(entry config.ServerEntry) (bool, string) {
	return gatewayCoverage(entry)
}

// AddServerToGatewayConfig adds a migrated client server to the Gateway
// config the way configure-ide does: an identical entry is reused, and a
// different server already holding the name gets a name derived from
// sourceKey. It returns the name the Gateway serves it under.
func AddServerToGatewayConfig(entry config.ServerEntry, sourceKey string) (string, error) {
	return addServerWithoutClobber(entry, sourceKey)
}

// InsideGitWorktree reports whether path sits inside a git worktree, where
// configure-ide does not rewrite a project file it was not explicitly given.
func InsideGitWorktree(path string) bool {
	return insideGitWorktree(path)
}

// NormalizeTransport returns the Gateway transport for a client entry.
func NormalizeTransport(entry config.ServerEntry) string {
	return normalizeTransport(entry)
}

// ClaudeCodePluginServers returns the MCP servers bundled with the Claude Code
// plugins installed under home, and every file it looked at, so a caller can
// tell when to look again. Only installs listed in installed_plugins.json
// count: marketplace checkouts also hold the .mcp.json of plugins nobody
// installed. A plugin the user settings switch off is skipped. A plugin keeps
// its servers in .mcp.json at its root, as a `mcpServers` map or as the
// document itself, or under `mcpServers` in .claude-plugin/plugin.json, inline
// or as paths relative to the plugin root.
func ClaudeCodePluginServers(home string) ([]DiscoveredServer, []string) {
	manifestPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	files := []string{manifestPath, settingsPath}
	data, err := readBoundedFile(manifestPath)
	if err != nil {
		return nil, files
	}
	var manifest struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return nil, files
	}
	disabled := disabledClaudeCodePlugins(settingsPath)
	ids := make([]string, 0, len(manifest.Plugins))
	for id := range manifest.Plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []DiscoveredServer
	seenInstalls := map[string]bool{}
	seenServers := map[string]bool{}
	add := func(path string, servers map[string]json.RawMessage) {
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > maxPluginServersPerFile {
			names = names[:maxPluginServersPerFile]
		}
		for _, name := range names {
			var entry config.ServerEntry
			if name == "" || json.Unmarshal(servers[name], &entry) != nil || (strings.TrimSpace(entry.Command) == "" && strings.TrimSpace(entry.URL) == "") {
				continue
			}
			key := filepath.Clean(path) + "\x00" + name
			if seenServers[key] {
				continue
			}
			seenServers[key] = true
			entry.Name = name
			out = append(out, DiscoveredServer{
				Name:         name,
				Client:       ClientClaudeCode,
				Scope:        "plugin",
				SourceKind:   SourceKindClaudeCodePlugin,
				SourcePath:   path,
				SourceHash:   sourceHash(path),
				Transport:    normalizeTransport(entry),
				Command:      entry.Command,
				URL:          entry.URL,
				ArgsCount:    len(entry.Args),
				EnvKeys:      sortedKeys(entry.Env),
				HeaderKeys:   sortedKeys(entry.Headers),
				RouteState:   RouteDirect,
				Routeability: RouteabilityClaudeCodePlugin,
				Routable:     false,
				Entry:        entry,
			})
		}
	}
	installs := 0
	for _, id := range ids {
		if disabled[id] {
			continue
		}
		for _, install := range manifest.Plugins[id] {
			root := filepath.Clean(install.InstallPath)
			if !filepath.IsAbs(install.InstallPath) || seenInstalls[root] {
				continue
			}
			if installs++; installs > maxPluginInstalls {
				return out, files
			}
			seenInstalls[root] = true
			mcpPath := filepath.Join(root, ".mcp.json")
			files = append(files, mcpPath)
			if data, err := readBoundedFile(mcpPath); err == nil {
				add(mcpPath, pluginServerMap(data))
			}
			pluginPath := filepath.Join(root, ".claude-plugin", "plugin.json")
			files = append(files, pluginPath)
			data, err := readBoundedFile(pluginPath)
			if err != nil {
				continue
			}
			var plugin struct {
				MCPServers json.RawMessage `json:"mcpServers"`
			}
			if json.Unmarshal(data, &plugin) != nil || len(plugin.MCPServers) == 0 {
				continue
			}
			var inline map[string]json.RawMessage
			if json.Unmarshal(plugin.MCPServers, &inline) == nil {
				add(pluginPath, inline)
				continue
			}
			var references []string
			var single string
			if json.Unmarshal(plugin.MCPServers, &single) == nil {
				references = []string{single}
			} else if json.Unmarshal(plugin.MCPServers, &references) != nil {
				continue
			}
			for _, reference := range references {
				path, ok := pluginRelativePath(root, reference)
				if !ok || path == mcpPath {
					continue
				}
				files = append(files, path)
				if data, err := readBoundedFile(path); err == nil {
					add(path, pluginServerMap(data))
				}
			}
		}
	}
	return out, files
}

// pluginServerMap reads a plugin MCP document: a `mcpServers` map, or the
// servers at the top level of the document.
func pluginServerMap(data []byte) map[string]json.RawMessage {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	if raw, wrapped := doc["mcpServers"]; wrapped {
		var servers map[string]json.RawMessage
		if json.Unmarshal(raw, &servers) != nil {
			return nil
		}
		return servers
	}
	return doc
}

// pluginRelativePath resolves a path a plugin manifest gives relative to its
// root, refusing one that leaves the plugin.
func pluginRelativePath(root, reference string) (string, bool) {
	reference = strings.TrimSpace(reference)
	if rest, ok := strings.CutPrefix(reference, "${CLAUDE_PLUGIN_ROOT}"); ok {
		reference = strings.TrimLeft(rest, `/\`)
	}
	if reference == "" || filepath.IsAbs(reference) {
		return "", false
	}
	path := filepath.Join(root, filepath.FromSlash(reference))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return path, true
}

func disabledClaudeCodePlugins(settingsPath string) map[string]bool {
	disabled := map[string]bool{}
	data, err := readBoundedFile(settingsPath)
	if err != nil {
		return disabled
	}
	var settings struct {
		EnabledPlugins map[string]json.RawMessage `json:"enabledPlugins"`
	}
	if json.Unmarshal(data, &settings) != nil {
		return disabled
	}
	for id, raw := range settings.EnabledPlugins {
		var enabled bool
		if json.Unmarshal(raw, &enabled) == nil && !enabled {
			disabled[id] = true
		}
	}
	return disabled
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPluginFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPluginFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxPluginFileBytes)
	}
	return data, nil
}
