// Package manualrouting owns reversible, user-initiated IDE routing. It keeps
// exact pre-route client bytes and the Gateway config entries introduced by the
// route so `configure-ide --remove-routing` can undo only AgentKeeper-owned
// changes without reconstructing customer configuration by hand.
package manualrouting

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/configbackup"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
)

const (
	manifestVersion = 1
	ownershipID     = "agentkeeper.manual.v1"
	// The Cowork entrypoint is written into the Claude Desktop config.
	clientClaudeDesktop     = "claude-desktop"
	clientCowork            = "cowork"
	claudeDesktopConfigName = "claude_desktop_config.json"
	// The manifest embeds each routed client's pre-route bytes, and a real
	// ~/.claude.json runs to megabytes. The cap only bounds a corrupt file.
	maxManifestBytes = 64 << 20
)

type ConfigureOptions struct {
	Adapters []*ideconfig.Adapter
	DryRun   bool
}

type RemoveOptions struct {
	// Adapters are the supported clients checked for an unowned Gateway route
	// when no ownership manifest exists.
	Adapters []*ideconfig.Adapter
	// Clients names the routes to restore, including ones no adapter covers
	// (Cowork sources). Empty selects the Adapters' clients.
	Clients []string
	DryRun  bool
}

// KindCoworkRemote marks Cowork's session state file, whose native remote MCP
// entries are disabled rather than replaced by a Gateway entry.
const KindCoworkRemote = "cowork_remote"

// AdoptOptions describes a client file that AgentKeeper rewrote outside the
// adapter path: Claude Code project-scoped routes, project .mcp.json files and
// Cowork sources.
type AdoptOptions struct {
	Client         string
	Path           string
	Kind           string
	OriginalExists bool
	Original       []byte
	SourceHash     string
	RouteRevision  string
	// AddedGatewayServers were created in the Gateway config by this step.
	// ReferencedGatewayServers are all Gateway servers the route depends on.
	AddedGatewayServers      []string
	ReferencedGatewayServers []string
}

type Report struct {
	Result             string   `json:"result"`
	Changed            bool     `json:"changed"`
	Configured         []string `json:"configured,omitempty"`
	Removed            []string `json:"removed,omitempty"`
	ExactRestored      []string `json:"exact_restored,omitempty"`
	StructuralRestored []string `json:"structural_restored,omitempty"`
	// SkippedMissing lists routed files that no longer exist. Their routes
	// went with them, so their records are dropped without a restore.
	SkippedMissing  []string          `json:"skipped_missing,omitempty"`
	MigratedServers []string          `json:"migrated_servers,omitempty"`
	ManifestPath    string            `json:"manifest_path"`
	Errors          map[string]string `json:"errors,omitempty"`
	Plans           []ideconfig.Plan  `json:"-"`
}

type manifest struct {
	Version         int                       `json:"version"`
	OwnershipID     string                    `json:"ownership_id"`
	Clients         []clientState             `json:"clients"`
	MigratedServers map[string]migratedServer `json:"migrated_servers"`
}

type clientState struct {
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	OriginalExists  bool     `json:"original_exists"`
	OriginalBytes   []byte   `json:"original_bytes,omitempty"`
	OriginalMode    uint32   `json:"original_mode,omitempty"`
	RoutedHash      string   `json:"routed_hash"`
	SourceHash      string   `json:"source_hash"`
	RouteRevision   string   `json:"route_revision"`
	MigratedServers []string `json:"migrated_servers,omitempty"`
	// Kind selects the restore strategy; empty is an mcpServers document.
	Kind string `json:"kind,omitempty"`
	// GatewayServers are Gateway config entries this route depends on whose
	// names can differ from the client's own server names.
	GatewayServers []string `json:"gateway_servers,omitempty"`
}

type migratedServer struct {
	Installed      config.ServerEntry  `json:"installed"`
	PreviousExists bool                `json:"previous_exists"`
	Previous       *config.ServerEntry `json:"previous,omitempty"`
}

type fileState struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

type preparedClient struct {
	adapter *ideconfig.Adapter
	plan    ideconfig.Plan
	state   clientState
}

type restoreAction struct {
	state      clientState
	current    fileState
	removeFile bool
	missing    bool
	updated    []byte
	mode       os.FileMode
	exact      bool
}

func Configure(opts ConfigureOptions) (Report, error) {
	manifestPath, err := ManifestPath()
	if err != nil {
		return Report{}, err
	}
	report := Report{Result: "configured", ManifestPath: manifestPath, Errors: map[string]string{}}
	state := manifest{
		Version: manifestVersion, OwnershipID: ownershipID,
		Clients: []clientState{}, MigratedServers: map[string]migratedServer{},
	}
	if existing, readErr := readManifest(manifestPath); readErr == nil {
		state = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return report, fmt.Errorf("read manual routing manifest: %w", readErr)
	}
	if state.Version != manifestVersion || state.OwnershipID != ownershipID {
		return report, fmt.Errorf("manual routing manifest version is incompatible")
	}
	if state.MigratedServers == nil {
		state.MigratedServers = map[string]migratedServer{}
	}

	var prepared []preparedClient
	for _, adapter := range opts.Adapters {
		plan, planErr := adapter.Plan()
		if planErr != nil {
			report.Errors[adapter.Name] = planErr.Error()
			continue
		}
		report.Plans = append(report.Plans, plan)
		if _, ok := findClient(state.Clients, plan.ConfigPath); ok && plan.AlreadyWired {
			report.Configured = append(report.Configured, adapter.Name)
			continue
		}

		original, stateErr := snapshotFile(plan.ConfigPath)
		if stateErr != nil {
			return report, stateErr
		}
		client := clientState{
			Name: adapter.Name, Path: plan.ConfigPath, OriginalExists: original.exists,
			OriginalBytes: original.data, OriginalMode: uint32(original.mode.Perm()),
			SourceHash: plan.SourceHash, RouteRevision: plan.RouteRevision,
		}
		if previous, ok := findClient(state.Clients, plan.ConfigPath); ok {
			// A file has one record. The Cowork entrypoint may have recorded
			// this path first; the adapter that routes the file takes it over.
			client = previous
			client.Name = adapter.Name
			client.OriginalMode = uint32(original.mode.Perm())
			baseline, baselineErr := directBaseline(original.data, previous.OriginalBytes, plan.Migrated)
			if baselineErr != nil {
				return report, fmt.Errorf("prepare updated rollback baseline for %s: %w", adapter.Name, baselineErr)
			}
			client.OriginalBytes = baseline
			// A file routing itself created stays removable until the customer
			// has put something of their own in it.
			client.OriginalExists = previous.OriginalExists || holdsCustomerContent(baseline)
		} else if plan.HasGateway {
			baseline, baselineErr := directBaseline(original.data, nil, plan.Migrated)
			if baselineErr != nil {
				return report, fmt.Errorf("prepare adopted rollback baseline for %s: %w", adapter.Name, baselineErr)
			}
			client.OriginalBytes = baseline
		}
		for _, server := range plan.Migrated {
			client.MigratedServers = appendUnique(client.MigratedServers, server.Name)
		}
		sort.Strings(client.MigratedServers)
		prepared = append(prepared, preparedClient{adapter: adapter, plan: plan, state: client})
		report.Configured = append(report.Configured, adapter.Name)
	}
	if opts.DryRun {
		previewNames := map[string]bool{}
		for _, item := range prepared {
			for _, server := range item.plan.Migrated {
				previewNames[server.Name] = true
			}
		}
		for name := range previewNames {
			report.MigratedServers = append(report.MigratedServers, name)
		}
		sort.Strings(report.MigratedServers)
		return report, nil
	}
	if len(prepared) == 0 {
		if len(report.Errors) > 0 {
			report.Result = "partial"
		} else {
			report.Result = "already_configured"
		}
		return report, nil
	}

	gatewayBefore, err := snapshotFile(config.SavePath())
	if err != nil {
		return report, err
	}
	gatewayConfig, err := config.Load()
	if err != nil {
		return report, fmt.Errorf("load gateway config for manual routing: %w", err)
	}
	originalGatewayConfig := gatewayConfig

	for index := range prepared {
		for _, server := range prepared[index].plan.Migrated {
			installed := toGatewayServer(server)
			if _, ok := state.MigratedServers[server.Name]; ok {
				continue
			}
			previous, previousExists := findGatewayServer(gatewayConfig.Servers, server.Name)
			owned := migratedServer{Installed: installed, PreviousExists: previousExists}
			if previousExists {
				previousCopy := previous
				owned.Previous = &previousCopy
			}
			state.MigratedServers[server.Name] = owned
			gatewayConfig.Servers = replaceGatewayServer(gatewayConfig.Servers, installed)
		}
	}

	var applied []fileState
	for index := range prepared {
		before, stateErr := snapshotFile(prepared[index].plan.ConfigPath)
		if stateErr != nil {
			return report, stateErr
		}
		if err := prepared[index].adapter.ApplyManaged(&prepared[index].plan); err != nil {
			_ = restoreFileStates(applied)
			return report, fmt.Errorf("apply manual routing for %s: %w", prepared[index].adapter.Name, err)
		}
		routed, stateErr := snapshotFile(prepared[index].plan.ConfigPath)
		if stateErr != nil {
			_ = restoreFileStates(applied)
			return report, stateErr
		}
		prepared[index].state.RoutedHash = gatewayentry.ContentHash(routed.data)
		prepared[index].state.SourceHash = prepared[index].plan.SourceHash
		prepared[index].state.RouteRevision = prepared[index].plan.RouteRevision
		state.Clients = replaceClient(state.Clients, prepared[index].state)
		for planIndex := range report.Plans {
			if report.Plans[planIndex].ConfigPath == prepared[index].plan.ConfigPath {
				report.Plans[planIndex] = prepared[index].plan
			}
		}
		applied = append(applied, before)
		report.Changed = true
	}

	if !reflect.DeepEqual(originalGatewayConfig, gatewayConfig) {
		if err := config.Save(gatewayConfig); err != nil {
			_ = restoreFileStates(applied)
			return report, fmt.Errorf("save gateway config for manual routing: %w", err)
		}
		report.Changed = true
	}
	if _, err := writeManifest(manifestPath, state); err != nil {
		_ = restoreFileState(gatewayBefore)
		_ = restoreFileStates(applied)
		return report, fmt.Errorf("write manual routing manifest: %w", err)
	}
	report.MigratedServers = sortedMigratedNames(state.MigratedServers)
	if len(report.Errors) > 0 {
		report.Result = "partial"
	}
	return report, nil
}

func Remove(opts RemoveOptions) (Report, error) {
	manifestPath, err := ManifestPath()
	if err != nil {
		return Report{}, err
	}
	report := Report{Result: "removed", ManifestPath: manifestPath}
	state, err := readManifest(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		for _, adapter := range opts.Adapters {
			plan, planErr := adapter.Plan()
			if planErr != nil {
				return report, planErr
			}
			if plan.HasGateway {
				return report, fmt.Errorf("%s is gateway-routed but the AgentKeeper manual ownership manifest is missing; refusing an inferred rollback", adapter.Name)
			}
		}
		report.Result = "not_configured"
		return report, nil
	}
	if err != nil {
		return report, fmt.Errorf("read manual routing manifest: %w", err)
	}
	if state.Version != manifestVersion || state.OwnershipID != ownershipID {
		return report, fmt.Errorf("manual routing manifest version is incompatible")
	}

	wanted := map[string]bool{}
	for _, name := range opts.Clients {
		wanted[strings.ToLower(strings.TrimSpace(name))] = true
	}
	if len(opts.Clients) == 0 {
		for _, adapter := range opts.Adapters {
			wanted[adapter.Name] = true
		}
	}
	var selected, remaining []clientState
	for _, client := range state.Clients {
		if wanted[client.Name] {
			selected = append(selected, client)
		} else {
			remaining = append(remaining, client)
		}
	}
	if len(selected) == 0 {
		report.Result = "not_configured"
		return report, nil
	}

	actions := make([]restoreAction, 0, len(selected))
	for _, client := range selected {
		action, actionErr := prepareRestore(client)
		if actionErr != nil {
			return report, fmt.Errorf("prepare rollback for %s: %w", client.Name, actionErr)
		}
		if action.missing {
			// The file may be gone for good (a Cowork session) or only absent
			// (a renamed or unmounted project). Its record and its Gateway
			// servers are kept so it can still be restored if it comes back.
			report.SkippedMissing = append(report.SkippedMissing, client.Path)
			remaining = append(remaining, client)
			continue
		}
		actions = append(actions, action)
		report.Removed = append(report.Removed, client.Name)
		if action.exact {
			report.ExactRestored = append(report.ExactRestored, client.Name)
		} else {
			report.StructuralRestored = append(report.StructuralRestored, client.Name)
		}
	}
	if len(actions) == 0 {
		report.Result = "skipped_missing"
		return report, nil
	}

	gatewayBefore, err := snapshotFile(config.SavePath())
	if err != nil {
		return report, err
	}
	gatewayConfig, err := config.Load()
	if err != nil {
		return report, fmt.Errorf("load gateway config for manual rollback: %w", err)
	}
	originalGatewayConfig := gatewayConfig
	stillOwned := referencedServers(remaining)
	for name, owned := range state.MigratedServers {
		if stillOwned[name] {
			continue
		}
		current, exists := findGatewayServer(gatewayConfig.Servers, name)
		if !exists {
			// Already removed by hand: nothing left to clean up.
			delete(state.MigratedServers, name)
			continue
		}
		if !reflect.DeepEqual(current, owned.Installed) {
			return report, fmt.Errorf("gateway server %s drifted after route configuration; refusing destructive cleanup", name)
		}
		if owned.PreviousExists && owned.Previous != nil {
			gatewayConfig.Servers = replaceGatewayServer(gatewayConfig.Servers, *owned.Previous)
		} else {
			gatewayConfig.Servers = removeGatewayServer(gatewayConfig.Servers, name)
		}
		delete(state.MigratedServers, name)
	}
	if opts.DryRun {
		return report, nil
	}

	var changedClients []fileState
	for _, action := range actions {
		latest, stateErr := snapshotFile(action.state.Path)
		if stateErr != nil {
			_ = restoreFileStates(changedClients)
			return report, stateErr
		}
		if latest.exists != action.current.exists || !bytes.Equal(latest.data, action.current.data) {
			_ = restoreFileStates(changedClients)
			return report, fmt.Errorf("configuration changed after rollback preview for %s; refusing to write", action.state.Path)
		}
		if action.current.exists {
			if _, backupErr := configbackup.Write(action.state.Path, action.current.data); backupErr != nil {
				_ = restoreFileStates(changedClients)
				return report, backupErr
			}
		}
		if action.removeFile {
			if err := os.Remove(action.state.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				_ = restoreFileStates(changedClients)
				return report, err
			}
		} else if err := writeAtomic(action.state.Path, action.updated, action.mode); err != nil {
			_ = restoreFileStates(changedClients)
			return report, err
		}
		changedClients = append(changedClients, action.current)
		report.Changed = true
	}
	if !reflect.DeepEqual(originalGatewayConfig, gatewayConfig) {
		if err := config.Save(gatewayConfig); err != nil {
			_ = restoreFileStates(changedClients)
			return report, err
		}
		report.Changed = true
	}
	state.Clients = remaining
	if len(remaining) == 0 {
		if err := os.Remove(manifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = restoreFileState(gatewayBefore)
			_ = restoreFileStates(changedClients)
			return report, err
		}
	} else if _, err := writeManifest(manifestPath, state); err != nil {
		_ = restoreFileState(gatewayBefore)
		_ = restoreFileStates(changedClients)
		return report, err
	}
	report.MigratedServers = sortedMigratedNames(state.MigratedServers)
	return report, nil
}

func ManifestPath() (string, error) {
	path := strings.TrimSpace(config.SavePath())
	if path == "" {
		return "", fmt.Errorf("gateway config path is unavailable")
	}
	return filepath.Join(filepath.Dir(path), config.ManualRoutingManifestName), nil
}

func prepareRestore(state clientState) (restoreAction, error) {
	current, err := snapshotFile(state.Path)
	if err != nil {
		return restoreAction{}, err
	}
	action := restoreAction{state: state, current: current, mode: current.mode}
	if !current.exists {
		// Cowork session and plugin directories come and go. A routed file
		// that is gone has no route left to remove, and must not stop every
		// other client from rolling back.
		action.missing = true
		return action, nil
	}
	if gatewayentry.ContentHash(current.data) == state.RoutedHash {
		action.exact = true
		if state.OriginalExists {
			action.updated = append([]byte(nil), state.OriginalBytes...)
			action.mode = os.FileMode(state.OriginalMode)
		} else {
			action.removeFile = true
		}
		return action, nil
	}
	updated, err := unroutedDocument(state, current.data, true)
	if err != nil {
		return action, err
	}
	action.updated = updated
	return action, nil
}

// unroutedDocument returns a routed client file with AgentKeeper's route taken
// out and the servers the route migrated put back, keeping everything else as
// the file has it now.
//
// Rollback passes requireOwned: the Gateway entry must be one this record
// owns, or nothing is touched. Adopt reads the bytes AgentKeeper itself is
// about to replace or has just replaced, where any Gateway-shaped entry is a
// route and none of it is customer content.
func unroutedDocument(state clientState, routed []byte, requireOwned bool) ([]byte, error) {
	if state.Kind == KindCoworkRemote {
		return restoreCoworkRemoteEntries(routed, state)
	}
	root := map[string]json.RawMessage{}
	if len(routed) > 0 {
		if err := json.Unmarshal(routed, &root); err != nil {
			return nil, fmt.Errorf("parse drifted client config: %w", err)
		}
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil, fmt.Errorf("parse drifted mcpServers: %w", err)
		}
	}
	if requireOwned {
		if raw, exists := servers[ideconfig.GatewayServerName]; exists {
			if !isOwnedGatewayEntry(raw, state) {
				return nil, fmt.Errorf("gateway entry no longer matches the AgentKeeper-owned route identity")
			}
			delete(servers, ideconfig.GatewayServerName)
		}
	} else if isGatewayRouteEntry(servers[ideconfig.GatewayServerName]) {
		// Only the entry under AgentKeeper's own name is a route. A Gateway
		// entry the customer wrote under another name is their server.
		delete(servers, ideconfig.GatewayServerName)
	}
	originalServers, err := serverMap(state.OriginalBytes)
	if err != nil {
		return nil, err
	}
	for _, name := range state.MigratedServers {
		if original, ok := originalServers[name]; ok {
			if _, exists := servers[name]; !exists {
				servers[name] = original
			}
		}
	}
	// A document that had no server map before routing does not gain an
	// empty one.
	_, had := root["mcpServers"]
	if len(servers) == 0 && len(state.OriginalBytes) > 0 && !hasTopLevelKey(state.OriginalBytes, "mcpServers") {
		delete(root, "mcpServers")
	} else if had || len(servers) > 0 {
		encoded, err := json.Marshal(servers)
		if err != nil {
			return nil, err
		}
		root["mcpServers"] = encoded
	}
	if err := restoreProjectScopedServers(root, state, requireOwned); err != nil {
		return nil, err
	}
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(updated, '\n'), nil
}

// isOwnedGatewayEntry accepts the route identity this manifest recorded, and
// also an identity AgentKeeper itself re-attested afterwards: project and
// Cowork migration rebind every Gateway entry in a file they rewrite, which
// the manifest written by an earlier release did not follow. A re-attested
// entry must still name this record's client (the Claude Desktop config is
// shared with the Cowork entrypoint). An entry whose identity was edited by
// hand matches neither and is refused.
func isOwnedGatewayEntry(raw json.RawMessage, state clientState) bool {
	var entry ideconfig.ServerEntry
	if json.Unmarshal(raw, &entry) != nil || len(entry.Args) != 1 || entry.Args[0] != "server" {
		return false
	}
	if !gatewayentry.IsGatewayCommand(entry.Command) {
		return false
	}
	client := entry.Env[gatewayentry.EnvClientName]
	if client == state.Name &&
		entry.Env[gatewayentry.EnvConfigSourceHash] == state.SourceHash &&
		entry.Env[gatewayentry.EnvRouteRevision] == state.RouteRevision {
		return true
	}
	sharesDesktopConfig := filepath.Base(state.Path) == claudeDesktopConfigName &&
		((state.Name == clientClaudeDesktop && client == clientCowork) ||
			(state.Name == clientCowork && client == clientClaudeDesktop))
	return (client == state.Name || sharesDesktopConfig) && gatewayentry.IsAttestedRoute(entry.Command, entry.Env)
}

// isGatewayRouteEntry recognises a Gateway entry by shape alone, for telling
// customer servers apart from routes when reading pre-route bytes.
func isGatewayRouteEntry(raw json.RawMessage) bool {
	var entry ideconfig.ServerEntry
	if json.Unmarshal(raw, &entry) != nil || len(entry.Args) != 1 || entry.Args[0] != "server" {
		return false
	}
	return gatewayentry.IsGatewayCommand(entry.Command)
}

// restoreProjectScopedServers undoes Claude Code project-scoped routes nested
// under `projects` in ~/.claude.json: each routed project loses its Gateway
// entry and regains the servers it had before routing. Projects and settings
// the client added later are left untouched.
func restoreProjectScopedServers(root map[string]json.RawMessage, state clientState, requireOwned bool) error {
	rawProjects := root["projects"]
	if len(rawProjects) == 0 || string(rawProjects) == "null" {
		return nil
	}
	var projects map[string]map[string]json.RawMessage
	if err := json.Unmarshal(rawProjects, &projects); err != nil {
		return nil // not the Claude Code project map; nothing to restore
	}
	originalProjects := projectServerMaps(state.OriginalBytes)
	changed := false
	for project, settings := range projects {
		servers := map[string]json.RawMessage{}
		if raw := settings["mcpServers"]; len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &servers); err != nil {
				continue
			}
		}
		routed := false
		if requireOwned {
			if raw, exists := servers[ideconfig.GatewayServerName]; exists {
				if !isOwnedGatewayEntry(raw, state) {
					return fmt.Errorf("gateway entry for project %s no longer matches the AgentKeeper-owned route identity", project)
				}
				delete(servers, ideconfig.GatewayServerName)
				routed = true
			}
		} else if isGatewayRouteEntry(servers[ideconfig.GatewayServerName]) {
			delete(servers, ideconfig.GatewayServerName)
			routed = true
		}
		if !routed {
			continue
		}
		for name, entry := range originalProjects[project] {
			if _, exists := servers[name]; exists || name == ideconfig.GatewayServerName {
				continue
			}
			servers[name] = entry
		}
		encoded, err := json.Marshal(servers)
		if err != nil {
			return err
		}
		settings["mcpServers"] = encoded
		projects[project] = settings
		changed = true
	}
	if !changed {
		return nil
	}
	encoded, err := json.Marshal(projects)
	if err != nil {
		return err
	}
	root["projects"] = encoded
	return nil
}

func coworkRemoteKey(remote map[string]json.RawMessage) string {
	var uuid, name, url string
	_ = json.Unmarshal(remote["uuid"], &uuid)
	if strings.TrimSpace(uuid) != "" {
		return uuid
	}
	_ = json.Unmarshal(remote["name"], &name)
	_ = json.Unmarshal(remote["url"], &url)
	return strings.ToLower(strings.TrimSpace(name)) + "|" + strings.TrimSpace(url)
}

func coworkRemoteEntries(data []byte) (map[string]json.RawMessage, []map[string]json.RawMessage, error) {
	root := map[string]json.RawMessage{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &root); err != nil {
			return nil, nil, err
		}
	}
	var remotes []map[string]json.RawMessage
	if raw := root["remoteMcpServersConfig"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &remotes); err != nil {
			return nil, nil, err
		}
	}
	return root, remotes, nil
}

// restoreCoworkRemoteEntries puts back the native remote MCP entries and tool
// selections that routing disabled, keeping everything Cowork wrote since.
func restoreCoworkRemoteEntries(current []byte, state clientState) ([]byte, error) {
	root, remotes, err := coworkRemoteEntries(current)
	if err != nil {
		return nil, fmt.Errorf("parse drifted Cowork state: %w", err)
	}
	originalRoot, originalRemotes, err := coworkRemoteEntries(state.OriginalBytes)
	if err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	for _, key := range state.MigratedServers {
		disabled[key] = true
	}
	present := map[string]bool{}
	for _, remote := range remotes {
		present[coworkRemoteKey(remote)] = true
	}
	restored := map[string]bool{}
	for _, remote := range originalRemotes {
		key := coworkRemoteKey(remote)
		if !disabled[key] || present[key] {
			continue
		}
		remotes = append(remotes, remote)
		restored[key] = true
	}
	encoded, err := json.Marshal(remotes)
	if err != nil {
		return nil, err
	}
	root["remoteMcpServersConfig"] = encoded

	originalEnabled := map[string]json.RawMessage{}
	if raw := originalRoot["enabledMcpTools"]; len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &originalEnabled)
	}
	// Cowork owns this file and may change the shape of its tool selections.
	// The remote entries are restored either way.
	enabled := map[string]json.RawMessage{}
	enabledReadable := true
	if raw := root["enabledMcpTools"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &enabled); err != nil {
			enabledReadable = false
		}
	}
	changedEnabled := false
	if !enabledReadable {
		originalEnabled = nil
	}
	for key, value := range originalEnabled {
		if _, exists := enabled[key]; exists {
			continue
		}
		for remoteKey := range restored {
			if strings.HasPrefix(key, remoteKey+":") {
				enabled[key] = value
				changedEnabled = true
			}
		}
	}
	if changedEnabled {
		encodedEnabled, err := json.Marshal(enabled)
		if err != nil {
			return nil, err
		}
		root["enabledMcpTools"] = encodedEnabled
	}
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(updated, '\n'), nil
}

// Adopt records a client file AgentKeeper rewrote outside the adapter path so
// `configure-ide --remove-routing` can undo it. A file has one record.
//
// The record's original is what the file would be without the route. When the
// file is routed again after the customer changed it (a server added to an
// already-routed file, settings added to a config routing created), that
// moves with it: restoring the bytes from before the first run would discard
// everything written since.
func Adopt(opts AdoptOptions) error {
	manifestPath, err := ManifestPath()
	if err != nil {
		return err
	}
	state := manifest{
		Version: manifestVersion, OwnershipID: ownershipID,
		Clients: []clientState{}, MigratedServers: map[string]migratedServer{},
	}
	if existing, readErr := readManifest(manifestPath); readErr == nil {
		state = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read manual routing manifest: %w", readErr)
	}
	if state.Version != manifestVersion || state.OwnershipID != ownershipID {
		return fmt.Errorf("manual routing manifest version is incompatible")
	}
	if state.MigratedServers == nil {
		state.MigratedServers = map[string]migratedServer{}
	}
	// The migration writes through a symlinked client file (a dotfiles
	// checkout), so the record names the file that was actually rewritten.
	// Only a link at the file itself is followed: resolving parent directories
	// would give the same file two spellings, and so two records.
	path := opts.Path
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
			path = resolved
		}
	}
	current, err := snapshotFile(path)
	if err != nil {
		return err
	}
	if !current.exists {
		return fmt.Errorf("routed configuration is missing: %s", path)
	}

	record, found := findClient(state.Clients, path)
	if !found {
		record = clientState{Name: opts.Client, Path: path, Kind: opts.Kind, OriginalMode: uint32(current.mode.Perm())}
	}
	if opts.OriginalExists {
		// The bytes this step replaced may already carry a route: one made by
		// a release that kept no record, or the route this record owns.
		baseline, baselineErr := unroutedDocument(record, opts.Original, false)
		switch {
		case baselineErr != nil:
			if !found {
				record.OriginalBytes = opts.Original
			}
		case !found && sameJSON(baseline, opts.Original):
			record.OriginalBytes = opts.Original // keep the customer's exact bytes
		case !found || !sameJSON(baseline, record.OriginalBytes):
			record.OriginalBytes = baseline
		}
		record.OriginalExists = record.OriginalExists || !found || record.Kind == KindCoworkRemote || holdsCustomerContent(record.OriginalBytes)
	}
	record.RoutedHash = gatewayentry.ContentHash(current.data)
	if opts.SourceHash != "" {
		record.SourceHash, record.RouteRevision = opts.SourceHash, opts.RouteRevision
	}
	removed, err := removedByRouting(record, current.data)
	if err != nil {
		return err
	}
	for _, name := range removed {
		record.MigratedServers = appendUnique(record.MigratedServers, name)
	}
	sort.Strings(record.MigratedServers)

	gatewayConfig, err := config.Load()
	if err != nil {
		return fmt.Errorf("load gateway config for route ownership: %w", err)
	}
	for _, name := range opts.AddedGatewayServers {
		if _, owned := state.MigratedServers[name]; owned {
			continue
		}
		if installed, ok := findGatewayServer(gatewayConfig.Servers, name); ok {
			state.MigratedServers[name] = migratedServer{Installed: installed}
		}
	}
	for _, name := range opts.ReferencedGatewayServers {
		if _, owned := state.MigratedServers[name]; owned {
			record.GatewayServers = appendUnique(record.GatewayServers, name)
		}
	}
	sort.Strings(record.GatewayServers)
	state.Clients = replaceClient(state.Clients, record)
	_, err = writeManifest(manifestPath, state)
	return err
}

// removedByRouting names what the route took out of the client file: server
// names for an mcpServers document, remote entry keys for Cowork state.
func removedByRouting(record clientState, current []byte) ([]string, error) {
	var removed []string
	if record.Kind == KindCoworkRemote {
		_, originalRemotes, err := coworkRemoteEntries(record.OriginalBytes)
		if err != nil {
			return nil, err
		}
		_, currentRemotes, err := coworkRemoteEntries(current)
		if err != nil {
			return nil, err
		}
		present := map[string]bool{}
		for _, remote := range currentRemotes {
			present[coworkRemoteKey(remote)] = true
		}
		for _, remote := range originalRemotes {
			if key := coworkRemoteKey(remote); !present[key] {
				removed = append(removed, key)
			}
		}
		return removed, nil
	}
	originalServers, err := serverMap(record.OriginalBytes)
	if err != nil {
		return nil, err
	}
	currentServers, err := serverMap(current)
	if err != nil {
		return nil, err
	}
	for name := range originalServers {
		if _, present := currentServers[name]; !present && name != ideconfig.GatewayServerName {
			removed = append(removed, name)
		}
	}
	return removed, nil
}

func hasTopLevelKey(data []byte, key string) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	_, ok := root[key]
	return ok
}

// holdsCustomerContent reports whether an mcpServers document has anything in
// it besides an empty server map.
func holdsCustomerContent(data []byte) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return len(bytes.TrimSpace(data)) > 0
	}
	for key, raw := range root {
		if key != "mcpServers" {
			return true
		}
		var servers map[string]json.RawMessage
		if json.Unmarshal(raw, &servers) != nil || len(servers) > 0 {
			return true
		}
	}
	return false
}

func sameJSON(a, b []byte) bool {
	var left, right interface{}
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(left, right)
}

func serverMap(data []byte) (map[string]json.RawMessage, error) {
	result := map[string]json.RawMessage{}
	if len(data) == 0 {
		return result, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if raw := root["mcpServers"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func directBaseline(current, priorOriginal []byte, migrated []ideconfig.NamedServer) ([]byte, error) {
	var root map[string]json.RawMessage
	if len(current) == 0 {
		root = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(current, &root); err != nil {
		return nil, err
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil, err
		}
	}
	for name, raw := range servers {
		var entry ideconfig.ServerEntry
		if name == ideconfig.GatewayServerName || (json.Unmarshal(raw, &entry) == nil && gatewayentry.IsGatewayCommand(entry.Command)) {
			delete(servers, name)
		}
	}
	priorServers, err := serverMap(priorOriginal)
	if err != nil {
		return nil, err
	}
	for name, raw := range priorServers {
		if _, exists := servers[name]; !exists {
			servers[name] = raw
		}
	}
	for _, server := range migrated {
		if _, exists := servers[server.Name]; exists {
			continue
		}
		raw, err := json.Marshal(server.Entry)
		if err != nil {
			return nil, err
		}
		servers[server.Name] = raw
	}
	encoded, err := json.Marshal(servers)
	if err != nil {
		return nil, err
	}
	root["mcpServers"] = encoded
	if err := baselineProjectScopedServers(root, priorOriginal); err != nil {
		return nil, err
	}
	baseline, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(baseline, '\n'), nil
}

// baselineProjectScopedServers carries the pre-route servers of each routed
// Claude Code project forward into a refreshed baseline. The refreshed
// baseline is built from the client's current file, whose projects hold only
// the Gateway entry, so without this a second configure-ide run would forget
// what rollback has to put back.
func baselineProjectScopedServers(root map[string]json.RawMessage, priorOriginal []byte) error {
	priorProjects := projectServerMaps(priorOriginal)
	if len(priorProjects) == 0 {
		return nil
	}
	var projects map[string]map[string]json.RawMessage
	if raw := root["projects"]; len(raw) == 0 || json.Unmarshal(raw, &projects) != nil {
		return nil
	}
	changed := false
	for project, settings := range projects {
		servers := map[string]json.RawMessage{}
		if raw := settings["mcpServers"]; len(raw) > 0 && string(raw) != "null" {
			if json.Unmarshal(raw, &servers) != nil {
				continue
			}
		}
		if !isGatewayRouteEntry(servers[ideconfig.GatewayServerName]) {
			continue
		}
		delete(servers, ideconfig.GatewayServerName)
		for name, raw := range priorProjects[project] {
			if _, exists := servers[name]; !exists && name != ideconfig.GatewayServerName {
				servers[name] = raw
			}
		}
		encoded, err := json.Marshal(servers)
		if err != nil {
			return err
		}
		settings["mcpServers"] = encoded
		projects[project] = settings
		changed = true
	}
	if !changed {
		return nil
	}
	encoded, err := json.Marshal(projects)
	if err != nil {
		return err
	}
	root["projects"] = encoded
	return nil
}

// projectServerMaps reads each Claude Code project's mcpServers from a
// ~/.claude.json document.
func projectServerMaps(data []byte) map[string]map[string]json.RawMessage {
	result := map[string]map[string]json.RawMessage{}
	if len(data) == 0 {
		return result
	}
	var root map[string]json.RawMessage
	var projects map[string]map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || len(root["projects"]) == 0 || json.Unmarshal(root["projects"], &projects) != nil {
		return result
	}
	for project, settings := range projects {
		servers := map[string]json.RawMessage{}
		if raw := settings["mcpServers"]; len(raw) > 0 && string(raw) != "null" {
			if json.Unmarshal(raw, &servers) != nil {
				continue
			}
		}
		result[project] = servers
	}
	return result
}

func snapshotFile(path string) (fileState, error) {
	state := fileState{path: path, mode: 0o600}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf("refusing non-regular configuration path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	state.exists, state.data, state.mode = true, data, info.Mode().Perm()
	return state, nil
}

func restoreFileStates(states []fileState) error {
	var failures []error
	for index := len(states) - 1; index >= 0; index-- {
		failures = append(failures, restoreFileState(states[index]))
	}
	return errors.Join(failures...)
}

func restoreFileState(state fileState) error {
	if !state.exists {
		if err := os.Remove(state.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomic(state.path, state.data, state.mode)
}

func toGatewayServer(server ideconfig.NamedServer) config.ServerEntry {
	return config.ServerEntry{
		Name: server.Name, Command: server.Entry.Command, Args: server.Entry.Args,
		Env: server.Entry.Env, Transport: server.Entry.Type, URL: server.Entry.URL,
		Headers: server.Entry.Headers,
	}
}

func findGatewayServer(servers []config.ServerEntry, name string) (config.ServerEntry, bool) {
	for _, server := range servers {
		if server.Name == name {
			return server, true
		}
	}
	return config.ServerEntry{}, false
}

func replaceGatewayServer(servers []config.ServerEntry, replacement config.ServerEntry) []config.ServerEntry {
	result := make([]config.ServerEntry, 0, len(servers)+1)
	for _, server := range servers {
		if server.Name != replacement.Name {
			result = append(result, server)
		}
	}
	return append(result, replacement)
}

func removeGatewayServer(servers []config.ServerEntry, name string) []config.ServerEntry {
	result := make([]config.ServerEntry, 0, len(servers))
	for _, server := range servers {
		if server.Name != name {
			result = append(result, server)
		}
	}
	return result
}

func referencedServers(clients []clientState) map[string]bool {
	result := map[string]bool{}
	for _, client := range clients {
		// Cowork state records remote entry keys here, not server names.
		if client.Kind != KindCoworkRemote {
			for _, name := range client.MigratedServers {
				result[name] = true
			}
		}
		for _, name := range client.GatewayServers {
			result[name] = true
		}
	}
	return result
}

// A client file has exactly one record: two would each try to restore it.
func findClient(clients []clientState, path string) (clientState, bool) {
	for _, client := range clients {
		if client.Path == path {
			return client, true
		}
	}
	return clientState{}, false
}

func replaceClient(clients []clientState, replacement clientState) []clientState {
	result := append([]clientState(nil), clients...)
	for index, client := range result {
		if client.Path == replacement.Path {
			result[index] = replacement
			return result
		}
	}
	return append(result, replacement)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortedMigratedNames(servers map[string]migratedServer) []string {
	result := make([]string, 0, len(servers))
	for name := range servers {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func writeManifest(path string, value manifest) (bool, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return false, err
	}
	raw = append(raw, '\n')
	if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, raw) {
		return false, nil
	}
	return true, writeAtomic(path, raw, 0o600)
}

// manifestModeIsPrivate reports whether a manifest's mode shows a regular file
// only its owner can read. Windows reports 0666 for every writable file and
// governs access through the ACL of the user's profile, so there the mode
// carries no information and only the file type is checked.
func manifestModeIsPrivate(goos string, mode os.FileMode) bool {
	if !mode.IsRegular() {
		return false
	}
	return goos == "windows" || mode.Perm()&0o077 == 0
}

func readManifest(path string) (manifest, error) {
	var value manifest
	info, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	if !manifestModeIsPrivate(runtime.GOOS, info.Mode()) {
		return value, fmt.Errorf("manual routing manifest must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return value, err
	}
	if len(raw) > maxManifestBytes {
		return value, fmt.Errorf("manual routing manifest exceeds %d MiB", maxManifestBytes>>20)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	return value, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentkeeper-manual-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
