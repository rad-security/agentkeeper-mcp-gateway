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
)

type ConfigureOptions struct {
	Adapters []*ideconfig.Adapter
	DryRun   bool
}

type RemoveOptions struct {
	Adapters []*ideconfig.Adapter
	DryRun   bool
}

type Report struct {
	Result             string            `json:"result"`
	Changed            bool              `json:"changed"`
	Configured         []string          `json:"configured,omitempty"`
	Removed            []string          `json:"removed,omitempty"`
	ExactRestored      []string          `json:"exact_restored,omitempty"`
	StructuralRestored []string          `json:"structural_restored,omitempty"`
	MigratedServers    []string          `json:"migrated_servers,omitempty"`
	ManifestPath       string            `json:"manifest_path"`
	Errors             map[string]string `json:"errors,omitempty"`
	Plans              []ideconfig.Plan  `json:"-"`
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
		if _, ok := findClient(state.Clients, adapter.Name, plan.ConfigPath); ok && plan.AlreadyWired {
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
		if previous, ok := findClient(state.Clients, adapter.Name, plan.ConfigPath); ok {
			client = previous
			client.OriginalExists = original.exists
			client.OriginalMode = uint32(original.mode.Perm())
			baseline, baselineErr := directBaseline(original.data, previous.OriginalBytes, plan.Migrated)
			if baselineErr != nil {
				return report, fmt.Errorf("prepare updated rollback baseline for %s: %w", adapter.Name, baselineErr)
			}
			client.OriginalBytes = baseline
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

	gatewayBefore, err := snapshotFile(config.CurrentConfigPath())
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
	for _, adapter := range opts.Adapters {
		wanted[adapter.Name] = true
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

	gatewayBefore, err := snapshotFile(config.CurrentConfigPath())
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
		if !exists || !reflect.DeepEqual(current, owned.Installed) {
			return report, fmt.Errorf("gateway server %s drifted after route configuration; refusing destructive cleanup", name)
		}
		if owned.PreviousExists && owned.Previous != nil {
			gatewayConfig.Servers = replaceGatewayServer(gatewayConfig.Servers, *owned.Previous)
		} else {
			gatewayConfig.Servers = removeGatewayServer(gatewayConfig.Servers, name)
		}
		delete(state.MigratedServers, name)
	}

	actions := make([]restoreAction, 0, len(selected))
	for _, client := range selected {
		action, actionErr := prepareRestore(client)
		if actionErr != nil {
			return report, fmt.Errorf("prepare rollback for %s: %w", client.Name, actionErr)
		}
		actions = append(actions, action)
		report.Removed = append(report.Removed, client.Name)
		if action.exact {
			report.ExactRestored = append(report.ExactRestored, client.Name)
		} else {
			report.StructuralRestored = append(report.StructuralRestored, client.Name)
		}
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
	path := strings.TrimSpace(config.CurrentConfigPath())
	if path == "" {
		return "", fmt.Errorf("gateway config path is unavailable")
	}
	return filepath.Join(filepath.Dir(path), "manual-routing.json"), nil
}

func prepareRestore(state clientState) (restoreAction, error) {
	current, err := snapshotFile(state.Path)
	if err != nil {
		return restoreAction{}, err
	}
	if !current.exists {
		return restoreAction{}, fmt.Errorf("owned route configuration is missing")
	}
	action := restoreAction{state: state, current: current, mode: current.mode}
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

	var root map[string]json.RawMessage
	if err := json.Unmarshal(current.data, &root); err != nil {
		return action, fmt.Errorf("parse drifted client config: %w", err)
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return action, fmt.Errorf("parse drifted mcpServers: %w", err)
		}
	}
	if raw, exists := servers[ideconfig.GatewayServerName]; exists {
		if !isOwnedGatewayEntry(raw, state) {
			return action, fmt.Errorf("gateway entry no longer matches the AgentKeeper-owned route identity")
		}
		delete(servers, ideconfig.GatewayServerName)
	}
	originalServers, err := serverMap(state.OriginalBytes)
	if err != nil {
		return action, err
	}
	for _, name := range state.MigratedServers {
		if original, ok := originalServers[name]; ok {
			if _, exists := servers[name]; !exists {
				servers[name] = original
			}
		}
	}
	encoded, err := json.Marshal(servers)
	if err != nil {
		return action, err
	}
	root["mcpServers"] = encoded
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return action, err
	}
	action.updated = append(updated, '\n')
	return action, nil
}

func isOwnedGatewayEntry(raw json.RawMessage, state clientState) bool {
	var entry ideconfig.ServerEntry
	if json.Unmarshal(raw, &entry) != nil || len(entry.Args) != 1 || entry.Args[0] != "server" {
		return false
	}
	return gatewayentry.IsGatewayCommand(entry.Command) &&
		entry.Env[gatewayentry.EnvClientName] == state.Name &&
		entry.Env[gatewayentry.EnvConfigSourceHash] == state.SourceHash &&
		entry.Env[gatewayentry.EnvRouteRevision] == state.RouteRevision
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
	baseline, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(baseline, '\n'), nil
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
		for _, name := range client.MigratedServers {
			result[name] = true
		}
	}
	return result
}

func findClient(clients []clientState, name, path string) (clientState, bool) {
	for _, client := range clients {
		if client.Name == name && client.Path == path {
			return client, true
		}
	}
	return clientState{}, false
}

func replaceClient(clients []clientState, replacement clientState) []clientState {
	result := append([]clientState(nil), clients...)
	for index, client := range result {
		if client.Name == replacement.Name && client.Path == replacement.Path {
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

func readManifest(path string) (manifest, error) {
	var value manifest
	info, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return value, fmt.Errorf("manual routing manifest must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return value, err
	}
	if len(raw) > 1<<20 {
		return value, fmt.Errorf("manual routing manifest exceeds 1 MiB")
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
