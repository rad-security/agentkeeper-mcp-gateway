package managedrouting

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
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/runtimebroker"
)

const manifestVersion = 1

type Options struct {
	RuntimeConfigPath string
	Remove            bool
	DryRun            bool
	Targets           []string
}

type Report struct {
	Result          string   `json:"result"`
	Changed         bool     `json:"changed"`
	Configured      []string `json:"configured,omitempty"`
	Removed         []string `json:"removed,omitempty"`
	SkippedAbsent   []string `json:"skipped_absent,omitempty"`
	MigratedServers []string `json:"migrated_servers,omitempty"`
	ManifestPath    string   `json:"manifest_path,omitempty"`
}

type manifest struct {
	Version           int                           `json:"version"`
	OwnershipID       string                        `json:"ownership_id"`
	RuntimeConfigPath string                        `json:"runtime_config_path"`
	Clients           []clientSnapshot              `json:"clients"`
	MigratedServers   map[string]config.ServerEntry `json:"migrated_servers"`
}

type clientSnapshot struct {
	Name            string                     `json:"name"`
	Path            string                     `json:"path"`
	OriginalServers map[string]json.RawMessage `json:"original_servers"`
}

func Run(opts Options) (Report, error) {
	managed, err := runtimebroker.LoadManagedConfig(opts.RuntimeConfigPath)
	if err != nil {
		return Report{}, err
	}
	manifestPath, err := managedManifestPath()
	if err != nil {
		return Report{}, err
	}
	if opts.Remove {
		return remove(managed, manifestPath, opts.DryRun)
	}
	return configure(managed, opts.RuntimeConfigPath, manifestPath, opts)
}

func configure(managed runtimebroker.ManagedConfig, runtimeConfigPath, manifestPath string, opts Options) (Report, error) {
	report := Report{Result: "configured", ManifestPath: manifestPath}
	wanted := normalizeTargets(opts.Targets)
	state := manifest{
		Version: manifestVersion, OwnershipID: "agentkeeper.universal.v1", RuntimeConfigPath: runtimeConfigPath,
		Clients: []clientSnapshot{}, MigratedServers: map[string]config.ServerEntry{},
	}
	if existing, readErr := readManifest(manifestPath); readErr == nil {
		if existing.Version != manifestVersion || existing.OwnershipID != "agentkeeper.universal.v1" || existing.RuntimeConfigPath != runtimeConfigPath {
			return report, fmt.Errorf("an incompatible managed routing manifest already exists")
		}
		state = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return report, fmt.Errorf("read existing managed routing manifest: %w", readErr)
	}
	var applyPlans []struct {
		adapter  *ideconfig.Adapter
		plan     ideconfig.Plan
		snapshot clientSnapshot
	}
	adapters, err := managedAdapters()
	if err != nil {
		return report, err
	}
	for _, adapter := range adapters {
		if len(wanted) > 0 && !wanted[managedAdapterTarget(adapter.Name)] {
			continue
		}
		plan, err := adapter.Plan()
		if err != nil {
			return report, fmt.Errorf("plan managed routing for %s: %w", adapter.Name, err)
		}
		if !plan.Exists {
			report.SkippedAbsent = append(report.SkippedAbsent, adapter.Name)
			continue
		}
		currentServers, err := readServerMap(plan.ConfigPath)
		if err != nil {
			return report, err
		}
		snapshot, hasSnapshot := findClientSnapshot(state.Clients, adapter.Name, plan.ConfigPath)
		if !hasSnapshot {
			if plan.HasGateway {
				return report, fmt.Errorf("%s is already gateway-routed without an AgentKeeper ownership manifest", adapter.Name)
			}
			snapshot = clientSnapshot{Name: adapter.Name, Path: plan.ConfigPath, OriginalServers: currentServers}
			state.Clients = append(state.Clients, snapshot)
		} else {
			for _, server := range plan.Migrated {
				if raw, ok := currentServers[server.Name]; ok {
					snapshot.OriginalServers[server.Name] = raw
				}
			}
			state.Clients = replaceClientSnapshot(state.Clients, snapshot)
		}
		applyPlans = append(applyPlans, struct {
			adapter  *ideconfig.Adapter
			plan     ideconfig.Plan
			snapshot clientSnapshot
		}{adapter: adapter, plan: plan, snapshot: clientSnapshot{
			Name: adapter.Name, Path: plan.ConfigPath, OriginalServers: currentServers,
		}})
		for _, server := range plan.Migrated {
			entry := config.ServerEntry{
				Name: server.Name, Command: server.Entry.Command, Args: server.Entry.Args,
				Env: server.Entry.Env, URL: server.Entry.URL, Headers: server.Entry.Headers,
			}
			if server.Entry.Type != "" {
				entry.Transport = server.Entry.Type
			}
			state.MigratedServers[server.Name] = entry
		}
	}
	if opts.DryRun {
		for _, item := range applyPlans {
			report.Configured = append(report.Configured, item.adapter.Name)
		}
		report.MigratedServers = sortedServerNames(state.MigratedServers)
		return report, nil
	}
	if len(applyPlans) == 0 && len(state.Clients) == 0 {
		report.Result = "no_supported_client_config"
		return report, nil
	}
	appliedSnapshots := []clientSnapshot{}
	for index := range applyPlans {
		if !applyPlans[index].plan.AlreadyWired {
			if err := applyPlans[index].adapter.ApplyManaged(&applyPlans[index].plan); err != nil {
				_ = restoreClients(appliedSnapshots)
				return report, fmt.Errorf("apply managed routing for %s: %w", applyPlans[index].adapter.Name, err)
			}
			appliedSnapshots = append(appliedSnapshots, applyPlans[index].snapshot)
			report.Changed = true
		}
		report.Configured = append(report.Configured, applyPlans[index].adapter.Name)
	}
	gatewayConfig, err := config.Load()
	if err != nil {
		_ = restoreClients(appliedSnapshots)
		return report, fmt.Errorf("load gateway config for managed routing: %w", err)
	}
	originalGatewayConfig := gatewayConfig
	gatewayConfig.ManagedRuntimeSocket = managed.RuntimeSocket
	gatewayConfig.ManagedRuntimeProtocol = managed.Protocol
	gatewayConfig.CredentialMode = managed.CredentialMode
	for name, entry := range state.MigratedServers {
		gatewayConfig.Servers = replaceServer(gatewayConfig.Servers, name, entry)
	}
	gatewayChanged := !reflect.DeepEqual(originalGatewayConfig, gatewayConfig)
	if gatewayChanged {
		if err := savePrivateGatewayConfig(gatewayConfig); err != nil {
			_ = restoreClients(appliedSnapshots)
			return report, fmt.Errorf("save gateway config for managed routing: %w", err)
		}
		report.Changed = true
	}
	manifestChanged, err := writeManifest(manifestPath, state)
	if err != nil {
		_ = restoreClients(appliedSnapshots)
		if gatewayChanged {
			_ = savePrivateGatewayConfig(originalGatewayConfig)
		}
		return report, fmt.Errorf("write managed routing manifest: %w", err)
	}
	report.Changed = report.Changed || manifestChanged
	report.MigratedServers = sortedServerNames(state.MigratedServers)
	return report, nil
}

func replaceClientSnapshot(clients []clientSnapshot, replacement clientSnapshot) []clientSnapshot {
	result := append([]clientSnapshot(nil), clients...)
	for index, client := range result {
		if client.Name == replacement.Name && client.Path == replacement.Path {
			result[index] = replacement
			return result
		}
	}
	return append(result, replacement)
}

func findClientSnapshot(clients []clientSnapshot, name, path string) (clientSnapshot, bool) {
	for _, client := range clients {
		if client.Name == name && client.Path == path {
			return client, true
		}
	}
	return clientSnapshot{}, false
}

func remove(managed runtimebroker.ManagedConfig, manifestPath string, dryRun bool) (Report, error) {
	report := Report{Result: "removed", ManifestPath: manifestPath}
	state, err := readManifest(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			adapters, adapterErr := managedAdapters()
			if adapterErr != nil {
				return report, adapterErr
			}
			for _, adapter := range adapters {
				plan, planErr := adapter.Plan()
				if planErr != nil {
					return report, planErr
				}
				if plan.HasGateway {
					return report, fmt.Errorf("%s is gateway-routed but the AgentKeeper ownership manifest is missing", adapter.Name)
				}
			}
			report.Result = "not_configured"
			return report, nil
		}
		return report, fmt.Errorf("read managed routing manifest: %w", err)
	}
	if state.Version != manifestVersion || state.OwnershipID != "agentkeeper.universal.v1" {
		return report, fmt.Errorf("managed routing manifest version is incompatible")
	}
	if dryRun {
		for _, client := range state.Clients {
			report.Removed = append(report.Removed, client.Name)
		}
		return report, nil
	}
	gatewayConfig, err := config.Load()
	if err != nil {
		return report, err
	}
	if gatewayConfig.ManagedRuntimeSocket != managed.RuntimeSocket ||
		gatewayConfig.ManagedRuntimeProtocol != managed.Protocol ||
		gatewayConfig.CredentialMode != managed.CredentialMode {
		return report, fmt.Errorf("gateway managed runtime fields drifted; refusing destructive cleanup")
	}
	restoreServers := map[string]json.RawMessage{}
	for _, current := range gatewayConfig.Servers {
		if _, owned := state.MigratedServers[current.Name]; owned {
			restoreServers[current.Name] = rawIDEEntry(current)
		}
	}
	for _, client := range state.Clients {
		if err := restoreClient(client, restoreServers); err != nil {
			return report, fmt.Errorf("remove managed routing from %s: %w", client.Name, err)
		}
		report.Removed = append(report.Removed, client.Name)
		report.Changed = true
	}
	filtered := make([]config.ServerEntry, 0, len(gatewayConfig.Servers))
	for _, current := range gatewayConfig.Servers {
		if _, owned := state.MigratedServers[current.Name]; owned {
			continue
		}
		filtered = append(filtered, current)
	}
	gatewayConfig.Servers = filtered
	gatewayConfig.ManagedRuntimeSocket = ""
	gatewayConfig.ManagedRuntimeProtocol = ""
	gatewayConfig.CredentialMode = ""
	if err := savePrivateGatewayConfig(gatewayConfig); err != nil {
		return report, err
	}
	if err := os.Remove(manifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return report, err
	}
	report.Changed = true
	return report, nil
}

func managedAdapters() ([]*ideconfig.Adapter, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home for managed MCP routing: %w", err)
	}
	adapters := append([]*ideconfig.Adapter(nil), ideconfig.Adapters()...)
	adapters = append(adapters, &ideconfig.Adapter{
		Name: "claude-code-user",
		PathResolver: func() (string, error) {
			return filepath.Join(home, ".claude.json"), nil
		},
	})
	return adapters, nil
}

func managedAdapterTarget(name string) string {
	if name == "claude-code-user" {
		return "claude-code"
	}
	return name
}

func savePrivateGatewayConfig(value config.Config) error {
	if err := config.Save(value); err != nil {
		return err
	}
	return os.Chmod(config.CurrentConfigPath(), 0o600)
}

func rawIDEEntry(entry config.ServerEntry) json.RawMessage {
	raw, _ := json.Marshal(struct {
		Command string            `json:"command,omitempty"`
		Args    []string          `json:"args,omitempty"`
		Env     map[string]string `json:"env,omitempty"`
		Type    string            `json:"type,omitempty"`
		URL     string            `json:"url,omitempty"`
		Headers map[string]string `json:"headers,omitempty"`
	}{
		Command: entry.Command, Args: entry.Args, Env: entry.Env,
		Type: entry.Transport, URL: entry.URL, Headers: entry.Headers,
	})
	return raw
}

func managedManifestPath() (string, error) {
	path := config.CurrentConfigPath()
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("gateway config path is unavailable")
	}
	return filepath.Join(filepath.Dir(path), "managed-routing.json"), nil
}

func readServerMap(path string) (map[string]json.RawMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	servers := map[string]json.RawMessage{}
	if encoded := root["mcpServers"]; len(encoded) > 0 {
		if err := json.Unmarshal(encoded, &servers); err != nil {
			return nil, fmt.Errorf("parse mcpServers in %s: %w", path, err)
		}
	}
	return servers, nil
}

func restoreClients(clients []clientSnapshot) error {
	var failures []error
	for _, client := range clients {
		failures = append(failures, restoreClient(client, nil))
	}
	return errors.Join(failures...)
}

func restoreClient(snapshot clientSnapshot, managedServers map[string]json.RawMessage) error {
	raw, err := os.ReadFile(snapshot.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(snapshot.Path); statErr == nil {
		mode = info.Mode().Perm()
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	servers := map[string]json.RawMessage{}
	if encoded := root["mcpServers"]; len(encoded) > 0 {
		if err := json.Unmarshal(encoded, &servers); err != nil {
			return err
		}
	}
	if gateway, ok := servers[ideconfig.GatewayServerName]; ok {
		if !isOwnedGatewayEntry(gateway) {
			return fmt.Errorf("gateway entry no longer matches the AgentKeeper-owned command")
		}
		delete(servers, ideconfig.GatewayServerName)
	}
	for name, original := range snapshot.OriginalServers {
		if managedServers != nil {
			var restorable bool
			original, restorable = managedServers[name]
			if !restorable {
				continue
			}
		}
		if _, exists := servers[name]; !exists {
			servers[name] = original
		}
	}
	encoded, err := json.Marshal(servers)
	if err != nil {
		return err
	}
	root["mcpServers"] = encoded
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if _, err := configbackup.Write(snapshot.Path, raw); err != nil {
		return err
	}
	return writeAtomic(snapshot.Path, append(updated, '\n'), mode)
}

func isOwnedGatewayEntry(raw json.RawMessage) bool {
	var entry struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if json.Unmarshal(raw, &entry) != nil || len(entry.Args) != 1 || entry.Args[0] != "server" {
		return false
	}
	return gatewayentry.IsCurrentGatewayCommand(entry.Command)
}

func replaceServer(servers []config.ServerEntry, name string, entry config.ServerEntry) []config.ServerEntry {
	filtered := make([]config.ServerEntry, 0, len(servers)+1)
	for _, server := range servers {
		if server.Name != name {
			filtered = append(filtered, server)
		}
	}
	return append(filtered, entry)
}

func normalizeTargets(targets []string) map[string]bool {
	result := map[string]bool{}
	for _, target := range targets {
		for _, item := range strings.Split(target, ",") {
			item = strings.ToLower(strings.TrimSpace(item))
			if item != "" {
				result[item] = true
			}
		}
	}
	return result
}

func sortedServerNames(servers map[string]config.ServerEntry) []string {
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
		return value, fmt.Errorf("managed routing manifest must be a private regular file")
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
		return value, fmt.Errorf("managed routing manifest exceeds 1 MiB")
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
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentkeeper-managed-*.tmp")
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
