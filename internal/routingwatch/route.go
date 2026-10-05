package routingwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/configbackup"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/manualrouting"
)

// routeLockName orders the routing transactions of the Gateway processes
// that share one Gateway config, one per routed client session.
const routeLockName = "routing-watch.lock"

// errClientConfigChanged reports that the client config changed between
// being read and being replaced. Nothing was written.
var errClientConfigChanged = errors.New("the client config changed while it was being routed")

// beforeReplace runs after the routed document is staged, immediately before
// the final content check and rename. Tests change the file there.
var beforeReplace func(path string)

type routeResult struct {
	// routed maps the key of each moved server to the name the Gateway
	// serves it under.
	routed       map[string]string
	backup       string
	ownershipErr error
}

type routeEdit struct {
	document      []byte
	sourceHash    string
	routeRevision string
	moved         []discovery.DiscoveredServer
}

// routeServers moves servers out of one client config file and behind the
// Gateway with configure-ide's building blocks: each server joins the Gateway
// config the way configure-ide adds it, the file gets a byte-exact backup and
// its routes are re-attested, and the change is recorded so configure-ide
// --remove-routing can undo it.
//
// It is a compare-and-swap. The file is read and hashed, the edit computed
// from those bytes, and right before the atomic rename the file is read again;
// if it changed, nothing is replaced and the Gateway config additions are
// undone. Only the moved entries leave the file, and a Gateway entry joins any
// server map that lacks one, as configure-ide leaves every map it routes.
// A server that changed or left since it was classified is skipped.
func routeServers(client string, file discovery.ClientConfigFile, servers []discovery.DiscoveredServer) (routeResult, error) {
	release, err := acquireRouteLock()
	if err != nil {
		return routeResult{}, fmt.Errorf("routing lock: %w", err)
	}
	defer release()

	// Like configure-ide's project migrations, write through a symlinked
	// client file (a dotfiles checkout) rather than replacing the link.
	target := file.Path
	if info, err := os.Lstat(file.Path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if target, err = filepath.EvalSymlinks(file.Path); err != nil {
			return routeResult{}, err
		}
	}
	info, err := os.Stat(target)
	if err != nil {
		return routeResult{}, err
	}
	original, err := os.ReadFile(target)
	if err != nil {
		return routeResult{}, err
	}
	expected := gatewayentry.ContentHash(original)

	edit, err := planRouteEdit(client, original, servers)
	if err != nil || len(edit.moved) == 0 {
		return routeResult{}, err
	}
	installed, added, err := installInGateway(edit.moved)
	if err != nil {
		return routeResult{}, joinRollback(err, removeAddedGatewayServers(added))
	}
	backup, err := configbackup.Write(file.Path, original)
	if err != nil {
		return routeResult{}, joinRollback(fmt.Errorf("writing backup: %w", err), removeAddedGatewayServers(added))
	}
	if err := replaceIfUnchanged(target, edit.document, info.Mode().Perm(), expected); err != nil {
		_ = os.Remove(backup)
		return routeResult{}, joinRollback(err, removeAddedGatewayServers(added))
	}

	result := routeResult{routed: installed, backup: backup}
	referenced := map[string]bool{}
	for _, name := range installed {
		referenced[name] = true
	}
	result.ownershipErr = manualrouting.Adopt(manualrouting.AdoptOptions{
		Client: client, Path: file.Path,
		OriginalExists: true, Original: original,
		SourceHash: edit.sourceHash, RouteRevision: edit.routeRevision,
		AddedGatewayServers:      sortedNames(added),
		ReferencedGatewayServers: sortedNames(referenced),
	})
	return result, nil
}

// planRouteEdit removes each server from its server map in original, adds a
// Gateway entry to a map that has none, and attests the routes.
func planRouteEdit(client string, original []byte, servers []discovery.DiscoveredServer) (routeEdit, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(original, &root); err != nil {
		return routeEdit{}, fmt.Errorf("parsing client config: %w", err)
	}
	if root == nil {
		return routeEdit{}, nil
	}
	var projects map[string]map[string]json.RawMessage
	maps := map[string]map[string]json.RawMessage{}
	serverMap := func(project string) (map[string]json.RawMessage, error) {
		if servers, ok := maps[project]; ok {
			return servers, nil
		}
		raw := root["mcpServers"]
		if project != "" {
			if projects == nil {
				projects = map[string]map[string]json.RawMessage{}
				if rawProjects := root["projects"]; len(rawProjects) > 0 && string(rawProjects) != "null" {
					if err := json.Unmarshal(rawProjects, &projects); err != nil {
						return nil, fmt.Errorf("parsing projects: %w", err)
					}
				}
			}
			settings, ok := projects[project]
			if !ok || settings == nil {
				return nil, nil
			}
			raw = settings["mcpServers"]
		}
		servers := map[string]json.RawMessage{}
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &servers); err != nil {
				return nil, fmt.Errorf("parsing mcpServers: %w", err)
			}
		}
		maps[project] = servers
		return servers, nil
	}

	var moved []discovery.DiscoveredServer
	touched := map[string]bool{}
	for _, server := range servers {
		entries, err := serverMap(server.Project)
		if err != nil {
			return routeEdit{}, err
		}
		raw, ok := entries[server.Name]
		if !ok {
			continue
		}
		var current config.ServerEntry
		if json.Unmarshal(raw, &current) != nil || !sameEntry(current, server.Entry) {
			continue
		}
		delete(entries, server.Name)
		touched[server.Project] = true
		moved = append(moved, server)
	}
	if len(moved) == 0 {
		return routeEdit{}, nil
	}

	projectTouched := false
	for _, project := range sortedNames(touched) {
		projectTouched = projectTouched || project != ""
		entries := maps[project]
		if !hasGatewayEntry(entries) {
			if _, taken := entries[ideconfig.GatewayServerName]; taken {
				return routeEdit{}, fmt.Errorf("a server the Gateway does not own is named %q", ideconfig.GatewayServerName)
			}
			gateway, err := json.Marshal(config.ServerEntry{
				Command: gatewayentry.Command(),
				Args:    []string{"server"},
				Env:     map[string]string{gatewayentry.EnvClientName: client},
			})
			if err != nil {
				return routeEdit{}, err
			}
			entries[ideconfig.GatewayServerName] = gateway
		}
		encoded, err := json.Marshal(entries)
		if err != nil {
			return routeEdit{}, err
		}
		if project == "" {
			root["mcpServers"] = encoded
			continue
		}
		projects[project]["mcpServers"] = encoded
	}
	if projectTouched {
		encoded, err := json.Marshal(projects)
		if err != nil {
			return routeEdit{}, err
		}
		root["projects"] = encoded
	}
	document, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return routeEdit{}, err
	}
	document, sourceHash, routeRevision, err := gatewayentry.AttestRoutes(client, document)
	if err != nil {
		return routeEdit{}, err
	}
	return routeEdit{document: append(document, '\n'), sourceHash: sourceHash, routeRevision: routeRevision, moved: moved}, nil
}

// installInGateway adds each moved server to the Gateway config. added holds
// the entries this call created, which a failed transaction removes again.
func installInGateway(moved []discovery.DiscoveredServer) (installed map[string]string, added map[string]config.ServerEntry, err error) {
	installed, added = map[string]string{}, map[string]config.ServerEntry{}
	cfg, err := config.Load()
	if err != nil {
		return installed, added, fmt.Errorf("loading the Gateway config: %w", err)
	}
	existing := map[string]bool{}
	for _, server := range cfg.Servers {
		existing[server.Name] = true
	}
	for _, server := range moved {
		entry := gatewayServer(server)
		name, err := discovery.AddServerToGatewayConfig(entry, sourceKey(server))
		if err != nil {
			return installed, added, fmt.Errorf("adding %s to the Gateway config: %w", server.Name, err)
		}
		installed[serverKey(server)] = name
		if !existing[name] {
			entry.Name = name
			added[name] = entry
			existing[name] = true
		}
	}
	return installed, added, nil
}

// gatewayServer is the Gateway config entry for a client server, as
// configure-ide's migrations write it. Only servers without client-only
// fields are routed, so nothing the client reads is lost.
func gatewayServer(server discovery.DiscoveredServer) config.ServerEntry {
	entry := server.Entry
	transport := entry.Transport
	if transport == "" {
		transport = discovery.NormalizeTransport(entry)
	}
	return config.ServerEntry{
		Name: server.Name, Type: entry.Type, Command: entry.Command, Args: entry.Args,
		Env: entry.Env, Transport: transport, URL: entry.URL, Headers: entry.Headers,
	}
}

// removeAddedGatewayServers undoes installInGateway for a transaction that
// did not complete, sparing an entry someone changed since.
func removeAddedGatewayServers(added map[string]config.ServerEntry) error {
	if len(added) == 0 {
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	kept := make([]config.ServerEntry, 0, len(cfg.Servers))
	for _, server := range cfg.Servers {
		if want, ours := added[server.Name]; ours && sameEntry(server, want) {
			continue
		}
		kept = append(kept, server)
	}
	if len(kept) == len(cfg.Servers) {
		return nil
	}
	cfg.Servers = kept
	return config.Save(cfg)
}

// replaceIfUnchanged stages data beside path and renames it over path only if
// path still hashes to expected. The check runs after staging, so the window
// in which another writer can slip in is the rename itself.
func replaceIfUnchanged(path string, data []byte, mode os.FileMode, expected string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentkeeper-route-*.tmp")
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
	if beforeReplace != nil {
		beforeReplace(path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if gatewayentry.ContentHash(current) != expected {
		return errClientConfigChanged
	}
	return os.Rename(tmpPath, path)
}

func acquireRouteLock() (func(), error) {
	savePath := strings.TrimSpace(config.SavePath())
	if savePath == "" {
		return nil, errors.New("the Gateway config path is unavailable")
	}
	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return fslock.Acquire(filepath.Join(dir, routeLockName))
}

// hasGatewayEntry reports whether a server map carries a Gateway entry,
// current or stale, which attestation then binds.
func hasGatewayEntry(entries map[string]json.RawMessage) bool {
	for _, raw := range entries {
		var entry config.ServerEntry
		if json.Unmarshal(raw, &entry) == nil && gatewayentry.IsGatewayCommand(entry.Command) && len(entry.Args) == 1 && entry.Args[0] == "server" {
			return true
		}
	}
	return false
}

// sameEntry compares two server entries without their names.
func sameEntry(a, b config.ServerEntry) bool {
	a.Name, b.Name = "", ""
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}

// sourceKey names a server's origin for configure-ide's conflict naming.
func sourceKey(server discovery.DiscoveredServer) string {
	if server.Project == "" {
		return server.SourceHash
	}
	sum := sha256.Sum256([]byte(filepath.Clean(server.SourcePath) + "|" + server.Project + "|" + server.Name))
	return hex.EncodeToString(sum[:])[:12]
}

func sortedNames[V any](values map[string]V) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func joinRollback(err, rollbackErr error) error {
	if rollbackErr != nil {
		return errors.Join(err, fmt.Errorf("undoing Gateway config additions: %w", rollbackErr))
	}
	return err
}
