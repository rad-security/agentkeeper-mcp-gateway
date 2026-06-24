// Package ideconfig rewrites per-developer IDE MCP configs to route through
// the AgentKeeper gateway.
//
// Scope: Claude Code, Claude Desktop, Cursor. Windsurf does not speak MCP
// (it uses a hooks-based integration) and is intentionally out of scope.
//
// All three target IDEs share the same JSON shape at the config root:
//
//	{
//	  "mcpServers": { "<name>": { "command": ..., "args": [...], "env": {...} } },
//	  ...other top-level keys the IDE cares about...
//	}
//
// The logic here is therefore IDE-agnostic — adapters differ only in path
// resolution (including per-OS differences for Claude Desktop). Unknown
// top-level keys round-trip via json.RawMessage so we never drop settings
// we don't model (e.g. Claude Code's `permissions`, Claude Desktop's
// `preferences`).
package ideconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/configbackup"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/nativeauth"
)

// GatewayServerName is the key this package writes under `mcpServers`. It is
// also how we detect "already wired" idempotency — an IDE config whose only
// MCP entry has this name and our exact shape is a no-op.
const GatewayServerName = "agentkeeper-mcp-gateway"

// ServerEntry mirrors the shape each target IDE uses inside its `mcpServers`
// map. It is a superset — stdio servers use Command/Args/Env; HTTP/SSE-style
// servers use Type/URL/Headers. We round-trip whatever we find.
type ServerEntry struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// NamedServer pairs an entry with the key it lived under in the IDE config.
type NamedServer struct {
	Name  string
	Entry ServerEntry
}

// Adapter represents one IDE's MCP config location. Behavior is shared across
// all three targets — they differ only in path.
type Adapter struct {
	Name         string                 // "claude-code", "claude-desktop", "cursor"
	PathResolver func() (string, error) // returns the per-OS path for this IDE
}

// Plan describes what Apply would do for a single IDE, in one struct so the
// command layer can render a summary and the caller can run --dry-run safely.
type Plan struct {
	IDE          string
	ConfigPath   string
	Exists       bool          // did the file exist when Plan was built
	AlreadyWired bool          // gateway is the sole MCP entry already
	Migrated     []NamedServer // servers we'd move into the gateway's own config
	NativeKept   []NamedServer // remote OAuth/native-auth servers kept in the IDE config
	BackupPath   string        // set by Apply when it writes a backup
}

// Adapters returns the adapters applicable on the current OS.
func Adapters() []*Adapter {
	return []*Adapter{
		claudeCodeAdapter(),
		claudeDesktopAdapter(),
		cursorAdapter(),
	}
}

func claudeCodeAdapter() *Adapter {
	return &Adapter{
		Name: "claude-code",
		PathResolver: func() (string, error) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(home, ".claude", "settings.json"), nil
		},
	}
}

func claudeDesktopAdapter() *Adapter {
	return &Adapter{
		Name: "claude-desktop",
		PathResolver: func() (string, error) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return claudeDesktopConfigPath(home, runtime.GOOS, os.Getenv("APPDATA")), nil
		},
	}
}

func claudeDesktopConfigPath(home, goos, appData string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		if appData != "" {
			return filepath.Join(appData, "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

func cursorAdapter() *Adapter {
	return &Adapter{
		Name: "cursor",
		PathResolver: func() (string, error) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(home, ".cursor", "mcp.json"), nil
		},
	}
}

// gatewayEntry is the single server entry we write into every IDE config.
func gatewayEntry() ServerEntry {
	return ServerEntry{
		Command: gatewayentry.Command(),
		Args:    []string{"server"},
	}
}

// isGatewayEntry reports whether an entry matches our canonical shape. When an
// installed binary path is known, the command must match that path exactly so a
// rerun repairs stale /usr/local or bare entries.
func isGatewayEntry(e ServerEntry) bool {
	if !gatewayentry.IsCurrentGatewayCommand(e.Command) {
		return false
	}
	if len(e.Args) != 1 || e.Args[0] != "server" {
		return false
	}
	return true
}

// Plan reads the IDE config and computes what Apply would do. Missing files
// are not errors — they produce an Exists=false plan whose Apply creates a
// fresh config.
func (a *Adapter) Plan() (Plan, error) {
	path, err := a.PathResolver()
	if err != nil {
		return Plan{}, err
	}
	p := Plan{IDE: a.Name, ConfigPath: path}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		p.Exists = true
	case errors.Is(err, os.ErrNotExist):
		return p, nil
	default:
		return p, fmt.Errorf("reading %s: %w", path, err)
	}

	// Preserve unknown top-level keys via RawMessage. We only decode the
	// `mcpServers` key into a typed map.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return p, fmt.Errorf("parsing %s: %w", path, err)
	}

	servers := map[string]ServerEntry{}
	if rawServers, ok := raw["mcpServers"]; ok && len(rawServers) > 0 {
		if err := json.Unmarshal(rawServers, &servers); err != nil {
			return p, fmt.Errorf("parsing mcpServers in %s: %w", path, err)
		}
	}

	hasCurrentGateway := false
	if entry, ok := servers[GatewayServerName]; ok && isGatewayEntry(entry) {
		hasCurrentGateway = true
	}

	// Collect everything except any existing gateway entry — that one gets
	// replaced, not migrated (the gateway is not itself an MCP server). Remote
	// HTTP entries without credential headers are kept native so the MCP client
	// can own OAuth and refresh tokens.
	for name, entry := range servers {
		if name == GatewayServerName {
			continue
		}
		if nativeauth.RequiresNativeClientAuth(entry.Type, entry.URL, entry.Headers) {
			p.NativeKept = append(p.NativeKept, NamedServer{Name: name, Entry: entry})
			continue
		}
		p.Migrated = append(p.Migrated, NamedServer{Name: name, Entry: entry})
	}

	p.NativeKept = mergeNamedServers(p.NativeKept, a.recoverNativeClientAuthServers(servers))
	if hasCurrentGateway && len(p.Migrated) == 0 && len(p.NativeKept) == len(nonGatewayServers(servers)) {
		p.AlreadyWired = true
	}
	return p, nil
}

// Apply executes a Plan: backs up the existing file (if any), then writes the
// new IDE config with the gateway plus any native-auth MCP entries under
// `mcpServers`. Already-wired plans are a no-op. All unknown top-level keys are
// preserved.
//
// Takes *Plan so the BackupPath side-effect is visible to the caller (the
// command layer renders it in the summary; tests assert on it).
//
// Apply does NOT move migrated servers into the gateway's own config — that is
// the caller's responsibility.
func (a *Adapter) Apply(p *Plan) error {
	if p == nil {
		return errors.New("nil plan")
	}
	if p.AlreadyWired {
		return nil
	}

	// Round-trip unknown top-level keys if the file exists; start fresh if not.
	var raw map[string]json.RawMessage
	if p.Exists {
		data, err := os.ReadFile(p.ConfigPath)
		if err != nil {
			return fmt.Errorf("re-reading %s for apply: %w", p.ConfigPath, err)
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parsing %s: %w", p.ConfigPath, err)
		}
		backup, err := configbackup.Write(p.ConfigPath, data)
		if err != nil {
			return fmt.Errorf("writing backup %s: %w", backup, err)
		}
		p.BackupPath = backup
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}

	newServers := map[string]ServerEntry{GatewayServerName: gatewayEntry()}
	for _, kept := range p.NativeKept {
		if kept.Name == "" || kept.Name == GatewayServerName {
			continue
		}
		newServers[kept.Name] = kept.Entry
	}
	encoded, err := json.Marshal(newServers)
	if err != nil {
		return fmt.Errorf("encoding mcpServers: %w", err)
	}
	raw["mcpServers"] = encoded

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding final config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.ConfigPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(p.ConfigPath), err)
	}
	if err := os.WriteFile(p.ConfigPath, out, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", p.ConfigPath, err)
	}
	pruneNativeKeptFromGatewayConfig(p.NativeKept)
	return nil
}

func (a *Adapter) recoverNativeClientAuthServers(existing map[string]ServerEntry) []NamedServer {
	if a.Name != "claude-code" {
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for name := range existing {
		seen[name] = true
	}
	var recovered []NamedServer
	for _, server := range cfg.Servers {
		if server.Name == "" || seen[server.Name] {
			continue
		}
		if !nativeauth.RequiresNativeClientAuth(server.Transport, server.URL, server.Headers) {
			continue
		}
		recovered = append(recovered, NamedServer{
			Name: server.Name,
			Entry: ServerEntry{
				Command: server.Command,
				Args:    server.Args,
				Env:     server.Env,
				Type:    server.Transport,
				URL:     server.URL,
				Headers: server.Headers,
			},
		})
		seen[server.Name] = true
	}
	sort.Slice(recovered, func(i, j int) bool { return recovered[i].Name < recovered[j].Name })
	return recovered
}

func mergeNamedServers(existing, add []NamedServer) []NamedServer {
	if len(add) == 0 {
		return existing
	}
	seen := map[string]bool{}
	for _, server := range existing {
		seen[server.Name] = true
	}
	out := append([]NamedServer{}, existing...)
	for _, server := range add {
		if seen[server.Name] {
			continue
		}
		out = append(out, server)
		seen[server.Name] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func nonGatewayServers(servers map[string]ServerEntry) []NamedServer {
	out := make([]NamedServer, 0, len(servers))
	for name, entry := range servers {
		if name == GatewayServerName {
			continue
		}
		out = append(out, NamedServer{Name: name, Entry: entry})
	}
	return out
}

func pruneNativeKeptFromGatewayConfig(kept []NamedServer) {
	if len(kept) == 0 {
		return
	}
	cfg, err := config.Load()
	if err != nil {
		return
	}
	keptByNameURL := map[string]bool{}
	for _, server := range kept {
		if server.Name == "" || server.Entry.URL == "" {
			continue
		}
		keptByNameURL[server.Name+"\x00"+server.Entry.URL] = true
	}
	if len(keptByNameURL) == 0 {
		return
	}
	filtered := make([]config.ServerEntry, 0, len(cfg.Servers))
	changed := false
	for _, server := range cfg.Servers {
		key := server.Name + "\x00" + server.URL
		if keptByNameURL[key] && nativeauth.RequiresNativeClientAuth(server.Transport, server.URL, server.Headers) {
			changed = true
			continue
		}
		filtered = append(filtered, server)
	}
	if !changed {
		return
	}
	cfg.Servers = filtered
	_ = config.Save(cfg)
}
