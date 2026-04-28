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
	"time"
)

// GatewayServerName is the key this package writes under `mcpServers`. It is
// also how we detect "already wired" idempotency — an IDE config whose only
// MCP entry has this name and our exact shape is a no-op.
const GatewayServerName = "agentkeeper-mcp-gateway"

// gatewayCommand is the command we write into the IDE config. Kept short and
// PATH-relative so it works on every laptop that ran our install script.
const gatewayCommand = "agentkeeper-mcp-gateway"

// backupSuffix is appended (with a timestamp) to the original path when we
// back up before rewriting.
const backupSuffix = ".agentkeeper-backup-"

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
	Name         string                   // "claude-code", "claude-desktop", "cursor"
	PathResolver func() (string, error)   // returns the per-OS path for this IDE
}

// Plan describes what Apply would do for a single IDE, in one struct so the
// command layer can render a summary and the caller can run --dry-run safely.
type Plan struct {
	IDE          string
	ConfigPath   string
	Exists       bool          // did the file exist when Plan was built
	AlreadyWired bool          // gateway is the sole MCP entry already
	Migrated     []NamedServer // servers we'd move into the gateway's own config
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
			if runtime.GOOS == "darwin" {
				return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
			}
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		},
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
		Command: gatewayCommand,
		Args:    []string{"server"},
	}
}

// isGatewayEntry reports whether an entry matches our canonical shape. The
// command must resolve (by basename) to the gateway binary — a developer who
// installed via `go install` will have a full home-dir path, which is still
// a correct wiring, so we don't require a bare command name. Args must match
// exactly to catch half-configured entries.
func isGatewayEntry(e ServerEntry) bool {
	if filepath.Base(e.Command) != gatewayCommand {
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

	// Idempotency: exactly one entry, and it's our gateway.
	if len(servers) == 1 {
		if entry, ok := servers[GatewayServerName]; ok && isGatewayEntry(entry) {
			p.AlreadyWired = true
			return p, nil
		}
	}

	// Collect everything except any existing gateway entry — that one gets
	// replaced, not migrated (the gateway is not itself an MCP server).
	for name, entry := range servers {
		if name == GatewayServerName {
			continue
		}
		p.Migrated = append(p.Migrated, NamedServer{Name: name, Entry: entry})
	}

	return p, nil
}

// Apply executes a Plan: backs up the existing file (if any), then writes the
// new IDE config with the gateway as the sole entry under `mcpServers`.
// Already-wired plans are a no-op. All unknown top-level keys are preserved.
//
// Takes *Plan so the BackupPath side-effect is visible to the caller (the
// command layer renders it in the summary; tests assert on it).
//
// Apply does NOT move migrated servers into the gateway's own config — that is
// the caller's responsibility, because doing it here would couple this package
// to internal/config and create a cycle for future tests.
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
		backup := p.ConfigPath + backupSuffix + fmt.Sprintf("%d", time.Now().UnixNano())
		if err := os.WriteFile(backup, data, 0o644); err != nil {
			return fmt.Errorf("writing backup %s: %w", backup, err)
		}
		p.BackupPath = backup
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}

	newServers := map[string]ServerEntry{GatewayServerName: gatewayEntry()}
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
	return nil
}
