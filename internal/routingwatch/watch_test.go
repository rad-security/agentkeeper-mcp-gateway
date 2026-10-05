package routingwatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/manualrouting"
)

const testClient = discovery.ClientClaudeCode

// harness is a developer home with a routed Claude Code config and a private
// Gateway config, plus a controllable clock, mode and log.
type harness struct {
	t          *testing.T
	home       string
	project    string
	gatewayBin string
	configPath string
	now        time.Time
	enforce    atomic.Bool
	changes    atomic.Int32
	mu         sync.Mutex
	logs       []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	h := &harness{
		t:       t,
		home:    home,
		project: filepath.Join(home, "work", "notes-app"),
		now:     time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC),
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	h.configPath = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
	t.Setenv("AGENTKEEPER_CONFIG", h.configPath)
	t.Setenv("AGENTKEEPER_BACKUP_DIR", "")
	h.gatewayBin = filepath.Join(home, "bin", "agentkeeper-mcp-gateway")
	t.Setenv(gatewayentry.EnvBinary, h.gatewayBin)
	if err := os.MkdirAll(h.project, 0o755); err != nil {
		t.Fatal(err)
	}
	h.writeFile(h.configPath, `{"mode": "audit", "servers": []}`)
	return h
}

func (h *harness) clock() time.Time { return h.now }

func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

func (h *harness) logf(format string, args ...interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, fmt.Sprintf(format, args...))
}

func (h *harness) logText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.logs, "\n")
}

func (h *harness) watcher(configure ...func(*Options)) *Watcher {
	h.t.Helper()
	opts := Options{
		Client:    testClient,
		CWD:       h.project,
		Interval:  time.Hour,
		Debounce:  20 * time.Millisecond,
		Enforce:   h.enforce.Load,
		AutoRoute: true,
		OnChange:  func() { h.changes.Add(1) },
		Logf:      h.logf,
		Now:       h.clock,
	}
	for _, apply := range configure {
		apply(&opts)
	}
	w, err := New(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(w.Stop)
	return w
}

func (h *harness) claudeJSONPath() string { return filepath.Join(h.home, ".claude.json") }

func (h *harness) gatewayEntry() map[string]interface{} {
	return map[string]interface{}{
		"command": h.gatewayBin,
		"args":    []interface{}{"server"},
		"env":     map[string]interface{}{gatewayentry.EnvClientName: testClient},
	}
}

// writeRoutedClaudeJSON writes a ~/.claude.json the way configure-ide leaves
// it: the Gateway entry, a native OAuth server and a server already present
// before this process started, with attested routes.
func (h *harness) writeRoutedClaudeJSON() {
	h.t.Helper()
	h.writeAttested(h.claudeJSONPath(), map[string]interface{}{
		"numStartups": 7,
		"theme":       "dark",
		"mcpServers": map[string]interface{}{
			ideconfig.GatewayServerName: h.gatewayEntry(),
			"calendar-sso":              map[string]interface{}{"type": "http", "url": "https://mcp.example.com/calendar"},
			"notes-local":               map[string]interface{}{"command": "notes-mcp", "args": []interface{}{"--stdio"}},
		},
		"projects": map[string]interface{}{
			h.project:            map[string]interface{}{"allowedTools": []interface{}{}, "mcpServers": map[string]interface{}{}},
			"/srv/other-project": map[string]interface{}{"mcpServers": map[string]interface{}{"ticket-tracker": map[string]interface{}{"command": "tickets-mcp"}}},
		},
	})
}

func (h *harness) writeAttested(path string, document map[string]interface{}) {
	h.t.Helper()
	h.writeAttestedFor(testClient, path, document)
}

func (h *harness) writeAttestedFor(client, path string, document map[string]interface{}) {
	h.t.Helper()
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	attested, _, _, err := gatewayentry.AttestRoutes(client, data)
	if err != nil {
		h.t.Fatal(err)
	}
	h.writeFile(path, string(attested))
}

func (h *harness) writeFile(path, body string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) readFile(path string) []byte {
	h.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	return data
}

func (h *harness) readJSON(path string) map[string]interface{} {
	h.t.Helper()
	var document map[string]interface{}
	if err := json.Unmarshal(h.readFile(path), &document); err != nil {
		h.t.Fatal(err)
	}
	return document
}

// edit changes a client config as the client itself would: read, change,
// write back.
func (h *harness) edit(path string, change func(document map[string]interface{})) {
	h.t.Helper()
	document := h.readJSON(path)
	change(document)
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	h.writeFile(path, string(data))
}

func serverMapAt(document map[string]interface{}, project string) map[string]interface{} {
	if project == "" {
		servers, _ := document["mcpServers"].(map[string]interface{})
		return servers
	}
	projects, _ := document["projects"].(map[string]interface{})
	settings, _ := projects[project].(map[string]interface{})
	servers, _ := settings["mcpServers"].(map[string]interface{})
	return servers
}

func (h *harness) addServer(path, project, name string, entry map[string]interface{}) {
	h.t.Helper()
	h.edit(path, func(document map[string]interface{}) {
		if project == "" {
			servers, _ := document["mcpServers"].(map[string]interface{})
			if servers == nil {
				servers = map[string]interface{}{}
				document["mcpServers"] = servers
			}
			servers[name] = entry
			return
		}
		projects, _ := document["projects"].(map[string]interface{})
		if projects == nil {
			projects = map[string]interface{}{}
			document["projects"] = projects
		}
		settings, _ := projects[project].(map[string]interface{})
		if settings == nil {
			settings = map[string]interface{}{}
			projects[project] = settings
		}
		servers, _ := settings["mcpServers"].(map[string]interface{})
		if servers == nil {
			servers = map[string]interface{}{}
			settings["mcpServers"] = servers
		}
		servers[name] = entry
	})
}

func (h *harness) gatewayServers() map[string]config.ServerEntry {
	h.t.Helper()
	cfg, err := config.LoadWithPath(h.configPath)
	if err != nil {
		h.t.Fatal(err)
	}
	servers := map[string]config.ServerEntry{}
	for _, server := range cfg.Servers {
		servers[server.Name] = server
	}
	return servers
}

func (h *harness) backups() []string {
	h.t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(h.configPath), "backups", "*"))
	if err != nil {
		h.t.Fatal(err)
	}
	return matches
}

func reported(t *testing.T, w *Watcher, name, scope string) Server {
	t.Helper()
	for _, server := range w.Servers() {
		if server.Name == name && server.Scope == scope {
			return server
		}
	}
	t.Fatalf("%s (%s) not reported: %+v", name, scope, w.Servers())
	return Server{}
}

func notReported(t *testing.T, w *Watcher, name string) {
	t.Helper()
	for _, server := range w.Servers() {
		if server.Name == name {
			t.Fatalf("%s reported: %+v", name, server)
		}
	}
}

func eventually(t *testing.T, within time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

func TestClassifiesDirectServersAndServersAddedAfterStart(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.writeFile(filepath.Join(h.project, ".mcp.json"), `{"mcpServers": {"lint-tools": {"command": "lint-mcp"}}}`)
	started := h.now
	w := h.watcher()
	w.Scan()

	notReported(t, w, ideconfig.GatewayServerName)
	if got := reported(t, w, "calendar-sso", "user"); got.DirectReason != ReasonOAuth || got.RouteState != discovery.RouteDirect {
		t.Fatalf("OAuth server: %+v", got)
	}
	for _, check := range []struct{ name, scope string }{{"notes-local", "user"}, {"lint-tools", "project"}, {"ticket-tracker", "local"}} {
		got := reported(t, w, check.name, check.scope)
		if got.DirectReason != "" || !got.FirstSeenAt.Equal(started) {
			t.Fatalf("server present at start: %+v", got)
		}
	}
	if got := reported(t, w, "lint-tools", "project"); got.SourceKind != "project_mcp_json" || !got.Routable {
		t.Fatalf("project .mcp.json server identity: %+v", got)
	}

	h.advance(10 * time.Second)
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp", "env": map[string]interface{}{"WEATHER_TOKEN": "synthetic-token"}})
	h.addServer(h.claudeJSONPath(), h.project, "search", map[string]interface{}{"command": "search-mcp"})
	h.addServer(h.claudeJSONPath(), "/srv/new-project", "docs", map[string]interface{}{"command": "docs-mcp"})
	w.Scan()

	weather := reported(t, w, "weather", "user")
	if weather.DirectReason != ReasonAddedAfterSetup || !weather.FirstSeenAt.Equal(started.Add(10*time.Second)) {
		t.Fatalf("server added after start: %+v", weather)
	}
	if len(weather.EnvKeys) != 1 || weather.EnvKeys[0] != "WEATHER_TOKEN" {
		t.Fatalf("env keys: %+v", weather.EnvKeys)
	}
	encoded, _ := json.Marshal(w.Servers())
	if strings.Contains(string(encoded), "synthetic-token") {
		t.Fatalf("an env value reached the report: %s", encoded)
	}
	for _, name := range []string{"search", "docs"} {
		if got := reported(t, w, name, "local"); got.DirectReason != ReasonAddedAfterSetup || got.SourceKind != "claude_json_project" {
			t.Fatalf("project server added after start: %+v", got)
		}
	}
	if got := reported(t, w, "notes-local", "user"); got.DirectReason != "" {
		t.Fatalf("an unchanged server was reclassified: %+v", got)
	}
	if !eventually(t, time.Second, func() bool { return h.changes.Load() == 1 }) {
		t.Fatalf("change notifications = %d, want 1 (the first scan reports through the first sync)", h.changes.Load())
	}
}

func TestSetupRecordMarksServersMissingFromTheRoutedFile(t *testing.T) {
	h := newHarness(t)
	// What configure-ide found: notes-local, which it moved into the Gateway,
	// and pinned, which it kept in the client for a field the Gateway does not
	// model.
	original := `{"mcpServers": {"notes-local": {"command": "notes-mcp"}, "pinned": {"command": "pinned-mcp", "cwd": "/srv/pinned"}}}`
	h.writeAttested(h.claudeJSONPath(), map[string]interface{}{
		"mcpServers": map[string]interface{}{
			ideconfig.GatewayServerName: h.gatewayEntry(),
			"pinned":                    map[string]interface{}{"command": "pinned-mcp", "cwd": "/srv/pinned"},
		},
	})
	if err := manualrouting.Adopt(manualrouting.AdoptOptions{
		Client: testClient, Path: h.claudeJSONPath(), OriginalExists: true, Original: []byte(original),
	}); err != nil {
		t.Fatal(err)
	}
	// Later, with no Gateway running: a new server, and the moved one put
	// back directly.
	h.addServer(h.claudeJSONPath(), "", "late", map[string]interface{}{"command": "late-mcp"})
	h.addServer(h.claudeJSONPath(), "", "notes-local", map[string]interface{}{"command": "notes-mcp"})

	w := h.watcher()
	w.Scan()
	for _, name := range []string{"late", "notes-local"} {
		if got := reported(t, w, name, "user"); got.DirectReason != ReasonAddedAfterSetup {
			t.Fatalf("%s is in the routed file but was not left there by setup: %+v", name, got)
		}
	}
	if got := reported(t, w, "pinned", "user"); got.DirectReason != "" || got.Routable {
		t.Fatalf("a server setup left in the client: %+v", got)
	}
}

func TestReportsInstalledClaudeCodePluginServersAndNeverRoutesThem(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	plugin := filepath.Join(h.home, ".claude", "plugins", "cache", "example-market", "release-notes", "1.0.0")
	h.writeFile(filepath.Join(plugin, ".mcp.json"), `{"changelog": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/changelog-mcp", "env": {"CHANGELOG_TOKEN": "synthetic"}}}`)
	manifest, _ := json.Marshal(map[string]interface{}{
		"version": 2,
		"plugins": map[string]interface{}{"release-notes@example-market": []interface{}{map[string]interface{}{"scope": "user", "installPath": plugin}}},
	})
	h.writeFile(filepath.Join(h.home, ".claude", "plugins", "installed_plugins.json"), string(manifest))
	pluginBefore := h.readFile(filepath.Join(plugin, ".mcp.json"))

	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	got := reported(t, w, "changelog", "plugin")
	if got.DirectReason != ReasonPlugin || got.Routable || got.SourceKind != discovery.SourceKindClaudeCodePlugin || got.Routeability != discovery.RouteabilityClaudeCodePlugin {
		t.Fatalf("plugin server: %+v", got)
	}
	w.tick()
	if !bytes.Equal(h.readFile(filepath.Join(plugin, ".mcp.json")), pluginBefore) || len(h.gatewayServers()) != 0 {
		t.Fatal("a plugin server was routed")
	}
}

func TestDebouncesChangeNotifications(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	w := h.watcher(func(opts *Options) { opts.Debounce = 150 * time.Millisecond })
	w.Scan()
	time.Sleep(300 * time.Millisecond)
	if got := h.changes.Load(); got != 0 {
		t.Fatalf("the first scan notified %d time(s)", got)
	}
	for i := 0; i < 3; i++ {
		h.addServer(h.claudeJSONPath(), "", fmt.Sprintf("burst-%d", i), map[string]interface{}{"command": "burst-mcp"})
		w.Scan()
	}
	if !eventually(t, 2*time.Second, func() bool { return h.changes.Load() == 1 }) {
		t.Fatalf("a burst of changes notified %d times, want 1", h.changes.Load())
	}
	time.Sleep(300 * time.Millisecond)
	if got := h.changes.Load(); got != 1 {
		t.Fatalf("notifications after the burst settled = %d, want 1", got)
	}
	w.Scan()
	time.Sleep(300 * time.Millisecond)
	if got := h.changes.Load(); got != 1 {
		t.Fatalf("a scan without changes notified (%d)", got)
	}
	h.addServer(h.claudeJSONPath(), "", "later", map[string]interface{}{"command": "later-mcp"})
	w.Scan()
	if !eventually(t, 2*time.Second, func() bool { return h.changes.Load() == 2 }) {
		t.Fatalf("a later change notified %d times in total, want 2", h.changes.Load())
	}
}

func TestStatFirstWithPeriodicContentCheck(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	path := h.claudeJSONPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	w := h.watcher()
	w.Scan()

	// The same size and modification time: invisible to a stat.
	rewritten := bytes.Replace(h.readFile(path), []byte(`"notes-local"`), []byte(`"notes-renam"`), 1)
	h.writeFile(path, string(rewritten))
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	w.Scan()
	reported(t, w, "notes-local", "user")

	h.advance(verifyInterval + time.Second)
	w.Scan()
	notReported(t, w, "notes-local")
	reported(t, w, "notes-renam", "user")
}

func TestKeepsTheLastStateOfAnUnreadableFile(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	w := h.watcher()
	w.Scan()
	h.writeFile(h.claudeJSONPath(), `{"mcpServers": {"half-writ`)
	w.Scan()
	reported(t, w, "notes-local", "user")
	h.writeRoutedClaudeJSON()
	w.Scan()
	if got := reported(t, w, "notes-local", "user"); got.DirectReason != "" {
		t.Fatalf("a server that was never gone was reclassified: %+v", got)
	}
}

func TestObserveNeverWrites(t *testing.T) {
	for name, configure := range map[string]func(*harness, *Options){
		"observe":                   func(h *harness, _ *Options) { h.enforce.Store(false) },
		"enforce without autoroute": func(h *harness, opts *Options) { h.enforce.Store(true); opts.AutoRoute = false },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.writeRoutedClaudeJSON()
			w := h.watcher(func(opts *Options) { configure(h, opts) })
			w.Scan()
			h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp"})
			clientBefore, gatewayBefore := h.readFile(h.claudeJSONPath()), h.readFile(h.configPath)
			for i := 0; i < 3; i++ {
				w.tick()
				h.advance(DefaultInterval)
			}
			if !bytes.Equal(h.readFile(h.claudeJSONPath()), clientBefore) || !bytes.Equal(h.readFile(h.configPath), gatewayBefore) {
				t.Fatal("a client or Gateway config was written")
			}
			if len(h.backups()) != 0 {
				t.Fatalf("backups written: %v", h.backups())
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(h.configPath), config.ManualRoutingManifestName)); !os.IsNotExist(err) {
				t.Fatalf("ownership manifest written: %v", err)
			}
			if got := reported(t, w, "weather", "user"); got.DirectReason != ReasonAddedAfterSetup || got.RouteState != discovery.RouteDirect {
				t.Fatalf("weather: %+v", got)
			}
		})
	}
}

func TestEnforceRoutesAServerAddedAfterSetupReversibly(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	h.advance(5 * time.Second)
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp", "args": []interface{}{"--units", "metric"}, "env": map[string]interface{}{"WEATHER_TOKEN": "synthetic-token"}})
	beforeRoute := h.readFile(h.claudeJSONPath())
	w.tick()

	routedBytes := h.readFile(h.claudeJSONPath())
	document := h.readJSON(h.claudeJSONPath())
	servers := serverMapAt(document, "")
	if _, still := servers["weather"]; still {
		t.Fatalf("weather is still direct: %s", routedBytes)
	}
	for _, kept := range []string{"calendar-sso", "notes-local", ideconfig.GatewayServerName} {
		if _, ok := servers[kept]; !ok {
			t.Fatalf("%s was removed: %s", kept, routedBytes)
		}
	}
	if document["theme"] != "dark" || document["numStartups"] != float64(7) {
		t.Fatalf("unrelated settings changed: %s", routedBytes)
	}
	if _, ok := serverMapAt(document, "/srv/other-project")["ticket-tracker"]; !ok {
		t.Fatalf("another project's server was touched: %s", routedBytes)
	}
	gateway, _ := servers[ideconfig.GatewayServerName].(map[string]interface{})
	env, _ := gateway["env"].(map[string]interface{})
	sourceHash, revision := gatewayentry.RouteIdentity(testClient, routedBytes)
	if env[gatewayentry.EnvConfigSourceHash] != sourceHash || env[gatewayentry.EnvRouteRevision] != revision {
		t.Fatalf("route attestation does not match the written file: %v", env)
	}

	installed, ok := h.gatewayServers()["weather"]
	if !ok || installed.Command != "weather-mcp" || installed.Transport != "stdio" || installed.Env["WEATHER_TOKEN"] != "synthetic-token" || len(installed.Args) != 2 {
		t.Fatalf("Gateway config entry: %+v (present %v)", installed, ok)
	}
	backups := h.backups()
	if len(backups) != 1 || !bytes.Equal(h.readFile(backups[0]), beforeRoute) {
		t.Fatalf("backups %v do not hold the pre-route bytes", backups)
	}
	record, found, err := manualrouting.ReadSetupRecord(h.claudeJSONPath())
	if err != nil || !found || !record.Migrated["weather"] {
		t.Fatalf("ownership record: %+v found=%v err=%v", record, found, err)
	}

	got := reported(t, w, "weather", "user")
	if got.RouteState != RouteStatePendingRestart || !got.GatewayCovered || got.GatewayName != "weather" || got.DirectReason != ReasonAddedAfterSetup || !got.FirstSeenAt.Equal(h.now) {
		t.Fatalf("routed server report: %+v", got)
	}
	// The ownership record the route wrote does not turn the servers it left
	// alone into servers added after setup.
	for _, check := range []struct{ name, scope string }{{"notes-local", "user"}, {"ticket-tracker", "local"}} {
		if got := reported(t, w, check.name, check.scope); got.DirectReason != "" || got.RouteState != discovery.RouteDirect {
			t.Fatalf("%s after the route: %+v", check.name, got)
		}
	}
	if !strings.Contains(h.logText(), `routed MCP server "weather"`) || strings.Count(h.logText(), "routed MCP server") != 1 {
		t.Fatalf("log: %s", h.logText())
	}
	if !eventually(t, time.Second, func() bool { return h.changes.Load() >= 1 }) {
		t.Fatal("routing was not announced")
	}
	w.tick()
	if strings.Count(h.logText(), "routed MCP server") != 1 || len(h.backups()) != 1 {
		t.Fatalf("a routed server was routed again: %s", h.logText())
	}

	// configure-ide --remove-routing undoes the route: the client gets the
	// server back as it was, and the Gateway config loses it.
	if _, err := manualrouting.Remove(manualrouting.RemoveOptions{Clients: []string{testClient}}); err != nil {
		t.Fatal(err)
	}
	restored := h.readJSON(h.claudeJSONPath())
	var original map[string]interface{}
	if err := json.Unmarshal(beforeRoute, &original); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(serverMapAt(restored, "")["weather"]) != fmt.Sprint(serverMapAt(original, "")["weather"]) {
		t.Fatalf("rollback did not restore weather: %v", serverMapAt(restored, "")["weather"])
	}
	if _, ok := serverMapAt(restored, "")[ideconfig.GatewayServerName]; ok {
		t.Fatal("rollback kept the Gateway entry")
	}
	if _, ok := serverMapAt(restored, "")["calendar-sso"]; !ok || restored["theme"] != "dark" {
		t.Fatalf("rollback lost unrelated content: %v", restored)
	}
	if _, still := h.gatewayServers()["weather"]; still {
		t.Fatal("rollback left the routed server in the Gateway config")
	}
}

func TestEnforceRoutesAProjectScopedServer(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	h.addServer(h.claudeJSONPath(), h.project, "search", map[string]interface{}{"command": "search-mcp"})
	w.tick()

	document := h.readJSON(h.claudeJSONPath())
	project := serverMapAt(document, h.project)
	if _, still := project["search"]; still {
		t.Fatal("search is still direct")
	}
	gateway, _ := project[ideconfig.GatewayServerName].(map[string]interface{})
	if gateway["command"] != h.gatewayBin {
		t.Fatalf("the routed project has no Gateway entry: %v", project)
	}
	if _, ok := serverMapAt(document, "/srv/other-project")[ideconfig.GatewayServerName]; ok {
		t.Fatal("a project nothing was routed from gained a Gateway entry")
	}
	if _, ok := h.gatewayServers()["search"]; !ok {
		t.Fatal("search is not in the Gateway config")
	}
	if got := reported(t, w, "search", "local"); got.RouteState != RouteStatePendingRestart {
		t.Fatalf("search: %+v", got)
	}
}

func TestConcurrentEditIsNeverClobbered(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp"})

	interfered := 0
	beforeReplace = func(path string) {
		interfered++
		// The client writes its own state between the read and the rename.
		h.edit(path, func(document map[string]interface{}) { document["lastSessionId"] = "session-synthetic-1" })
	}
	t.Cleanup(func() { beforeReplace = nil })
	w.tick()
	beforeReplace = nil

	document := h.readJSON(h.claudeJSONPath())
	if interfered != 1 || document["lastSessionId"] != "session-synthetic-1" {
		t.Fatalf("the concurrent write was lost (hook ran %d times)", interfered)
	}
	if _, ok := serverMapAt(document, "")["weather"]; !ok {
		t.Fatal("weather left the client although the edit was abandoned")
	}
	if _, ok := h.gatewayServers()["weather"]; ok {
		t.Fatal("the abandoned edit left weather in the Gateway config")
	}
	if len(h.backups()) != 0 {
		t.Fatalf("the abandoned edit left a backup: %v", h.backups())
	}
	if got := reported(t, w, "weather", "user"); got.RouteState != discovery.RouteDirect {
		t.Fatalf("weather after a conflict: %+v", got)
	}

	// The next tick starts again from the client's latest bytes.
	h.advance(DefaultInterval)
	w.tick()
	document = h.readJSON(h.claudeJSONPath())
	if _, ok := serverMapAt(document, "")["weather"]; ok {
		t.Fatal("weather was not routed on retry")
	}
	if document["lastSessionId"] != "session-synthetic-1" {
		t.Fatal("the retry discarded the client's write")
	}
}

func TestGivesUpAfterThreeAttempts(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp"})

	attempts := 0
	beforeReplace = func(path string) {
		attempts++
		h.edit(path, func(document map[string]interface{}) {
			document["lastSessionId"] = fmt.Sprintf("session-synthetic-%d", attempts)
		})
	}
	t.Cleanup(func() { beforeReplace = nil })
	for i := 0; i < 5; i++ {
		w.tick()
		h.advance(DefaultInterval)
	}
	if attempts != maxRouteAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, maxRouteAttempts)
	}
	if !strings.Contains(h.logText(), "after 3 attempts") || strings.Count(h.logText(), "could not route") != 1 {
		t.Fatalf("log: %s", h.logText())
	}
	if _, ok := serverMapAt(h.readJSON(h.claudeJSONPath()), "")["weather"]; !ok {
		t.Fatal("weather left the client")
	}
	if len(h.gatewayServers()) != 0 {
		t.Fatalf("Gateway config changed: %v", h.gatewayServers())
	}
}

func TestServersThatMustStayDirectAreReportedNotRouted(t *testing.T) {
	cases := map[string]struct {
		setup  func(h *harness)
		add    func(h *harness)
		name   string
		file   func(h *harness) string
		logged string
	}{
		"client-only field": {
			setup: func(h *harness) { h.writeRoutedClaudeJSON() },
			add: func(h *harness) {
				h.addServer(h.claudeJSONPath(), "", "pinned", map[string]interface{}{"command": "pinned-mcp", "cwd": "/srv/pinned"})
			},
			name:   "pinned",
			file:   func(h *harness) string { return h.claudeJSONPath() },
			logged: "keeps it in the client",
		},
		"oauth": {
			setup: func(h *harness) { h.writeRoutedClaudeJSON() },
			add: func(h *harness) {
				h.addServer(h.claudeJSONPath(), "", "wiki", map[string]interface{}{"type": "http", "url": "https://mcp.example.com/wiki"})
			},
			name: "wiki",
			file: func(h *harness) string { return h.claudeJSONPath() },
		},
		"unrouted project file": {
			setup: func(h *harness) {
				h.writeRoutedClaudeJSON()
				h.writeFile(filepath.Join(h.project, ".mcp.json"), `{"mcpServers": {}}`)
			},
			add: func(h *harness) {
				h.addServer(filepath.Join(h.project, ".mcp.json"), "", "lint-tools", map[string]interface{}{"command": "lint-mcp"})
			},
			name: "lint-tools",
			file: func(h *harness) string { return filepath.Join(h.project, ".mcp.json") },
		},
		"project file in a git repository": {
			setup: func(h *harness) {
				h.writeRoutedClaudeJSON()
				if err := os.MkdirAll(filepath.Join(h.project, ".git"), 0o755); err != nil {
					t.Fatal(err)
				}
				h.writeAttested(filepath.Join(h.project, ".mcp.json"), map[string]interface{}{"mcpServers": map[string]interface{}{ideconfig.GatewayServerName: h.gatewayEntry()}})
			},
			add: func(h *harness) {
				h.addServer(filepath.Join(h.project, ".mcp.json"), "", "lint-tools", map[string]interface{}{"command": "lint-mcp"})
			},
			name:   "lint-tools",
			file:   func(h *harness) string { return filepath.Join(h.project, ".mcp.json") },
			logged: "inside a git repository",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h)
			h.enforce.Store(true)
			w := h.watcher()
			w.Scan()
			tc.add(h)
			before, gatewayBefore := h.readFile(tc.file(h)), h.readFile(h.configPath)
			w.tick()
			w.tick()
			if !bytes.Equal(h.readFile(tc.file(h)), before) || !bytes.Equal(h.readFile(h.configPath), gatewayBefore) {
				t.Fatal("a server that must stay direct was routed")
			}
			for _, server := range w.Servers() {
				if server.Name == tc.name && server.RouteState != discovery.RouteDirect {
					t.Fatalf("%s: %+v", tc.name, server)
				}
			}
			if tc.logged != "" && strings.Count(h.logText(), tc.logged) != 1 {
				t.Fatalf("expected one %q line: %s", tc.logged, h.logText())
			}
		})
	}
}

func TestAStaleGatewayEntryIsNeverTreatedAsDirect(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.enforce.Store(true)
	w := h.watcher()
	w.Scan()
	h.addServer(h.claudeJSONPath(), "", "old-gateway", map[string]interface{}{"command": "/opt/legacy/agentkeeper-mcp-gateway", "args": []interface{}{"server"}})
	w.tick()
	notReported(t, w, "old-gateway")
	if len(h.gatewayServers()) != 0 {
		t.Fatal("a Gateway entry was moved into the Gateway config")
	}
}

func TestRouteSkipsAServerChangedSinceItWasClassified(t *testing.T) {
	h := newHarness(t)
	h.writeRoutedClaudeJSON()
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp"})
	servers, err := discovery.ParseClientConfig(discovery.ClaudeJSONFile(h.home), h.readFile(h.claudeJSONPath()))
	if err != nil {
		t.Fatal(err)
	}
	var classified discovery.DiscoveredServer
	for _, server := range servers {
		if server.Name == "weather" {
			classified = server
		}
	}
	h.addServer(h.claudeJSONPath(), "", "weather", map[string]interface{}{"command": "weather-mcp", "args": []interface{}{"--changed"}})
	before := h.readFile(h.claudeJSONPath())
	result, err := routeServers(testClient, discovery.ClaudeJSONFile(h.home), []discovery.DiscoveredServer{classified})
	if err != nil || len(result.routed) != 0 {
		t.Fatalf("result %+v err %v", result, err)
	}
	if !bytes.Equal(h.readFile(h.claudeJSONPath()), before) || len(h.gatewayServers()) != 0 || len(h.backups()) != 0 {
		t.Fatal("a changed server was routed")
	}
}

func TestUnsupportedClients(t *testing.T) {
	newHarness(t)
	for _, client := range []string{"", "cowork", "codex"} {
		if _, err := New(Options{Client: client}); err == nil {
			t.Fatalf("client %q: no error", client)
		}
	}
	for _, client := range []string{"claude-desktop", "cursor", "windsurf", "gemini-cli", "antigravity", "kiro"} {
		if _, err := New(Options{Client: client}); err != nil {
			t.Fatalf("client %q: %v", client, err)
		}
	}
}

func TestWatchesOtherClientsThroughTheirConfigureIDEPath(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.home, ".cursor", "mcp.json")
	h.writeAttestedFor("cursor", path, map[string]interface{}{"mcpServers": map[string]interface{}{ideconfig.GatewayServerName: map[string]interface{}{
		"command": h.gatewayBin, "args": []interface{}{"server"}, "env": map[string]interface{}{gatewayentry.EnvClientName: "cursor"},
	}}})
	h.enforce.Store(true)
	w := h.watcher(func(opts *Options) { opts.Client = "cursor" })
	w.Scan()
	h.addServer(path, "", "weather", map[string]interface{}{"command": "weather-mcp"})
	w.tick()
	if got := reported(t, w, "weather", "global"); got.SourceKind != "cursor_mcp_json" || got.RouteState != RouteStatePendingRestart {
		t.Fatalf("cursor server: %+v", got)
	}
	if _, ok := serverMapAt(h.readJSON(path), "")["weather"]; ok {
		t.Fatal("weather is still in the Cursor config")
	}
}
