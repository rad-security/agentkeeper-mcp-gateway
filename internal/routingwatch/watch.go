// Package routingwatch keeps the MCP servers that reach a client without
// passing through the Gateway in view while the Gateway runs.
//
// The Gateway reads the client's config only when it starts, and a server
// added afterwards reaches the client directly the next time the client
// starts. The watch re-reads, every few seconds, the client config files
// configure-ide routes for the client this Gateway serves (a stat first; the
// contents only when a file changed) and, for Claude Code, the MCP servers of
// installed plugins. It classifies every direct server with why it is direct
// and when this process first saw it, and reports a change at once.
//
// In Enforce, a server added after setup to a file that carries a Gateway
// route is moved behind the Gateway the way configure-ide moves it. In
// Observe nothing is written.
package routingwatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/manualrouting"
)

// Why a server is direct.
const (
	// ReasonAddedAfterSetup: the server appeared after setup. It was first
	// seen after this Gateway process started, or the file's configure-ide
	// record shows it was not left in the client when the file was routed.
	ReasonAddedAfterSetup = "added_after_setup"
	// ReasonOAuth: a remote server the client authenticates itself, which
	// configure-ide leaves in the client by design.
	ReasonOAuth = "oauth"
	// ReasonPlugin: a server an installed client plugin provides.
	ReasonPlugin = "plugin"
)

// RouteStatePendingRestart is the route state of a server moved behind the
// Gateway while the client was running. The client keeps its direct
// connection until it restarts.
const RouteStatePendingRestart = "routed_pending_restart"

const (
	DefaultInterval = 5 * time.Second
	DefaultDebounce = 2 * time.Second

	// maxRouteAttempts bounds the routing transactions for one server.
	maxRouteAttempts = 3
	// verifyInterval forces a content check of a file whose size and
	// modification time look unchanged, which a same-size write within the
	// timestamp granularity would otherwise hide.
	verifyInterval = time.Minute
)

// ErrUnsupportedClient reports a client the watch has no config files for.
var ErrUnsupportedClient = errors.New("routing watch does not cover this client")

// Server is one MCP server the watch reports: a direct server, or one routed
// while the client still holds its direct connection.
type Server struct {
	discovery.DiscoveredServer
	// DirectReason is one of the Reason values, or empty.
	DirectReason string
	// FirstSeenAt is when this Gateway process first saw the server.
	FirstSeenAt time.Time
}

// Options configures a Watcher.
type Options struct {
	// Client is the client this Gateway serves (AGENTKEEPER_MCP_CLIENT).
	Client string
	// CWD is the project directory the client started the Gateway in.
	CWD string
	// Interval between checks and Debounce before OnChange; zero selects the
	// defaults.
	Interval time.Duration
	Debounce time.Duration
	// Enforce reports whether the route's effective mode is Enforce.
	Enforce func() bool
	// AutoRoute permits routing writes in Enforce. Managed deployments leave
	// routing to their own reconciler.
	AutoRoute bool
	// OnChange is called, debounced, when the reported servers change.
	OnChange func()
	// Logf prints a line for the operator; Debugf a verbose one.
	Logf   func(format string, args ...interface{})
	Debugf func(format string, args ...interface{})
	// Now is the clock; nil selects time.Now.
	Now func() time.Time
}

type fileStamp struct {
	exists bool
	size   int64
	mod    time.Time
}

func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileStamp{}, nil
	}
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{exists: true, size: info.Size(), mod: info.ModTime()}, nil
}

// source is one client config file and what the watch last knew of it.
type source struct {
	file     discovery.ClientConfigFile
	stamp    fileStamp
	verifyAt time.Time
	hash     string
	servers  []discovery.DiscoveredServer
	// known is set once servers reflect a parse, or the file's absence.
	known bool
	// baselined is set once the first known state has been taken: a server
	// first seen after that was added after this process started.
	baselined bool
	// routed reports that the file carries a Gateway entry.
	routed bool
	record *manualrouting.SetupRecord
}

// pluginSource is the set of files Claude Code plugin servers come from.
type pluginSource struct {
	home     string
	stamps   map[string]fileStamp
	verifyAt time.Time
	servers  []discovery.DiscoveredServer
	known    bool
}

type sighting struct {
	firstSeen  time.Time
	afterStart bool
}

// direct is one direct server with the file it sits in.
type direct struct {
	src    *source // nil for a plugin server
	server discovery.DiscoveredServer
	key    string
	reason string
}

// Watcher watches one client's MCP config files.
type Watcher struct {
	opts    Options
	sources []*source
	plugins *pluginSource

	manifestPath     string
	manifestStamp    fileStamp
	manifestKnown    bool
	manifestVerifyAt time.Time

	mu          sync.Mutex
	seen        map[string]sighting
	routed      map[string]Server
	attempts    map[string]int
	noted       map[string]bool
	directs     []direct
	report      []Server
	fingerprint string
	scanned     bool
	timer       *time.Timer

	startOnce sync.Once
	stopOnce  sync.Once
	started   bool
	stop      chan struct{}
	done      chan struct{}
}

// New returns a Watcher for the client this Gateway serves. It reads
// nothing until Scan.
func New(opts Options) (*Watcher, error) {
	client := strings.ToLower(strings.TrimSpace(opts.Client))
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Debounce <= 0 {
		opts.Debounce = DefaultDebounce
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...interface{}) {}
	}
	if opts.Debugf == nil {
		opts.Debugf = func(string, ...interface{}) {}
	}
	opts.Client = client
	w := &Watcher{
		opts:     opts,
		seen:     map[string]sighting{},
		routed:   map[string]Server{},
		attempts: map[string]int{},
		noted:    map[string]bool{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	switch client {
	case discovery.ClientClaudeCode:
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		w.sources = append(w.sources, &source{file: discovery.ClaudeJSONFile(home)})
		if cwd := strings.TrimSpace(opts.CWD); cwd != "" {
			if abs, err := filepath.Abs(cwd); err == nil {
				w.sources = append(w.sources, &source{file: discovery.ProjectMCPFile(abs)})
			}
		}
		w.plugins = &pluginSource{home: home}
	default:
		scope, sourceKind, ok := discovery.ClientSourceKind(client)
		var adapter *ideconfig.Adapter
		for _, candidate := range ideconfig.AllAdapters() {
			if candidate.Name == client {
				adapter = candidate
			}
		}
		if !ok || adapter == nil {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedClient, opts.Client)
		}
		path, err := adapter.PathResolver()
		if err != nil {
			return nil, err
		}
		w.sources = append(w.sources, &source{file: discovery.ClientConfigFile{Client: client, Path: path, Scope: scope, SourceKind: sourceKind}})
	}
	if path, err := manualrouting.ManifestPath(); err == nil {
		w.manifestPath = path
	}
	return w, nil
}

// Start checks the files every Interval, and in Enforce routes servers added
// after setup, until Stop.
func (w *Watcher) Start() {
	w.startOnce.Do(func() {
		w.mu.Lock()
		w.started = true
		w.mu.Unlock()
		go func() {
			defer close(w.done)
			ticker := time.NewTicker(w.opts.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					w.tick()
				case <-w.stop:
					return
				}
			}
		}()
	})
}

// Stop ends the checks and drops a pending change notification.
func (w *Watcher) Stop() {
	w.stopOnce.Do(func() {
		close(w.stop)
		w.mu.Lock()
		started := w.started
		w.mu.Unlock()
		if started {
			<-w.done
		}
		w.mu.Lock()
		if w.timer != nil {
			w.timer.Stop()
		}
		w.mu.Unlock()
	})
}

// Servers returns the servers the watch reports, as of the last check.
func (w *Watcher) Servers() []Server {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Server(nil), w.report...)
}

func (w *Watcher) tick() {
	w.Scan()
	w.routeAddedServers()
}

// Scan checks every watched file once and updates the report. A change after
// the first Scan is announced through OnChange.
func (w *Watcher) Scan() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scanLocked()
}

func (w *Watcher) scanLocked() {
	now := w.opts.Now()
	recordsChanged := w.refreshManifest(now)
	for _, src := range w.sources {
		w.refreshSource(src, now)
		if recordsChanged {
			w.loadRecord(src)
		}
	}
	if w.plugins != nil {
		w.refreshPlugins(now)
	}
	w.rebuildLocked()
	first := !w.scanned
	w.scanned = true
	if fingerprint := w.fingerprintLocked(); fingerprint != w.fingerprint {
		w.fingerprint = fingerprint
		if !first {
			w.changedLocked()
		}
	}
}

// refreshManifest reports whether the configure-ide ownership records are
// due a reload: the manifest changed, or its periodic content check is due.
func (w *Watcher) refreshManifest(now time.Time) bool {
	if w.manifestPath == "" {
		return false
	}
	stamp, err := stampOf(w.manifestPath)
	if err != nil {
		return false
	}
	due := !w.manifestKnown || stamp != w.manifestStamp || !now.Before(w.manifestVerifyAt)
	w.manifestStamp, w.manifestKnown = stamp, true
	if due {
		w.manifestVerifyAt = now.Add(verifyInterval)
	}
	return due
}

func (w *Watcher) loadRecord(src *source) {
	record, found, err := manualrouting.ReadSetupRecord(src.file.Path)
	if err != nil {
		w.noteOnce("record|"+src.file.Path, w.opts.Debugf, "routing watch: no configure-ide record used for %s: %v", src.file.Path, err)
	}
	if err != nil || !found {
		src.record = nil
		return
	}
	src.record = &record
}

// refreshSource re-reads a file whose stat changed, or that is due a
// content check. A file that cannot be read or parsed keeps its last known
// servers.
func (w *Watcher) refreshSource(src *source, now time.Time) {
	stamp, err := stampOf(src.file.Path)
	if err != nil {
		return
	}
	if !stamp.exists {
		src.stamp, src.hash, src.servers, src.routed = stamp, "", nil, false
		w.settleLocked(src, now)
		return
	}
	if src.known && stamp == src.stamp && now.Before(src.verifyAt) {
		return
	}
	data, err := os.ReadFile(src.file.Path)
	if err != nil {
		return
	}
	src.stamp, src.verifyAt = stamp, now.Add(verifyInterval)
	hash := gatewayentry.ContentHash(data)
	if hash == src.hash {
		return
	}
	src.hash = hash
	servers, err := discovery.ParseClientConfig(src.file, data)
	if err != nil {
		w.noteOnce("parse|"+src.file.Path, w.opts.Debugf, "routing watch: keeping the last readable state of %s: %v", src.file.Path, err)
		return
	}
	delete(w.noted, "parse|"+src.file.Path)
	src.servers, src.routed = servers, false
	for _, server := range servers {
		if isGatewayServer(server) {
			src.routed = true
		}
	}
	w.settleLocked(src, now)
}

// settleLocked records first sightings once a file's state is known. The
// first known state is the baseline: what it holds was there when this
// process started. A file absent at that point has an empty baseline.
func (w *Watcher) settleLocked(src *source, now time.Time) {
	src.known = true
	for _, server := range src.servers {
		if isGatewayServer(server) {
			continue
		}
		key := serverKey(server)
		if _, seen := w.seen[key]; !seen {
			w.seen[key] = sighting{firstSeen: now.UTC(), afterStart: src.baselined}
		}
	}
	src.baselined = true
}

func (w *Watcher) refreshPlugins(now time.Time) {
	plugins := w.plugins
	if plugins.known && !now.After(plugins.verifyAt) {
		unchanged := true
		for path, recorded := range plugins.stamps {
			stamp, err := stampOf(path)
			if err != nil || stamp != recorded {
				unchanged = false
				break
			}
		}
		if unchanged {
			return
		}
	}
	servers, files := discovery.ClaudeCodePluginServers(plugins.home)
	plugins.stamps = make(map[string]fileStamp, len(files))
	for _, path := range files {
		if stamp, err := stampOf(path); err == nil {
			plugins.stamps[path] = stamp
		}
	}
	plugins.servers, plugins.known, plugins.verifyAt = servers, true, now.Add(verifyInterval)
	for _, server := range servers {
		key := serverKey(server)
		if _, seen := w.seen[key]; !seen {
			w.seen[key] = sighting{firstSeen: now.UTC()}
		}
	}
}

// rebuildLocked classifies every direct server and composes the report:
// direct servers, then servers routed while the client still runs them.
func (w *Watcher) rebuildLocked() {
	present := map[string]bool{}
	var directs []direct
	for _, src := range w.sources {
		for _, server := range src.servers {
			if isGatewayServer(server) {
				continue
			}
			key := serverKey(server)
			present[key] = true
			directs = append(directs, direct{src: src, server: server, key: key, reason: w.reason(src, server, key)})
		}
	}
	if w.plugins != nil {
		for _, server := range w.plugins.servers {
			key := serverKey(server)
			present[key] = true
			directs = append(directs, direct{server: server, key: key, reason: ReasonPlugin})
		}
	}
	w.directs = directs

	report := make([]Server, 0, len(directs)+len(w.routed))
	for _, d := range directs {
		report = append(report, Server{DiscoveredServer: d.server, DirectReason: d.reason, FirstSeenAt: w.seen[d.key].firstSeen})
	}
	routedKeys := make([]string, 0, len(w.routed))
	for key := range w.routed {
		if present[key] {
			// Back in the client file: direct again.
			delete(w.routed, key)
			continue
		}
		routedKeys = append(routedKeys, key)
	}
	sort.Strings(routedKeys)
	for _, key := range routedKeys {
		report = append(report, w.routed[key])
	}
	w.report = w.dedupe(report)
}

func (w *Watcher) reason(src *source, server discovery.DiscoveredServer, key string) string {
	switch {
	case server.Routeability == discovery.RouteabilityNativeClientAuth:
		return ReasonOAuth
	case w.seen[key].afterStart:
		return ReasonAddedAfterSetup
	case src.record != nil && !leftDirectAtSetup(*src.record, server):
		return ReasonAddedAfterSetup
	default:
		return ""
	}
}

// leftDirectAtSetup reports whether routing the file left this server in the
// client: it was there when the route was made or last renewed, and the
// route did not move it into the Gateway.
func leftDirectAtSetup(record manualrouting.SetupRecord, server discovery.DiscoveredServer) bool {
	recorded := record.Servers
	if server.Project != "" {
		recorded = record.Projects[server.Project]
	}
	_, present := recorded[server.Name]
	return present && !record.Migrated[server.Name]
}

// dedupe keeps one entry per reported identity. Claude Code projects share
// one identity per server name; the project the client runs in is listed
// first, so its entry is the one kept.
func (w *Watcher) dedupe(report []Server) []Server {
	rank := func(server Server) int {
		if server.Project == "" {
			return 0
		}
		return projectRank(server.Project, w.opts.CWD)
	}
	sort.SliceStable(report, func(i, j int) bool {
		a, b := report[i], report[j]
		pendingA, pendingB := a.RouteState == RouteStatePendingRestart, b.RouteState == RouteStatePendingRestart
		if pendingA != pendingB {
			return !pendingA
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return a.Project < b.Project
	})
	seen := map[string]bool{}
	out := make([]Server, 0, len(report))
	for _, server := range report {
		identity := reportIdentity(server.DiscoveredServer)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		out = append(out, server)
	}
	return out
}

// projectRank orders Claude Code project keys as Discover matches them to
// the working directory: the exact project, then a related one, then others.
func projectRank(project, cwd string) int {
	if strings.TrimSpace(cwd) == "" {
		return 3
	}
	cleanCWD, cleanKey := filepath.Clean(cwd), filepath.Clean(project)
	switch {
	case cleanKey == cleanCWD:
		return 1
	case strings.HasPrefix(cleanCWD, cleanKey+string(os.PathSeparator)) || strings.HasPrefix(cleanKey, cleanCWD+string(os.PathSeparator)):
		return 2
	default:
		return 3
	}
}

func (w *Watcher) fingerprintLocked() string {
	parts := make([]string, 0, len(w.report))
	for _, server := range w.report {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%t|%s", reportIdentity(server.DiscoveredServer), server.RouteState, server.DirectReason, server.Routable, server.GatewayName))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// changedLocked announces a change once Debounce passes without another.
func (w *Watcher) changedLocked() {
	if w.opts.OnChange == nil {
		return
	}
	select {
	case <-w.stop:
		return
	default:
	}
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(w.opts.Debounce, w.opts.OnChange)
}

func (w *Watcher) noteOnce(key string, logf func(string, ...interface{}), format string, args ...interface{}) {
	if w.noted[key] {
		return
	}
	w.noted[key] = true
	logf(format, args...)
}

// routeAddedServers routes, in Enforce, every server added after setup that
// configure-ide would route, one transaction per client file.
func (w *Watcher) routeAddedServers() {
	if !w.opts.AutoRoute || w.opts.Enforce == nil || !w.opts.Enforce() {
		return
	}
	w.mu.Lock()
	batches := map[*source][]discovery.DiscoveredServer{}
	var order []*source
	for _, d := range w.directs {
		if d.src == nil || d.reason != ReasonAddedAfterSetup || w.attempts[d.key] >= maxRouteAttempts {
			continue
		}
		if _, done := w.routed[d.key]; done {
			continue
		}
		switch {
		case !d.src.routed:
			// Routing maintains an existing route. A file without one was
			// never routed, or its route was removed on purpose.
			w.noteOnce("unrouted|"+d.key, w.opts.Debugf, "routing watch: %q in %s stays direct: the file carries no Gateway route", d.server.Name, d.src.file.Path)
			continue
		case !d.server.Routable:
			w.noteOnce("native|"+d.key, w.opts.Logf, "routing watch: MCP server %q was added to %s after setup but configure-ide keeps it in the client (%s); it stays direct", d.server.Name, d.src.file.Path, d.server.Routeability)
			continue
		case d.src.file.SourceKind == "project_mcp_json" && discovery.InsideGitWorktree(d.src.file.Path):
			w.noteOnce("git|"+d.key, w.opts.Logf, "routing watch: MCP server %q was added to %s, inside a git repository; it stays direct (run configure-ide --cwd to route it)", d.server.Name, d.src.file.Path)
			continue
		}
		if _, queued := batches[d.src]; !queued {
			order = append(order, d.src)
		}
		batches[d.src] = append(batches[d.src], d.server)
	}
	w.mu.Unlock()

	for _, src := range order {
		servers := batches[src]
		result, err := routeServers(w.opts.Client, src.file, servers)
		w.mu.Lock()
		w.recordRouteLocked(src, servers, result, err)
		w.scanLocked()
		w.mu.Unlock()
	}
}

func (w *Watcher) recordRouteLocked(src *source, servers []discovery.DiscoveredServer, result routeResult, err error) {
	for _, server := range servers {
		key := serverKey(server)
		name, routed := result.routed[key]
		if err == nil && !routed {
			// Changed or gone since it was classified; the next check
			// classifies it again.
			continue
		}
		w.attempts[key]++
		if err != nil {
			if w.attempts[key] >= maxRouteAttempts {
				w.opts.Logf("routing watch: could not route MCP server %q in %s after %d attempts (%v); it stays direct until configure-ide is run", server.Name, src.file.Path, w.attempts[key], err)
			} else {
				w.opts.Debugf("routing watch: routing %q in %s will be retried: %v", server.Name, src.file.Path, err)
			}
			continue
		}
		pending := server
		pending.RouteState = RouteStatePendingRestart
		pending.GatewayCovered = true
		pending.GatewayName = name
		w.routed[key] = Server{DiscoveredServer: pending, DirectReason: ReasonAddedAfterSetup, FirstSeenAt: w.seen[key].firstSeen}
		w.opts.Logf("routing watch: routed MCP server %q, added to %s after setup, through the Gateway as %q; %s uses the routed server after it restarts (backup: %s)", server.Name, src.file.Path, name, w.opts.Client, result.backup)
	}
	if err == nil && result.ownershipErr != nil {
		w.opts.Logf("routing watch: routed servers in %s but could not record them for configure-ide --remove-routing: %v", src.file.Path, result.ownershipErr)
	}
}

// isGatewayServer reports an AgentKeeper Gateway entry, current or stale. It
// is never treated as a direct server.
func isGatewayServer(server discovery.DiscoveredServer) bool {
	return server.RouteState == discovery.RouteRouted || server.Name == ideconfig.GatewayServerName || gatewayentry.IsGatewayCommand(server.Entry.Command)
}

// serverKey identifies one server entry: its file, project and name.
func serverKey(server discovery.DiscoveredServer) string {
	return strings.Join([]string{server.Client, filepath.Clean(server.SourcePath), server.Project, server.Name}, "\x00")
}

// reportIdentity is how a reported server is told apart from the others,
// the same way Discover tells its servers apart.
func reportIdentity(server discovery.DiscoveredServer) string {
	return strings.Join([]string{server.Client, server.Scope, server.SourceKind, filepath.Clean(server.SourcePath), server.Name}, "\x00")
}
