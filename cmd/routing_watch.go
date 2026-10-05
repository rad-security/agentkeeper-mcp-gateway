package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/gatewayentry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/routingwatch"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// envAutoRoute turns off the routing watch's automatic routing in Enforce
// when set to 0, false, no or off. Reporting continues.
const envAutoRoute = "AGENTKEEPER_AUTO_ROUTE"

// newRoutingWatch returns the routing watch for the client this Gateway
// serves, or nil when there is nothing for one to do: no supported client,
// or neither a dashboard to report to nor Enforce to route in. It reads
// nothing until Scan.
func newRoutingWatch(cwd string, managedRuntime bool, authority, tc *telemetry.Client, logger *logging.Logger) *routingwatch.Watcher {
	client := strings.TrimSpace(os.Getenv(gatewayentry.EnvClientName))
	if client == "" {
		return nil
	}
	enforce := func() bool {
		mode, _ := authority.EffectiveMode()
		return mode == "enforce"
	}
	if tc == nil && !enforce() {
		return nil
	}
	opts := routingwatch.Options{
		Client:    client,
		CWD:       cwd,
		Enforce:   enforce,
		AutoRoute: autoRouteAllowed(managedRuntime),
		Logf:      logger.Warn,
		Debugf:    logger.Info,
	}
	if tc != nil {
		opts.OnChange = tc.RequestSync
	}
	watch, err := routingwatch.New(opts)
	if err != nil {
		if !errors.Is(err, routingwatch.ErrUnsupportedClient) {
			logger.Warn("routing watch unavailable: %v", err)
		}
		return nil
	}
	return watch
}

// autoRouteAllowed reports whether the routing watch may route servers added
// after setup when the route is in Enforce. A managed deployment's own
// reconciler owns its routes.
func autoRouteAllowed(managedRuntime bool) bool {
	if managedRuntime {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envAutoRoute))) {
	case "0", "false", "no", "off":
		return false
	}
	if savePath := strings.TrimSpace(config.SavePath()); savePath != "" {
		if _, err := os.Stat(filepath.Join(filepath.Dir(savePath), config.ManagedRoutingManifestName)); err == nil {
			return false
		}
	}
	return true
}

// withRoutingWatch adds the routing watch's view to a discovery heartbeat:
// why each direct server bypasses the Gateway and when it was first seen,
// the servers discovery does not read (other Claude Code projects, plugins),
// and servers routed while the client still runs them directly.
func withRoutingWatch(discovered []telemetry.DiscoveredServerInfo, watch *routingwatch.Watcher) []telemetry.DiscoveredServerInfo {
	if watch == nil {
		return discovered
	}
	return mergeWatchedServers(discovered, watch.Servers())
}

func mergeWatchedServers(discovered []telemetry.DiscoveredServerInfo, watched []routingwatch.Server) []telemetry.DiscoveredServerInfo {
	byIdentity := make(map[string]routingwatch.Server, len(watched))
	for _, server := range watched {
		key := discoveredIdentity(server.Client, server.Scope, server.SourceKind, server.SourcePath, server.Name)
		if _, duplicate := byIdentity[key]; !duplicate {
			byIdentity[key] = server
		}
	}
	merged := map[string]bool{}
	out := make([]telemetry.DiscoveredServerInfo, 0, len(discovered)+len(watched))
	for _, info := range discovered {
		key := discoveredIdentity(info.Client, info.Scope, info.SourceKind, info.SourcePath, info.Name)
		if server, ok := byIdentity[key]; ok && !merged[key] {
			merged[key] = true
			info = watchedServerInfo(server)
		}
		out = append(out, info)
	}
	for _, server := range watched {
		key := discoveredIdentity(server.Client, server.Scope, server.SourceKind, server.SourcePath, server.Name)
		if merged[key] {
			continue
		}
		merged[key] = true
		out = append(out, watchedServerInfo(server))
	}
	return out
}

func watchedServerInfo(server routingwatch.Server) telemetry.DiscoveredServerInfo {
	info := telemetryDiscoveredServer(server.DiscoveredServer)
	info.DirectReason = server.DirectReason
	if !server.FirstSeenAt.IsZero() {
		info.FirstSeenAt = server.FirstSeenAt.UTC().Format(time.RFC3339)
	}
	return info
}

func discoveredIdentity(client, scope, sourceKind, sourcePath, name string) string {
	if sourcePath != "" {
		sourcePath = filepath.Clean(sourcePath)
	}
	return strings.Join([]string{client, scope, sourceKind, sourcePath, name}, "\x00")
}

func telemetryDiscoveredServer(s discovery.DiscoveredServer) telemetry.DiscoveredServerInfo {
	return telemetry.DiscoveredServerInfo{
		Name:           s.Name,
		Client:         s.Client,
		Scope:          s.Scope,
		SourceKind:     s.SourceKind,
		SourcePath:     s.SourcePath,
		SourceHash:     s.SourceHash,
		Transport:      s.Transport,
		RouteState:     s.RouteState,
		Routeability:   s.Routeability,
		Routable:       s.Routable,
		GatewayCovered: s.GatewayCovered,
		GatewayName:    s.GatewayName,
		EnvKeys:        s.EnvKeys,
		HeaderKeys:     s.HeaderKeys,
	}
}
