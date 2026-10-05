package cmd

import (
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/routingwatch"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

func TestMergeWatchedServersAnnotatesAndAddsWatchedServers(t *testing.T) {
	seen := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	claudeJSON := "/home/dev/.claude.json"
	discovered := []telemetry.DiscoveredServerInfo{
		{Name: "notes", Client: "claude-code", Scope: "user", SourceKind: "claude_json_user", SourcePath: claudeJSON, RouteState: "direct", Routable: true},
		{Name: "agentkeeper-mcp-gateway", Client: "claude-code", Scope: "user", SourceKind: "claude_json_user", SourcePath: claudeJSON, RouteState: "routed"},
		{Name: "notes", Client: "cursor", Scope: "global", SourceKind: "cursor_mcp_json", SourcePath: "/home/dev/.cursor/mcp.json", RouteState: "direct"},
	}
	watched := []routingwatch.Server{
		{DiscoveredServer: discovery.DiscoveredServer{Name: "notes", Client: "claude-code", Scope: "user", SourceKind: "claude_json_user", SourcePath: claudeJSON, RouteState: "direct", Routable: true}, DirectReason: routingwatch.ReasonAddedAfterSetup, FirstSeenAt: seen},
		{DiscoveredServer: discovery.DiscoveredServer{Name: "tickets", Client: "claude-code", Scope: "local", SourceKind: "claude_json_project", SourcePath: claudeJSON, RouteState: "direct", Routable: true}, FirstSeenAt: seen},
		{DiscoveredServer: discovery.DiscoveredServer{Name: "weather", Client: "claude-code", Scope: "user", SourceKind: "claude_json_user", SourcePath: claudeJSON, RouteState: routingwatch.RouteStatePendingRestart, Routable: true, GatewayCovered: true, GatewayName: "weather"}, DirectReason: routingwatch.ReasonAddedAfterSetup, FirstSeenAt: seen},
	}
	merged := mergeWatchedServers(discovered, watched)
	if len(merged) != 5 {
		t.Fatalf("merged: %+v", merged)
	}
	if notes := merged[0]; notes.DirectReason != routingwatch.ReasonAddedAfterSetup || notes.FirstSeenAt != "2026-10-05T09:30:00Z" {
		t.Fatalf("annotated discovery entry: %+v", notes)
	}
	if gateway := merged[1]; gateway.RouteState != "routed" || gateway.DirectReason != "" || gateway.FirstSeenAt != "" {
		t.Fatalf("the Gateway entry was annotated: %+v", gateway)
	}
	if cursor := merged[2]; cursor.DirectReason != "" || cursor.FirstSeenAt != "" {
		t.Fatalf("another client's server was annotated: %+v", cursor)
	}
	if tickets := merged[3]; tickets.Name != "tickets" || tickets.DirectReason != "" || tickets.FirstSeenAt == "" {
		t.Fatalf("a watched server discovery does not read: %+v", tickets)
	}
	if weather := merged[4]; weather.RouteState != routingwatch.RouteStatePendingRestart || !weather.GatewayCovered || weather.GatewayName != "weather" {
		t.Fatalf("a server routed while the client runs: %+v", weather)
	}
	if got := withRoutingWatch(discovered, nil); len(got) != len(discovered) {
		t.Fatal("no watch must leave discovery as it is")
	}
}
