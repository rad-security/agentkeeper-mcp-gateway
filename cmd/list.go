package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/spf13/cobra"
)

var (
	listHealth bool
	listJSON   bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Show registered MCP servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		healthFlag, _ := cmd.Flags().GetBool("health")
		jsonFlag, _ := cmd.Flags().GetBool("json")

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if healthFlag {
			report := buildListHealthReport(cfg)
			if jsonFlag {
				data, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(data))
				return nil
			}
			printListHealth(out, report)
			return nil
		}

		if jsonFlag {
			data, _ := json.MarshalIndent(cfg.Servers, "", "  ")
			fmt.Fprintln(out, string(data))
			return nil
		}

		if len(cfg.Servers) == 0 {
			printListEmptyState(out)
			return nil
		}

		fmt.Fprintf(out, "%-20s %-10s %s\n", "NAME", "TRANSPORT", "COMMAND/URL")
		fmt.Fprintf(out, "%-20s %-10s %s\n", "----", "---------", "-----------")
		for _, s := range cfg.Servers {
			transport := s.Transport
			if transport == "" {
				transport = "stdio"
			}
			target := s.Command
			if s.URL != "" {
				target = s.URL
			}
			fmt.Fprintf(out, "%-20s %-10s %s\n", s.Name, transport, target)
		}
		return nil
	},
}

type listHealthReport struct {
	ConfigPath         string                       `json:"config_path"`
	DashboardConnected bool                         `json:"dashboard_connected"`
	APIURL             string                       `json:"api_url,omitempty"`
	RoutedServers      []config.ServerEntry         `json:"routed_servers"`
	BackendToolHealth  []backendToolHealth          `json:"backend_tool_health"`
	DiscoveredServers  []discovery.DiscoveredServer `json:"discovered_servers"`
	ConfigPathsChecked []string                     `json:"config_paths_checked"`
	SeenOnlyCount      int                          `json:"seen_only_count"`
	ToolManifestStatus string                       `json:"tool_manifest_status"`
	NextSteps          []string                     `json:"next_steps"`
	DiscoveryError     string                       `json:"discovery_error,omitempty"`
}

type backendToolHealth struct {
	Name         string `json:"name"`
	Transport    string `json:"transport"`
	Status       string `json:"status"`
	ToolCount    int    `json:"tool_count"`
	LastToolName string `json:"last_tool_name,omitempty"`
	LastCallAt   string `json:"last_call_at,omitempty"`
	Error        string `json:"error,omitempty"`
}

func buildListHealthReport(cfg config.Config) listHealthReport {
	cwd, _ := os.Getwd()
	res, err := discovery.Discover(discovery.Options{CWD: cwd})
	discovered := res.Servers
	seenOnly := countSeenOnly(discovered, cfg.Servers)
	backendHealth := probeBackendToolHealth(cfg)
	nextSteps := healthNextSteps(cfg, discovered, seenOnly, backendHealth)
	report := listHealthReport{
		ConfigPath:         config.CurrentConfigPath(),
		DashboardConnected: config.HasUsableAPIKey(cfg.APIKey),
		APIURL:             cfg.APIURL,
		RoutedServers:      cfg.Servers,
		BackendToolHealth:  backendHealth,
		DiscoveredServers:  discovered,
		ConfigPathsChecked: configPathsChecked(discovered),
		SeenOnlyCount:      seenOnly,
		ToolManifestStatus: summarizeToolManifestStatus(cfg.Servers, backendHealth),
		NextSteps:          nextSteps,
	}
	if err != nil {
		report.DiscoveryError = err.Error()
	}
	return report
}

func printListHealth(out interface{ Write([]byte) (int, error) }, report listHealthReport) {
	fmt.Fprintln(out, "MCP Gateway health")
	fmt.Fprintf(out, "Config: %s\n", report.ConfigPath)
	if report.DashboardConnected {
		fmt.Fprintf(out, "Dashboard: connected (%s)\n", report.APIURL)
	} else {
		fmt.Fprintf(out, "Dashboard: local only (%s)\n", report.APIURL)
	}
	fmt.Fprintf(out, "Routed servers: %d\n", len(report.RoutedServers))
	fmt.Fprintf(out, "Discovered local config servers: %d\n", len(report.DiscoveredServers))
	fmt.Fprintf(out, "Seen only: %d\n", report.SeenOnlyCount)
	fmt.Fprintf(out, "Tool manifest: %s\n", report.ToolManifestStatus)
	if report.DiscoveryError != "" {
		fmt.Fprintf(out, "Discovery warning: %s\n", report.DiscoveryError)
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Config paths checked:")
	for _, path := range report.ConfigPathsChecked {
		fmt.Fprintf(out, "  - %s\n", path)
	}
	if len(report.DiscoveredServers) > 0 {
		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "%-20s %-16s %-10s %-12s %s\n", "DISCOVERED", "CLIENT", "SCOPE", "STATE", "SOURCE")
		fmt.Fprintf(out, "%-20s %-16s %-10s %-12s %s\n", "----------", "------", "-----", "-----", "------")
		for _, s := range report.DiscoveredServers {
			fmt.Fprintf(out, "%-20s %-16s %-10s %-12s %s\n", s.Name, s.Client, s.Scope, s.RouteState, s.SourcePath)
		}
	}
	if len(report.RoutedServers) > 0 {
		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "%-20s %-10s %s\n", "ROUTED", "TRANSPORT", "COMMAND/URL")
		fmt.Fprintf(out, "%-20s %-10s %s\n", "------", "---------", "-----------")
		for _, s := range report.RoutedServers {
			transport := s.Transport
			if transport == "" {
				transport = "stdio"
			}
			target := s.Command
			if s.URL != "" {
				target = s.URL
			}
			fmt.Fprintf(out, "%-20s %-10s %s\n", s.Name, transport, target)
		}
	}
	if len(report.BackendToolHealth) > 0 {
		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "%-20s %-10s %-16s %-6s %s\n", "BACKEND", "TRANSPORT", "TOOLS", "COUNT", "DETAIL")
		fmt.Fprintf(out, "%-20s %-10s %-16s %-6s %s\n", "-------", "---------", "-----", "-----", "------")
		for _, h := range report.BackendToolHealth {
			fmt.Fprintf(out, "%-20s %-10s %-16s %-6d %s\n", h.Name, h.Transport, h.Status, h.ToolCount, backendToolHealthDetail(h))
		}
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Next steps:")
	for _, step := range report.NextSteps {
		fmt.Fprintf(out, "  - %s\n", step)
	}
}

func printListEmptyState(out interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(out, "No routed MCP servers configured.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Automatic setup:")
	fmt.Fprintln(out, "  agentkeeper-mcp-gateway configure-ide --dry-run")
	fmt.Fprintln(out, "  agentkeeper-mcp-gateway configure-ide")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Health check:")
	fmt.Fprintln(out, "  agentkeeper-mcp-gateway list --health")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Manual fallback/admin:")
	fmt.Fprintln(out, "  agentkeeper-mcp-gateway add <name> <command>")
}

func countSeenOnly(discovered []discovery.DiscoveredServer, routed []config.ServerEntry) int {
	count := 0
	for _, s := range discovered {
		if s.RouteState == discovery.RouteRouted || s.Name == "agentkeeper-mcp-gateway" {
			continue
		}
		if s.Routable {
			count++
		}
	}
	return count
}

func hasConfiguredTools(servers []config.ServerEntry) bool {
	return false
}

func healthNextSteps(cfg config.Config, discovered []discovery.DiscoveredServer, seenOnly int, backendHealth []backendToolHealth) []string {
	var steps []string
	if len(discovered) == 0 && len(cfg.Servers) == 0 {
		steps = append(steps, "Run agentkeeper-mcp-gateway configure-ide --dry-run to discover supported local MCP client configs.")
	}
	if seenOnly > 0 {
		steps = append(steps, "Run agentkeeper-mcp-gateway configure-ide --dry-run from the project directory, or pass --cwd for project .mcp.json, then apply configure-ide. Project files inside a git repo are only rewritten with explicit --cwd or --scope=project.")
	}
	if hasDirectCoworkSource(discovered) {
		steps = append(steps, "For Cowork sources created after setup, run agentkeeper-mcp-gateway cowork guard --once now and keep cowork guard running from a login item or service.")
	}
	if countBackendStatus(backendHealth, "auth_required") > 0 {
		steps = append(steps, "Reconnect or authenticate remote MCP backends that report auth_required; native Claude/Cowork connectors may use separate cloud auth and bypass the standalone local gateway.")
	}
	if countBackendStatus(backendHealth, "unreachable") > 0 {
		steps = append(steps, "Fix remote MCP backend connectivity for unreachable servers, then rerun agentkeeper-mcp-gateway list --health.")
	}
	if countBackendStatus(backendHealth, "pending") > 0 || countBackendStatus(backendHealth, "auth_configured") > 0 {
		steps = append(steps, "Restart the MCP client and make one real harmless tool call through Gateway.")
	}
	if !config.HasUsableAPIKey(cfg.APIKey) {
		steps = append(steps, "Connect to AgentKeeper with auth login or managed config for dashboard sync, central policy, and fleet proof.")
	}
	steps = append(steps, "Use manual add only for unsupported config sources or gateway-native admin setup.")
	return steps
}

func hasDirectCoworkSource(discovered []discovery.DiscoveredServer) bool {
	for _, s := range discovered {
		if s.Client == discovery.ClientCowork && s.RouteState != discovery.RouteRouted && s.Routable {
			return true
		}
	}
	return false
}

func probeBackendToolHealth(cfg config.Config) []backendToolHealth {
	if len(cfg.Servers) == 0 {
		return nil
	}
	observedCalls := readObservedToolCalls(defaultEventLogPath(cfg))
	health := make([]backendToolHealth, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		transport := normalizeListTransport(s)
		h := backendToolHealth{
			Name:      s.Name,
			Transport: transport,
			Status:    "pending",
		}
		if transport == "http" {
			if knownOAuthMCPURL(s.URL) && !hasAuthHeader(s.Headers) {
				h.Status = "auth_required"
				h.Error = "remote MCP endpoint requires OAuth/auth headers; native Claude/Cowork connector auth is separate from the standalone local gateway"
			} else if hasAuthHeader(s.Headers) {
				h.Status = "auth_configured"
			}
		}
		if observed, ok := observedCalls[s.Name]; ok {
			h.Status = "calls_observed"
			h.LastCallAt = observed.Timestamp
			h.LastToolName = observed.ToolName
			h.Error = ""
		}
		health = append(health, h)
	}
	return health
}

func summarizeToolManifestStatus(servers []config.ServerEntry, health []backendToolHealth) string {
	if len(servers) == 0 {
		return "unknown"
	}
	if countBackendStatus(health, "auth_required") > 0 || countBackendStatus(health, "unreachable") > 0 {
		return "action_required"
	}
	if countBackendStatus(health, "tools_observed") > 0 || countBackendStatus(health, "calls_observed") > 0 {
		return "observed"
	}
	return "pending"
}

func countBackendStatus(health []backendToolHealth, status string) int {
	count := 0
	for _, h := range health {
		if h.Status == status {
			count++
		}
	}
	return count
}

func backendToolHealthDetail(h backendToolHealth) string {
	if h.Error != "" {
		return h.Error
	}
	if h.LastToolName != "" && h.LastCallAt != "" {
		return fmt.Sprintf("last call %s at %s", h.LastToolName, h.LastCallAt)
	}
	if h.LastCallAt != "" {
		return "last call at " + h.LastCallAt
	}
	return ""
}

func normalizeListTransport(s config.ServerEntry) string {
	transport := strings.ToLower(strings.TrimSpace(s.Transport))
	switch transport {
	case "http", "sse", "streamable-http":
		return "http"
	case "":
		if strings.TrimSpace(s.URL) != "" {
			return "http"
		}
		return "stdio"
	default:
		return transport
	}
}

func hasAuthHeader(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), "authorization") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func knownOAuthMCPURL(raw string) bool {
	u := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(u, "mcp.notion.com") ||
		strings.Contains(u, "mcp.raindrop.ai") ||
		strings.Contains(u, "mcp.linear.app")
}

type observedToolCall struct {
	Timestamp string
	ToolName  string
}

func defaultEventLogPath(cfg config.Config) string {
	if strings.TrimSpace(cfg.LogPath) != "" {
		return cfg.LogPath
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
}

func readObservedToolCalls(path string) map[string]observedToolCall {
	observed := map[string]observedToolCall{}
	if strings.TrimSpace(path) == "" {
		return observed
	}
	file, err := os.Open(path)
	if err != nil {
		return observed
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var event struct {
			Timestamp  string `json:"timestamp"`
			EventType  string `json:"event_type"`
			ServerName string `json:"server_name"`
			ToolName   string `json:"tool_name"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.EventType != "mcp.tool_call" || event.ServerName == "" {
			continue
		}
		observed[event.ServerName] = observedToolCall{
			Timestamp: event.Timestamp,
			ToolName:  event.ToolName,
		}
	}
	return observed
}

func configPathsChecked(discovered []discovery.DiscoveredServer) []string {
	seen := map[string]bool{}
	var paths []string
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}
	for _, s := range discovered {
		add(s.SourcePath)
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	if cwd != "" {
		add(filepath.Join(cwd, ".mcp.json"))
	}
	if home != "" {
		add(filepath.Join(home, ".claude.json"))
		add(filepath.Join(home, ".claude", "settings.json"))
		add(filepath.Join(home, ".cursor", "mcp.json"))
		switch runtime.GOOS {
		case "darwin":
			add(filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
		case "windows":
			add(filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"))
		default:
			add(filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
		}
	}
	return paths
}

func init() {
	listCmd.Flags().BoolVar(&listHealth, "health", false, "Include health check status")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output in JSON format")
	rootCmd.AddCommand(listCmd)
}
