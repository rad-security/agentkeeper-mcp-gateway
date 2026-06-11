package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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
	DiscoveredServers  []discovery.DiscoveredServer `json:"discovered_servers"`
	ConfigPathsChecked []string                     `json:"config_paths_checked"`
	SeenOnlyCount      int                          `json:"seen_only_count"`
	ToolManifestStatus string                       `json:"tool_manifest_status"`
	NextSteps          []string                     `json:"next_steps"`
	DiscoveryError     string                       `json:"discovery_error,omitempty"`
}

func buildListHealthReport(cfg config.Config) listHealthReport {
	cwd, _ := os.Getwd()
	res, err := discovery.Discover(discovery.Options{CWD: cwd})
	discovered := res.Servers
	seenOnly := countSeenOnly(discovered, cfg.Servers)
	nextSteps := healthNextSteps(cfg, discovered, seenOnly)
	status := "unknown"
	if len(cfg.Servers) > 0 {
		status = "pending"
	}
	if hasConfiguredTools(cfg.Servers) {
		status = "observed"
	}
	report := listHealthReport{
		ConfigPath:         config.CurrentConfigPath(),
		DashboardConnected: config.HasUsableAPIKey(cfg.APIKey),
		APIURL:             cfg.APIURL,
		RoutedServers:      cfg.Servers,
		DiscoveredServers:  discovered,
		ConfigPathsChecked: configPathsChecked(discovered),
		SeenOnlyCount:      seenOnly,
		ToolManifestStatus: status,
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
	routedNames := map[string]bool{}
	for _, s := range routed {
		if s.Name != "" {
			routedNames[s.Name] = true
		}
	}
	count := 0
	for _, s := range discovered {
		if s.RouteState == discovery.RouteRouted || s.Name == "agentkeeper-mcp-gateway" {
			continue
		}
		if !routedNames[s.Name] {
			count++
		}
	}
	return count
}

func hasConfiguredTools(servers []config.ServerEntry) bool {
	return false
}

func healthNextSteps(cfg config.Config, discovered []discovery.DiscoveredServer, seenOnly int) []string {
	var steps []string
	if len(discovered) == 0 && len(cfg.Servers) == 0 {
		steps = append(steps, "Run agentkeeper-mcp-gateway configure-ide --dry-run to discover supported local MCP client configs.")
	}
	if seenOnly > 0 {
		steps = append(steps, "Run agentkeeper-mcp-gateway configure-ide --dry-run, verify supported config paths, then apply configure-ide.")
	}
	if len(cfg.Servers) > 0 {
		steps = append(steps, "Restart the MCP client and make one real harmless tool call through Gateway.")
	}
	if !config.HasUsableAPIKey(cfg.APIKey) {
		steps = append(steps, "Connect to AgentKeeper with auth login or managed config for dashboard sync, central policy, and fleet proof.")
	}
	steps = append(steps, "Use manual add only for unsupported config sources or gateway-native admin setup.")
	return steps
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
