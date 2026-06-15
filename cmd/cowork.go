package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/spf13/cobra"
)

var coworkCWD string
var coworkDryRun bool
var coworkSource string
var coworkJSON bool
var coworkStrict bool
var coworkRequireNativeConnectors bool
var coworkGuardInterval time.Duration
var coworkGuardOnce bool

var coworkCmd = &cobra.Command{
	Use:   "cowork",
	Short: "Inspect Claude Desktop / Cowork local MCP gateway coverage",
}

var coworkDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover Cowork local/plugin MCP servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := discovery.Discover(discovery.Options{Client: discovery.ClientCowork, CWD: coworkCWD})
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	},
}

var coworkDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Summarize Cowork local Gateway routeability",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := discovery.Discover(discovery.Options{Client: discovery.ClientCowork, CWD: coworkCWD})
		if err != nil {
			return err
		}
		verdict := "no_cowork_mcp_servers_discovered"
		routedCount := 0
		directCount := 0
		routableCount := 0
		coveredDirectCount := 0
		gatewayConfigPath := config.CurrentConfigPath()
		gatewayBackends, gatewayConfigErr := coworkGatewayBackends()
		gatewayBackendCount := len(gatewayBackends)
		for _, s := range res.Servers {
			if s.RouteState == discovery.RouteRouted {
				routedCount++
				continue
			}
			if s.RouteState == discovery.RouteDirect {
				directCount++
				if s.GatewayCovered {
					coveredDirectCount++
				}
				if s.Routable {
					routableCount++
				}
			}
		}
		switch {
		case routedCount > 0 && directCount == 0 && gatewayBackendCount == 0:
			verdict = "cowork_gateway_entrypoint_routed_but_no_backends_configured"
		case routedCount > 0 && directCount == 0:
			verdict = "cowork_local_mcp_routed_native_connectors_require_zip"
		case routedCount > 0 && directCount > 0:
			verdict = "cowork_gateway_routed_but_direct_bypass_detected"
		case directCount > 0 && coveredDirectCount > 0:
			verdict = "cowork_gateway_covered_but_direct_bypass_detected"
		case routableCount > 0:
			verdict = "cowork_servers_discovered_not_routed"
		}
		payload := map[string]interface{}{
			"verdict":               verdict,
			"routed_count":          routedCount,
			"direct_count":          directCount,
			"routable_count":        routableCount,
			"covered_direct_count":  coveredDirectCount,
			"coverage_scope":        "local_mcp_only",
			"gateway_config_path":   gatewayConfigPath,
			"gateway_backend_count": gatewayBackendCount,
			"gateway_backends":      gatewayBackends,
			"native_connectors": map[string]interface{}{
				"standalone_gateway_supported": false,
				"required_path":                "agentkeeper_cowork_plugin_zip",
				"reason":                       "Standalone gateway covers Cowork local, plugin, and locally discoverable remote MCP configs. Cowork connector calls that are not represented in local MCP config can still execute through Claude's cloud-managed connector path without invoking the local gateway process.",
			},
			"servers": res.Servers,
		}
		if gatewayConfigErr != nil {
			payload["gateway_config_error"] = gatewayConfigErr.Error()
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		if coworkStrict && directCount > 0 {
			return fmt.Errorf("%s: %d direct Cowork MCP source(s) can bypass the gateway; run `agentkeeper-mcp-gateway cowork configure` or keep `agentkeeper-mcp-gateway cowork guard` running, then restart Cowork", verdict, directCount)
		}
		if coworkStrict && routedCount > 0 && gatewayBackendCount == 0 {
			return fmt.Errorf("%s: Cowork is wired to the gateway entrypoint, but the gateway config has no backend MCP servers; run `agentkeeper-mcp-gateway cowork configure` first, or use fallback/admin `agentkeeper-mcp-gateway add` for unsupported sources", verdict)
		}
		if coworkRequireNativeConnectors {
			return fmt.Errorf("Cowork native connector governance is not supported by the standalone local gateway; use the AgentKeeper Cowork plugin ZIP path")
		}
		return nil
	},
}

type coworkGatewayBackend struct {
	Name       string   `json:"name"`
	Transport  string   `json:"transport"`
	Command    string   `json:"command,omitempty"`
	URL        string   `json:"url,omitempty"`
	ArgsCount  int      `json:"args_count,omitempty"`
	EnvKeys    []string `json:"env_keys,omitempty"`
	HeaderKeys []string `json:"header_keys,omitempty"`
}

func coworkGatewayBackends() ([]coworkGatewayBackend, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	backends := make([]coworkGatewayBackend, 0, len(cfg.Servers))
	for _, server := range cfg.Servers {
		if isGatewayServerConfig(server) {
			continue
		}
		transport := strings.TrimSpace(server.Transport)
		if transport == "" {
			if strings.TrimSpace(server.URL) != "" {
				transport = "http"
			} else {
				transport = "stdio"
			}
		}
		backends = append(backends, coworkGatewayBackend{
			Name:       server.Name,
			Transport:  transport,
			Command:    server.Command,
			URL:        server.URL,
			ArgsCount:  len(server.Args),
			EnvKeys:    coworkSortedKeys(server.Env),
			HeaderKeys: coworkSortedKeys(server.Headers),
		})
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].Name < backends[j].Name
	})
	return backends, nil
}

func isGatewayServerConfig(server config.ServerEntry) bool {
	command := strings.TrimSpace(server.Command)
	base := command
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		base = base[slash+1:]
	}
	return server.Name == "agentkeeper-mcp-gateway" || base == "agentkeeper-mcp-gateway"
}

func coworkSortedKeys(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var coworkConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Route discovered Cowork local/plugin MCP servers through the gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := discovery.MigrateCoworkMCP(coworkSource, coworkDryRun)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if coworkJSON {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(out, string(data))
			return nil
		}
		if len(result.Plans) == 0 {
			fmt.Fprintln(out, "No routable Cowork MCP sources discovered.")
			return nil
		}
		for _, plan := range result.Plans {
			printCoworkMigrationPlan(out, plan)
		}
		if result.GatewayEntrypoint != nil {
			printCoworkGatewayEntrypointPlan(out, *result.GatewayEntrypoint)
		}
		if coworkDryRun {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "(dry-run - no files written)")
		}
		return nil
	},
}

var coworkGuardCmd = &cobra.Command{
	Use:   "guard",
	Short: "Continuously route newly-created Cowork MCP sources through the gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval := coworkGuardInterval
		if interval <= 0 {
			interval = 250 * time.Millisecond
		}

		out := cmd.OutOrStdout()
		errOut := cmd.ErrOrStderr()
		summary, err := runCoworkGuardOnce(coworkSource, false)
		if err != nil {
			return err
		}
		printCoworkGuardSummary(out, summary)
		if coworkGuardOnce {
			return nil
		}

		fmt.Fprintf(out, "Cowork guard running every %s. Press Ctrl-C to stop.\n", interval)
		stop := make(chan struct{})
		done := make(chan struct{})
		go coworkGuardLoop(interval, coworkSource, errOut, func(summary coworkGuardSummary) {
			printCoworkGuardSummary(out, summary)
		}, stop, done)

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		<-signals
		close(stop)
		<-done
		return nil
	},
}

type coworkGuardSummary struct {
	Plans    int
	Migrated int
	Disabled int
}

func runCoworkGuardOnce(sourcePath string, dryRun bool) (coworkGuardSummary, error) {
	unlock, acquired, err := acquireCoworkGuardLock()
	if err != nil {
		return coworkGuardSummary{}, err
	}
	if !acquired {
		return coworkGuardSummary{}, nil
	}
	defer unlock()

	result, err := discovery.MigrateCoworkMCP(sourcePath, dryRun)
	if err != nil {
		return coworkGuardSummary{}, err
	}
	summary := coworkGuardSummary{Plans: len(result.Plans)}
	for _, plan := range result.Plans {
		summary.Migrated += len(plan.Migrated)
		summary.Disabled += len(plan.NativeDisabled)
	}
	return summary, nil
}

func acquireCoworkGuardLock() (func(), bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false, err
	}
	baseDir := filepath.Join(home, ".agentkeeper", "locks")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, false, err
	}

	lockPath := filepath.Join(baseDir, "cowork-guard.lockdir")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if os.IsExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		_ = os.RemoveAll(lockPath)
	}, true, nil
}

func coworkGuardChanged(summary coworkGuardSummary) bool {
	return summary.Migrated > 0 || summary.Disabled > 0
}

func printCoworkGuardSummary(out io.Writer, summary coworkGuardSummary) {
	if coworkGuardChanged(summary) {
		fmt.Fprintf(out, "Cowork guard routed %d backend(s) and disabled %d native direct source(s).\n", summary.Migrated, summary.Disabled)
		return
	}
	fmt.Fprintln(out, "Cowork guard: no direct Cowork MCP bypasses found.")
}

func coworkGuardLoop(interval time.Duration, sourcePath string, errOut io.Writer, onChange func(coworkGuardSummary), stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			summary, err := runCoworkGuardOnce(sourcePath, false)
			if err != nil {
				fmt.Fprintf(errOut, "[agentkeeper] Cowork guard error: %v\n", err)
				continue
			}
			if coworkGuardChanged(summary) && onChange != nil {
				onChange(summary)
			}
		case <-stop:
			return
		}
	}
}

func printCoworkMigrationPlan(out interface {
	Write(p []byte) (int, error)
}, plan discovery.MigrationPlan) {
	migratable := 0
	for _, s := range plan.Servers {
		if s.RouteState != discovery.RouteRouted && s.Routable {
			migratable++
		}
	}
	status := "no MCP servers discovered"
	if plan.AlreadyRouted {
		status = "already routed"
	} else if len(plan.Migrated) > 0 {
		if plan.Scope == "remote" {
			status = fmt.Sprintf("imported %d remote MCP backend(s)", len(plan.Migrated))
			if len(plan.NativeDisabled) > 0 {
				status += fmt.Sprintf(" + disabled %d native direct source(s)", len(plan.NativeDisabled))
			}
		} else {
			status = fmt.Sprintf("migrated %d + wired", len(plan.Migrated))
		}
	} else if migratable > 0 {
		if plan.Scope == "remote" {
			status = fmt.Sprintf("import %d remote MCP backend(s) + disable native direct source(s)", migratable)
		} else {
			status = fmt.Sprintf("migrate %d + wire", migratable)
		}
	} else if len(plan.Servers) > 0 {
		status = "no routable MCP servers"
	}
	fmt.Fprintf(out, "  %-16s %s - %s\n", plan.Client, status, plan.ConfigPath)
	for _, s := range plan.Servers {
		if s.RouteState == discovery.RouteRouted || !s.Routable {
			continue
		}
		rendered := s.Command
		if rendered == "" {
			rendered = s.URL
		}
		if s.ArgsCount > 0 {
			rendered = fmt.Sprintf("%s (%d args)", rendered, s.ArgsCount)
		}
		name := s.Name
		if s.GatewayName != "" && s.GatewayName != s.Name {
			name = fmt.Sprintf("%s -> %s", s.Name, s.GatewayName)
		}
		if strings.TrimSpace(rendered) == "" {
			rendered = s.Transport
		}
		fmt.Fprintf(out, "    -> migrate: %s (%s)\n", name, rendered)
	}
	if plan.BackupPath != "" {
		fmt.Fprintf(out, "  %-16s backup: %s\n", "", plan.BackupPath)
	}
}

func printCoworkGatewayEntrypointPlan(out interface {
	Write(p []byte) (int, error)
}, plan discovery.MigrationPlan) {
	status := "wire gateway entrypoint"
	if plan.AlreadyRouted {
		status = "gateway entrypoint already present"
	} else if plan.BackupPath != "" || !coworkDryRun {
		status = "wired gateway entrypoint"
	}
	fmt.Fprintf(out, "  %-16s %s - %s\n", plan.Client, status, plan.ConfigPath)
	if plan.BackupPath != "" {
		fmt.Fprintf(out, "  %-16s backup: %s\n", "", plan.BackupPath)
	}
}

func init() {
	coworkCmd.PersistentFlags().StringVar(&coworkCWD, "cwd", "", "Optional project directory")
	coworkConfigureCmd.Flags().BoolVar(&coworkDryRun, "dry-run", false, "Preview changes without writing files")
	coworkConfigureCmd.Flags().StringVar(&coworkSource, "source", "", "Specific Cowork MCP source file to route")
	coworkConfigureCmd.Flags().BoolVar(&coworkJSON, "json", false, "Emit JSON")
	coworkDoctorCmd.Flags().BoolVar(&coworkStrict, "strict", false, "Exit non-zero if any direct Cowork MCP source can bypass the gateway")
	coworkDoctorCmd.Flags().BoolVar(&coworkRequireNativeConnectors, "require-native-connectors", false, "Exit non-zero because Cowork native/cloud connectors require the AgentKeeper Cowork plugin ZIP path")
	coworkGuardCmd.Flags().StringVar(&coworkSource, "source", "", "Specific Cowork MCP source file to guard")
	coworkGuardCmd.Flags().DurationVar(&coworkGuardInterval, "interval", 250*time.Millisecond, "How often to scan Cowork session files")
	coworkGuardCmd.Flags().BoolVar(&coworkGuardOnce, "once", false, "Run one guard pass and exit")
	coworkCmd.AddCommand(coworkDiscoverCmd)
	coworkCmd.AddCommand(coworkDoctorCmd)
	coworkCmd.AddCommand(coworkConfigureCmd)
	coworkCmd.AddCommand(coworkGuardCmd)
	rootCmd.AddCommand(coworkCmd)
}
