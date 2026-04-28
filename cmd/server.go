package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/proxy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/spf13/cobra"
)

var (
	enforce    bool
	noAutoAuth bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the MCP gateway proxy",
	Long: `Start the AgentKeeper MCP Gateway proxy. In audit mode (default),
the gateway logs all tool calls and flags suspicious activity without
blocking. In enforce mode, tool calls that violate security policies
are blocked.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		enforce, _ := cmd.Flags().GetBool("enforce")
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

		// Load config
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agentkeeper] warning: config load error: %v, using defaults\n", err)
			cfg = config.DefaultConfig()
		}

		if enforce {
			cfg.Mode = "enforce"
		}

		// Create logger
		logger, err := logging.NewLogger(cfg.LogPath, verbose)
		if err != nil {
			return fmt.Errorf("creating logger: %w", err)
		}
		defer logger.Close()

		// Start telemetry if connected
		var tc *telemetry.Client
		if cfg.APIKey != "" {
			apiURL := cfg.APIURL
			if apiURL == "" {
				apiURL = "https://www.agentkeeper.dev"
			}
			tc = telemetry.NewClient(apiURL, cfg.APIKey, logger)
			tc.SetMode(cfg.Mode)
			tc.SetVersion(version)

			// Build server info for registration
			var serverInfos []telemetry.ServerInfo
			for _, s := range cfg.Servers {
				serverInfos = append(serverInfos, telemetry.ServerInfo{
					Name:      s.Name,
					Transport: s.Transport,
				})
			}
			tc.SetServers(serverInfos)
			tc.Start()
			defer tc.Stop()
		}

		// Create detection engine
		engine := detection.NewEngine()

		// Build server configs from config
		var serverConfigs []server.ServerConfig
		for _, s := range cfg.Servers {
			serverConfigs = append(serverConfigs, server.ServerConfig{
				Name:      s.Name,
				Command:   s.Command,
				Args:      s.Args,
				Env:       s.Env,
				Transport: s.Transport,
				URL:       s.URL,
				Headers:   s.Headers,
			})
		}

		// Create server manager
		mgr := server.NewManager(serverConfigs)

		// Log session start
		hostname := telemetry.StableHostname()
		serverNames := make([]string, len(cfg.Servers))
		for i, s := range cfg.Servers {
			serverNames[i] = s.Name
		}
		logger.LogSessionStart(hostname, runtime.GOOS, version, serverNames)

		// Print startup message
		mode := "audit"
		if cfg.Mode == "enforce" {
			mode = "enforce"
		}
		fmt.Fprintf(os.Stderr, "[agentkeeper] MCP Gateway v%s starting in %s mode\n", version, mode)
		fmt.Fprintf(os.Stderr, "[agentkeeper] %d servers configured, %d detection patterns loaded\n", len(serverConfigs), 36)
		if cfg.APIKey != "" {
			fmt.Fprintf(os.Stderr, "[agentkeeper] Connected to dashboard\n")
		} else {
			fmt.Fprintf(os.Stderr, "[agentkeeper] Local mode (run 'agentkeeper-mcp-gateway auth login' to connect)\n")
		}

		// Create and run proxy
		p := proxy.NewProxy(proxy.Config{
			EnforceMode:     cfg.Mode == "enforce",
			DetectionEngine: engine,
			Logger:          logger,
		}, mgr, tc)

		return p.Run()
	},
}

func init() {
	serverCmd.Flags().BoolVar(&enforce, "enforce", false, "Enable enforce mode (block policy violations)")
	serverCmd.Flags().BoolVar(&noAutoAuth, "no-auto-auth", false, "Disable automatic device authentication")
	rootCmd.AddCommand(serverCmd)
}
