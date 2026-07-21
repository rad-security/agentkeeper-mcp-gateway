package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/proxy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/runtimebroker"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
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

		if coworkAutoGuardEnabled() {
			summary, err := runCoworkGuardOnce("", false)
			if err != nil {
				logger.Warn("Cowork guard startup pass failed: %v", err)
			} else if coworkGuardChanged(summary) {
				fmt.Fprintf(os.Stderr, "[agentkeeper] Cowork guard routed %d backend(s) and disabled %d native direct source(s)\n", summary.Migrated, summary.Disabled)
				if reloaded, err := config.Load(); err == nil {
					cfg = reloaded
					if enforce {
						cfg.Mode = "enforce"
					}
				} else {
					logger.Warn("Cowork guard could not reload config after startup pass: %v", err)
				}
			}
		}

		// Start telemetry if connected
		var tc *telemetry.Client
		hasAPIKey := config.HasUsableAPIKey(cfg.APIKey)
		hasRuntimeBroker := cfg.ManagedRuntimeSocket != "" &&
			cfg.ManagedRuntimeProtocol == runtimebroker.Protocol &&
			cfg.CredentialMode == runtimebroker.CredentialMode
		if hasRuntimeBroker {
			tc = telemetry.NewRuntimeClient(cfg.ManagedRuntimeSocket, logger)
		} else if hasAPIKey {
			apiURL := cfg.APIURL
			if apiURL == "" {
				apiURL = "https://www.agentkeeper.dev"
			}
			tc = telemetry.NewClient(apiURL, cfg.APIKey, logger)
		}
		if tc != nil {
			tc.SetMode(cfg.Mode)
			tc.SetVersion(version)

			// Build server info for registration
			tc.SetServers(telemetryServerInfosFromConfig(cfg))
			cwd, _ := os.Getwd()
			tc.SetDiscoveryProvider(func() []telemetry.DiscoveredServerInfo {
				return discoverTelemetryServers(cwd)
			})
			tc.Start()
			defer tc.Stop()
		}

		// Create detection engine
		engine := detection.NewEngine()

		// Build server configs from config
		serverConfigs := serverConfigsFromConfig(cfg)

		// Create server manager
		mgr := server.NewManager(serverConfigs)
		defer mgr.StopAll()
		if coworkAutoGuardEnabled() {
			interval := coworkAutoGuardInterval()
			stop := make(chan struct{})
			done := make(chan struct{})
			go coworkGuardLoop(interval, "", os.Stderr, func(summary coworkGuardSummary) {
				fmt.Fprintf(os.Stderr, "[agentkeeper] Cowork guard routed %d backend(s) and disabled %d native direct source(s)\n", summary.Migrated, summary.Disabled)
				reloaded, err := config.Load()
				if err != nil {
					logger.Warn("Cowork guard could not reload config: %v", err)
					return
				}
				if enforce {
					reloaded.Mode = "enforce"
				}
				mgr.UpdateConfigs(serverConfigsFromConfig(reloaded))
				if err := mgr.StartAll(); err != nil {
					logger.Warn("Cowork guard could not start newly routed backend(s): %v", err)
				}
				if tc != nil {
					tc.SetServers(telemetryServerInfosFromConfig(reloaded))
				}
			}, stop, done)
			defer func() {
				close(stop)
				<-done
			}()
		}

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
		if hasRuntimeBroker {
			fmt.Fprintf(os.Stderr, "[agentkeeper] Connected through credentialless AgentKeeper runtime broker\n")
		} else if hasAPIKey {
			fmt.Fprintf(os.Stderr, "[agentkeeper] Connected to dashboard\n")
		} else {
			fmt.Fprintf(os.Stderr, "[agentkeeper] Local mode (run 'agentkeeper-mcp-gateway auth login' to connect)\n")
		}

		// Create and run proxy
		p := proxy.NewProxy(proxy.Config{
			EnforceMode:     cfg.Mode == "enforce",
			GatewayVersion:  version,
			Detection:       telemetry.DetectionConfig{Threat: cfg.Detection.Threat, SensitiveData: cfg.Detection.SensitiveData},
			DetectionEngine: engine,
			Logger:          logger,
		}, mgr, tc)

		return p.Run()
	},
}

func serverConfigsFromConfig(cfg config.Config) []server.ServerConfig {
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
	return serverConfigs
}

func telemetryServerInfosFromConfig(cfg config.Config) []telemetry.ServerInfo {
	var serverInfos []telemetry.ServerInfo
	for _, s := range cfg.Servers {
		serverInfos = append(serverInfos, telemetry.ServerInfo{
			Name:      s.Name,
			Transport: s.Transport,
		})
	}
	return serverInfos
}

func coworkAutoGuardEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTKEEPER_COWORK_GUARD"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func coworkAutoGuardInterval() time.Duration {
	const minInterval = 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("AGENTKEEPER_COWORK_GUARD_INTERVAL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			if parsed < minInterval {
				return minInterval
			}
			return parsed
		}
	}
	if raw := strings.TrimSpace(os.Getenv("AGENTKEEPER_COWORK_GUARD_INTERVAL_MS")); raw != "" {
		var ms int
		if _, err := fmt.Sscanf(raw, "%d", &ms); err == nil && ms > 0 {
			parsed := time.Duration(ms) * time.Millisecond
			if parsed < minInterval {
				return minInterval
			}
			return parsed
		}
	}
	return 60 * time.Second
}

func discoverTelemetryServers(cwd string) []telemetry.DiscoveredServerInfo {
	res, err := discovery.Discover(discovery.Options{Client: "all", CWD: cwd})
	if err != nil {
		return nil
	}
	out := make([]telemetry.DiscoveredServerInfo, 0, len(res.Servers))
	for _, s := range res.Servers {
		out = append(out, telemetry.DiscoveredServerInfo{
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
		})
	}
	return out
}

func init() {
	serverCmd.Flags().BoolVar(&enforce, "enforce", false, "Enable enforce mode (block policy violations)")
	serverCmd.Flags().BoolVar(&noAutoAuth, "no-auto-auth", false, "Disable automatic device authentication")
	rootCmd.AddCommand(serverCmd)
}
