package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/proxy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/spf13/cobra"
)

var (
	scanJSON    bool
	scanTimeout time.Duration
)

type scanServerResult struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Scanned   bool   `json:"scanned"`
	ToolCount int    `json:"tool_count"`
	Error     string `json:"error,omitempty"`
}

type scanFinding struct {
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Server      string `json:"server,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Description string `json:"description"`
}

type scanReport struct {
	Servers  []scanServerResult `json:"servers"`
	Findings []scanFinding      `json:"findings"`
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan registered MCP servers' tool definitions for security issues",
	Long: `Start each registered MCP server, read the tools it advertises, and
check their names, descriptions and parameters for:

  tool_poisoning  instructions hidden in a tool definition (prompt injection,
                  requests to bypass safeguards, act silently or exfiltrate)
  tool_shadowing  the same tool name advertised by more than one server
                  (informational: the Gateway namespaces tools per server)

A server that cannot be started or listed is reported, not treated as clean.
Exits non-zero when a tool definition is flagged or a server could not be
scanned. No tool is called and nothing is sent to AgentKeeper.`,
	// A finding is a result, not a usage error.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if len(cfg.Servers) == 0 {
			if scanJSON {
				return writeScanJSON(out, scanReport{Servers: []scanServerResult{}, Findings: []scanFinding{}})
			}
			fmt.Fprintln(out, "No MCP servers are registered. Run configure-ide --dry-run to see what can be routed.")
			return nil
		}
		report := runScan(serverConfigsFromConfig(cfg), scanTimeout)
		if scanJSON {
			if err := writeScanJSON(out, report); err != nil {
				return err
			}
		} else {
			printScanReport(out, report)
		}
		flagged, unscanned := 0, 0
		for _, finding := range report.Findings {
			switch finding.Kind {
			case "tool_poisoning":
				flagged++
			case "not_scanned":
				unscanned++
			}
		}
		if flagged > 0 || unscanned > 0 {
			return fmt.Errorf("scan flagged %d tool definition(s); %d server(s) could not be scanned", flagged, unscanned)
		}
		return nil
	},
}

func writeScanJSON(out io.Writer, report scanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

// runScan lists every server's tools in parallel and evaluates the manifests.
// It only starts servers and reads their tool lists; it never calls a tool.
func runScan(configs []server.ServerConfig, timeout time.Duration) scanReport {
	manager := server.NewManager(configs)
	_ = manager.StartAll()
	defer manager.StopAll()

	type listed struct {
		tools []interface{}
		err   error
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	results := make(map[string]listed, len(configs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			var result listed
			if upstream := manager.Get(name); upstream == nil {
				result.err = fmt.Errorf("the server could not be started")
			} else {
				result.tools, result.err = upstream.ListToolsContext(ctx)
			}
			mu.Lock()
			results[name] = result
			mu.Unlock()
		}(cfg.Name)
	}
	wg.Wait()

	engine := detection.NewEngine()
	report := scanReport{Servers: []scanServerResult{}, Findings: []scanFinding{}}
	owners := map[string][]string{}
	sorted := append([]server.ServerConfig(nil), configs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, cfg := range sorted {
		transport := cfg.Transport
		if transport == "" {
			transport = "stdio"
			if cfg.URL != "" {
				transport = "http"
			}
		}
		result := results[cfg.Name]
		entry := scanServerResult{Name: cfg.Name, Transport: transport, Scanned: result.err == nil, ToolCount: len(result.tools)}
		if result.err != nil {
			entry.Error = result.err.Error()
			report.Findings = append(report.Findings, scanFinding{
				Kind: "not_scanned", Severity: "info", Server: cfg.Name,
				Description: "could not be scanned: " + entry.Error,
			})
		}
		report.Servers = append(report.Servers, entry)
		for _, value := range result.tools {
			tool, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			description := proxy.ToolDescription(tool)
			if description.Name == "" {
				continue
			}
			owners[description.Name] = append(owners[description.Name], cfg.Name)
			for _, hit := range engine.EvaluateToolDescriptions([]detection.ToolDescription{description}) {
				report.Findings = append(report.Findings, scanFinding{
					Kind: "tool_poisoning", Severity: hit.Severity, Server: cfg.Name,
					Tool: description.Name, Rule: hit.PatternName, Description: hit.Description,
				})
			}
		}
	}
	shadowed := make([]string, 0)
	for name, servers := range owners {
		if len(servers) > 1 {
			shadowed = append(shadowed, name)
		}
	}
	sort.Strings(shadowed)
	for _, name := range shadowed {
		report.Findings = append(report.Findings, scanFinding{
			Kind: "tool_shadowing", Severity: "info", Tool: name,
			Description: fmt.Sprintf("advertised by %d servers (%s); distinct through the Gateway, ambiguous to a client that uses these servers directly", len(owners[name]), strings.Join(owners[name], ", ")),
		})
	}
	return report
}

func printScanReport(out io.Writer, report scanReport) {
	fmt.Fprintf(out, "Scanned %d registered MCP server(s)\n\n", len(report.Servers))
	fmt.Fprintf(out, "%-24s %-10s %s\n", "SERVER", "TRANSPORT", "RESULT")
	fmt.Fprintf(out, "%-24s %-10s %s\n", "------", "---------", "------")
	for _, result := range report.Servers {
		status := fmt.Sprintf("%d tools", result.ToolCount)
		if !result.Scanned {
			status = "could not be scanned"
		}
		fmt.Fprintf(out, "%-24s %-10s %s\n", result.Name, result.Transport, status)
	}
	fmt.Fprintln(out, "")
	issues := 0
	for _, finding := range report.Findings {
		if finding.Kind != "tool_shadowing" {
			issues++
		}
	}
	if issues == 0 {
		fmt.Fprintln(out, "No issues found in the advertised tool definitions.")
	}
	if len(report.Findings) == 0 {
		return
	}
	if issues == 0 {
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Notes:")
	} else {
		fmt.Fprintln(out, "Findings:")
	}
	for _, finding := range report.Findings {
		subject := finding.Server
		if finding.Tool != "" && finding.Server != "" {
			subject = finding.Server + "/" + finding.Tool
		} else if finding.Tool != "" {
			subject = finding.Tool
		}
		rule := finding.Kind
		if finding.Rule != "" {
			rule = finding.Kind + " " + finding.Rule
		}
		fmt.Fprintf(out, "  [%s] %s: %s - %s\n", finding.Severity, subject, rule, finding.Description)
	}
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Emit the scan report as JSON")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 30*time.Second, "How long to wait for servers to list their tools")
	rootCmd.AddCommand(scanCmd)
}
