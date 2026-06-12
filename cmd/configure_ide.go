package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
	"github.com/spf13/cobra"
)

var (
	configureIDEDryRun bool
	configureIDETarget []string
	configureIDECWD    string
	configureIDEScope  string
	configureIDEJSON   bool
)

var configureIDECmd = &cobra.Command{
	Use:   "configure-ide",
	Short: "Rewrite local IDE MCP configs to route through the gateway",
	Long: `Point your AI coding IDE(s) at the gateway with a single command.

Finds supported local MCP client configs (Claude Code, Claude Desktop, Cursor,
and Cowork MCP sources), backs each one up, and rewrites the MCP server list so
the client launches AgentKeeper Gateway. Any previously-registered MCP servers
are migrated into the gateway's own config so no wiring is lost.

This command is idempotent - if an IDE is already pointing at the gateway and
nothing else, running it again is a no-op.

By default every detected IDE is configured. Use --ide to target just one.
	Use --dry-run to preview changes without writing anything.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		if shouldUseProjectMigration() {
			cwd := configureIDECWD
			if strings.TrimSpace(cwd) == "" {
				var err error
				cwd, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			plan, err := discovery.MigrateProjectMCP(cwd, configureIDEDryRun)
			if err != nil {
				return err
			}
			if configureIDEJSON {
				data, err := json.MarshalIndent(plan, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(data))
				return nil
			}
			printProjectMigrationPlan(out, plan)
			if configureIDEDryRun {
				fmt.Fprintln(out, "")
				fmt.Fprintln(out, "(dry-run - no files written)")
			}
			return nil
		}

		adapters := ideconfig.Adapters()

		// Filter by --ide if provided.
		if len(configureIDETarget) > 0 {
			wanted := map[string]bool{}
			for _, t := range configureIDETarget {
				wanted[strings.ToLower(t)] = true
			}
			wantsCowork := wanted[discovery.ClientCowork]
			filtered := adapters[:0]
			for _, a := range adapters {
				if wanted[a.Name] {
					filtered = append(filtered, a)
				}
			}
			adapters = filtered
			if len(adapters) == 0 && !wantsCowork {
				return fmt.Errorf("no matching IDE (known: claude-code, claude-desktop, cursor, cowork)")
			}
		}

		var migratedAll []ideconfig.NamedServer
		for _, a := range adapters {
			plan, err := a.Plan()
			if err != nil {
				fmt.Fprintf(out, "  %-16s error planning: %v\n", a.Name, err)
				continue
			}
			printPlan(out, a.Name, plan)
			if configureIDEDryRun {
				continue
			}
			if err := a.Apply(&plan); err != nil {
				fmt.Fprintf(out, "  %-16s error applying: %v\n", a.Name, err)
				continue
			}
			if plan.BackupPath != "" {
				fmt.Fprintf(out, "  %-16s backup: %s\n", "", plan.BackupPath)
			}
			migratedAll = append(migratedAll, plan.Migrated...)
		}

		if configureIDETargetIncludes("claude-code") {
			plan, err := discovery.MigrateClaudeJSONUser(configureIDEDryRun)
			if err != nil {
				fmt.Fprintf(out, "  %-16s error applying: %v\n", "claude-code:user", err)
			} else {
				printMigrationPlan(out, plan)
			}
			plan, err = discovery.MigrateClaudeJSONProjects(configureIDEDryRun)
			if err != nil {
				fmt.Fprintf(out, "  %-16s error applying: %v\n", "claude-code:projects", err)
			} else {
				printMigrationPlan(out, plan)
			}
			if cwd, ok, err := projectMigrationCWD(); err != nil {
				fmt.Fprintf(out, "  %-16s error applying: %v\n", "claude-code:project", err)
			} else if ok {
				plan, err = discovery.MigrateProjectMCP(cwd, configureIDEDryRun)
				if err != nil {
					fmt.Fprintf(out, "  %-16s error applying: %v\n", "claude-code:project", err)
				} else {
					printMigrationPlan(out, plan)
				}
			}
		}

		if configureIDETargetIncludes(discovery.ClientCowork) {
			result, err := discovery.MigrateCoworkMCP("", configureIDEDryRun)
			if err != nil {
				fmt.Fprintf(out, "  %-16s error applying: %v\n", discovery.ClientCowork, err)
			} else {
				for _, plan := range result.Plans {
					printCoworkMigrationPlan(out, plan)
				}
				if result.GatewayEntrypoint != nil {
					wasCoworkDryRun := coworkDryRun
					coworkDryRun = configureIDEDryRun
					printCoworkGatewayEntrypointPlan(out, *result.GatewayEntrypoint)
					coworkDryRun = wasCoworkDryRun
				}
			}
		}

		if len(migratedAll) == 0 {
			fmt.Fprintln(out, "")
			if configureIDEDryRun {
				fmt.Fprintln(out, "(dry-run - no files written)")
			}
			return nil
		}

		// Move migrated servers into the gateway's own config. De-dupe by name
		// to avoid double-registering when multiple IDEs list the same server.
		seen := map[string]bool{}
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Migrating servers into gateway config:")
		for _, s := range migratedAll {
			if seen[s.Name] {
				continue
			}
			seen[s.Name] = true
			if configureIDEDryRun {
				fmt.Fprintf(out, "  would add: %s (%s)\n", s.Name, renderCommand(s.Entry))
				continue
			}
			entry := config.ServerEntry{
				Name:    s.Name,
				Command: s.Entry.Command,
				Args:    s.Entry.Args,
				Env:     s.Entry.Env,
				URL:     s.Entry.URL,
				Headers: s.Entry.Headers,
			}
			// IDE "type:http" maps to gateway "transport:http"
			if s.Entry.Type != "" {
				entry.Transport = s.Entry.Type
			}
			if err := config.AddServer(entry); err != nil {
				fmt.Fprintf(out, "  error adding %s to gateway config: %v\n", s.Name, err)
				continue
			}
			fmt.Fprintf(out, "  added: %s\n", s.Name)
		}
		if configureIDEDryRun {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "(dry-run - no files written)")
		}
		return nil
	},
}

func printPlan(out interface {
	Write(p []byte) (int, error)
}, ide string, p ideconfig.Plan) {
	status := "would wire"
	if configureIDEDryRun {
		// keep the same verb; it's already hypothetical by flag
	}
	switch {
	case p.AlreadyWired:
		status = "already wired"
	case !p.Exists:
		status = "create"
	case len(p.Migrated) > 0:
		status = fmt.Sprintf("migrate %d + wire", len(p.Migrated))
	}
	fmt.Fprintf(out, "  %-16s %s - %s\n", ide, status, p.ConfigPath)
	for _, m := range p.Migrated {
		fmt.Fprintf(out, "    -> migrate: %s (%s)\n", m.Name, renderCommand(m.Entry))
	}
}

func renderCommand(e ideconfig.ServerEntry) string {
	if e.URL != "" {
		return e.URL
	}
	if e.Command == "" {
		return "(empty command)"
	}
	if len(e.Args) == 0 {
		return e.Command
	}
	return e.Command + " " + strings.Join(e.Args, " ")
}

func shouldUseProjectMigration() bool {
	if configureIDECWD == "" && configureIDEScope != "project" {
		return false
	}
	if configureIDEScope != "" && configureIDEScope != "project" {
		return false
	}
	if len(configureIDETarget) == 0 {
		return false
	}
	for _, t := range configureIDETarget {
		if strings.ToLower(t) != "claude-code" {
			return false
		}
	}
	return true
}

func configureIDETargetIncludes(target string) bool {
	if len(configureIDETarget) == 0 {
		return true
	}
	target = strings.ToLower(target)
	for _, t := range configureIDETarget {
		if strings.ToLower(t) == target {
			return true
		}
	}
	return false
}

func projectMigrationCWD() (string, bool, error) {
	if configureIDEScope != "" && configureIDEScope != "project" {
		return "", false, nil
	}
	if strings.TrimSpace(configureIDECWD) != "" {
		return configureIDECWD, true, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", false, err
	}
	if configureIDEScope == "project" {
		return cwd, true, nil
	}
	if _, err := os.Stat(filepath.Join(cwd, ".mcp.json")); err == nil {
		return cwd, true, nil
	} else if !os.IsNotExist(err) {
		return "", false, err
	}
	return "", false, nil
}

func printProjectMigrationPlan(out interface {
	Write(p []byte) (int, error)
}, plan discovery.MigrationPlan) {
	printMigrationPlan(out, plan)
}

func printMigrationPlan(out interface {
	Write(p []byte) (int, error)
}, plan discovery.MigrationPlan) {
	status := "no MCP servers discovered"
	if plan.AlreadyRouted {
		status = "already routed"
	} else if len(plan.Servers) > 0 {
		status = fmt.Sprintf("migrate %d + wire", len(plan.Servers))
	}
	label := plan.Client
	if plan.Scope != "" && plan.Scope != "global" {
		label = fmt.Sprintf("%s:%s", plan.Client, plan.Scope)
	}
	fmt.Fprintf(out, "  %-16s %s - %s\n", label, status, plan.ConfigPath)
	for _, s := range plan.Servers {
		if s.RouteState == discovery.RouteRouted {
			continue
		}
		rendered := s.Command
		if rendered == "" {
			rendered = s.URL
		}
		if s.ArgsCount > 0 {
			rendered = fmt.Sprintf("%s (%d args)", rendered, s.ArgsCount)
		}
		fmt.Fprintf(out, "    -> migrate: %s (%s)\n", s.Name, rendered)
	}
	if plan.BackupPath != "" {
		fmt.Fprintf(out, "  %-16s backup: %s\n", "", plan.BackupPath)
	}
}

func init() {
	configureIDECmd.Flags().BoolVar(&configureIDEDryRun, "dry-run", false, "Preview changes without writing any files")
	configureIDECmd.Flags().StringSliceVar(&configureIDETarget, "ide", nil, "Restrict to a specific MCP client (claude-code, claude-desktop, cursor, cowork). Repeatable.")
	configureIDECmd.Flags().StringVar(&configureIDECWD, "cwd", "", "Project directory for Claude Code project-scoped MCP migration")
	configureIDECmd.Flags().StringVar(&configureIDEScope, "scope", "", "MCP scope to configure (project for Claude Code .mcp.json)")
	configureIDECmd.Flags().BoolVar(&configureIDEJSON, "json", false, "Emit JSON for project-scoped migration")
	rootCmd.AddCommand(configureIDECmd)
}
