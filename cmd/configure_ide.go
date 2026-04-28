package cmd

import (
	"fmt"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/ideconfig"
	"github.com/spf13/cobra"
)

var (
	configureIDEDryRun bool
	configureIDETarget []string
)

var configureIDECmd = &cobra.Command{
	Use:   "configure-ide",
	Short: "Rewrite local IDE MCP configs to route through the gateway",
	Long: `Point your AI coding IDE(s) at the gateway with a single command.

Finds installed IDE configs (Claude Code, Claude Desktop, Cursor), backs each
one up, and rewrites the MCP server list so the only entry is the AgentKeeper
gateway. Any previously-registered MCP servers are migrated into the gateway's
own config so no wiring is lost.

This command is idempotent — if an IDE is already pointing at the gateway and
nothing else, running it again is a no-op.

By default every detected IDE is configured. Use --ide to target just one.
Use --dry-run to preview changes without writing anything.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		adapters := ideconfig.Adapters()

		// Filter by --ide if provided.
		if len(configureIDETarget) > 0 {
			wanted := map[string]bool{}
			for _, t := range configureIDETarget {
				wanted[strings.ToLower(t)] = true
			}
			filtered := adapters[:0]
			for _, a := range adapters {
				if wanted[a.Name] {
					filtered = append(filtered, a)
				}
			}
			adapters = filtered
			if len(adapters) == 0 {
				return fmt.Errorf("no matching IDE (known: claude-code, claude-desktop, cursor)")
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

		if len(migratedAll) == 0 {
			fmt.Fprintln(out, "")
			if configureIDEDryRun {
				fmt.Fprintln(out, "(dry-run — no files written)")
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
			// IDE "type:http" ↔ gateway "transport:http"
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
			fmt.Fprintln(out, "(dry-run — no files written)")
		}
		return nil
	},
}

func printPlan(out interface {
	Write(p []byte) (int, error)
}, ide string, p ideconfig.Plan) {
	status := "would wire"
	if configureIDEDryRun {
		// keep the same verb — it's already hypothetical by flag
	}
	switch {
	case p.AlreadyWired:
		status = "already wired"
	case !p.Exists:
		status = "create"
	case len(p.Migrated) > 0:
		status = fmt.Sprintf("migrate %d + wire", len(p.Migrated))
	}
	fmt.Fprintf(out, "  %-16s %s — %s\n", ide, status, p.ConfigPath)
	for _, m := range p.Migrated {
		fmt.Fprintf(out, "    → migrate: %s (%s)\n", m.Name, renderCommand(m.Entry))
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

func init() {
	configureIDECmd.Flags().BoolVar(&configureIDEDryRun, "dry-run", false, "Preview changes without writing any files")
	configureIDECmd.Flags().StringSliceVar(&configureIDETarget, "ide", nil, "Restrict to a specific IDE (claude-code, claude-desktop, cursor). Repeatable.")
	rootCmd.AddCommand(configureIDECmd)
}
