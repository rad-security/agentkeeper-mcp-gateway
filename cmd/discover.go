package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/spf13/cobra"
)

var (
	discoverClient string
	discoverIDE    string
	discoverCWD    string
	discoverJSON   bool
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover local MCP servers without relying on hooks",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := discoverClient
		if discoverIDE != "" {
			client = discoverIDE
		}
		res, err := discovery.Discover(discovery.Options{
			Client: client,
			CWD:    discoverCWD,
		})
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if discoverJSON {
			data, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(out, string(data))
			return nil
		}
		if len(res.Servers) == 0 {
			fmt.Fprintln(out, "No MCP servers discovered.")
			return nil
		}
		for _, s := range res.Servers {
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Client, s.Scope, s.RouteState, s.Routeability, s.Name, s.SourcePath)
		}
		return nil
	},
}

func init() {
	discoverCmd.Flags().StringVar(&discoverClient, "client", "all", "Client to scan (all, claude-code, claude-desktop, cowork)")
	discoverCmd.Flags().StringVar(&discoverIDE, "ide", "", "Alias for --client")
	discoverCmd.Flags().StringVar(&discoverCWD, "cwd", "", "Project directory for project/local scoped MCP discovery")
	discoverCmd.Flags().BoolVar(&discoverJSON, "json", false, "Emit JSON")
	rootCmd.AddCommand(discoverCmd)
}
