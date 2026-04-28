package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
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
		jsonFlag, _ := cmd.Flags().GetBool("json")

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if len(cfg.Servers) == 0 {
			fmt.Println("No servers configured. Add one with:")
			fmt.Println("  agentkeeper-mcp-gateway add <name> <command>")
			return nil
		}

		if jsonFlag {
			data, _ := json.MarshalIndent(cfg.Servers, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("%-20s %-10s %s\n", "NAME", "TRANSPORT", "COMMAND/URL")
		fmt.Printf("%-20s %-10s %s\n", "----", "---------", "-----------")
		for _, s := range cfg.Servers {
			transport := s.Transport
			if transport == "" {
				transport = "stdio"
			}
			target := s.Command
			if s.URL != "" {
				target = s.URL
			}
			fmt.Printf("%-20s %-10s %s\n", s.Name, transport, target)
		}
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&listHealth, "health", false, "Include health check status")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output in JSON format")
	rootCmd.AddCommand(listCmd)
}
