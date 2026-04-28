package cmd

import (
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Unregister an MCP server from the gateway",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := config.RemoveServer(name); err != nil {
			return err
		}
		fmt.Printf("Removed server: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)
}
