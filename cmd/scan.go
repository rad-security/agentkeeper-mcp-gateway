package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan connected MCP servers for security issues",
	Long: `Run an on-demand security audit of all registered MCP servers.
Checks for tool shadowing, excessive permissions, prompt injection
patterns, and sensitive data exposure.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Scanning registered MCP servers...")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
