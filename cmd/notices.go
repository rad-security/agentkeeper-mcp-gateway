package cmd

import (
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/notices"
	"github.com/spf13/cobra"
)

var noticesCmd = &cobra.Command{
	Use:   "notices",
	Short: "Print third-party license notices",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprint(cmd.OutOrStdout(), notices.Text())
	},
}

func init() {
	rootCmd.AddCommand(noticesCmd)
}
