package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage gateway configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration and where each field came from",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := config.LoadWithSource(
			config.ResolveConfigPath(configPath, config.DefaultSystemConfigPath()),
		)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "# config path: %s\n", res.Path)
		fmt.Fprintf(cmd.OutOrStdout(), "# api_key:     %s\n", res.APIKeySource)
		fmt.Fprintf(cmd.OutOrStdout(), "# api_url:     %s\n", res.APIURLSource)
		data, _ := json.MarshalIndent(res.Config, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}
