package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/runtimebroker"
	"github.com/spf13/cobra"
)

var enterpriseCapabilitiesJSON bool

var enterpriseCapabilitiesCmd = &cobra.Command{
	Use:   "enterprise-capabilities",
	Short: "Report machine-verifiable enterprise installer capabilities",
	RunE: func(cmd *cobra.Command, _ []string) error {
		capabilities := runtimebroker.EnterpriseCapabilities()
		if !enterpriseCapabilitiesJSON {
			return fmt.Errorf("--json is required")
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(capabilities)
	},
}

func init() {
	enterpriseCapabilitiesCmd.Flags().BoolVar(&enterpriseCapabilitiesJSON, "json", false, "emit the capability contract as JSON")
	rootCmd.AddCommand(enterpriseCapabilitiesCmd)
}
