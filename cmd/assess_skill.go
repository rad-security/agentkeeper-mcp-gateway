package cmd

import (
	"encoding/json"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/skillinventory"
	"github.com/spf13/cobra"
)

func newAssessSkillCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "assess-skill DIRECTORY",
		Short: "Assess a local skill package without executing or uploading its contents",
		Long:  "Read a bounded skill package and emit metadata-only JSON findings and a package digest. Requires a directory, never follows package symlinks, and never executes scripts or contacts the network. Partial/unsupported scans explicitly report incomplete assessment. Findings are review indicators, not malware convictions or runtime blocking decisions.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			assessment := skillinventory.AssessPackage(cmd.Context(), args[0], skillinventory.DefaultAssessmentLimits())
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(assessment)
		},
	}
}

func init() { rootCmd.AddCommand(newAssessSkillCommand()) }
