package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	exportFormat string
	exportSince  string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export gateway event logs",
	Long:  `Export recorded MCP gateway events in JSON or CSV format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Exporting events in %s format...\n", exportFormat)
		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "json", "Output format (json or csv)")
	exportCmd.Flags().StringVar(&exportSince, "since", "", "Export events since date (YYYY-MM-DD)")
	rootCmd.AddCommand(exportCmd)
}
