package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	logsFollow bool
	logsLines  int
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View gateway event logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")

		home, _ := os.UserHomeDir()
		logPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")

		if follow {
			// Tail -f equivalent
			tailCmd := exec.Command("tail", "-f", logPath)
			tailCmd.Stdout = os.Stdout
			tailCmd.Stderr = os.Stderr
			return tailCmd.Run()
		}

		// Show last N lines
		tailCmd := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logPath)
		tailCmd.Stdout = os.Stdout
		tailCmd.Stderr = os.Stderr
		return tailCmd.Run()
	},
}

func init() {
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow log output")
	logsCmd.Flags().IntVarP(&logsLines, "lines", "l", 20, "Number of lines to show")
	rootCmd.AddCommand(logsCmd)
}
