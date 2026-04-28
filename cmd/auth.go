package cmd

import (
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/auth"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication with AgentKeeper Cloud",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with AgentKeeper Cloud",
	RunE: func(cmd *cobra.Command, args []string) error {
		return auth.Login()
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		return auth.Status()
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		return auth.Logout()
	},
}

func init() {
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authLogoutCmd)
	rootCmd.AddCommand(authCmd)
}
