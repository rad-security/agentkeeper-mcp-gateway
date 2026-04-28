package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/spf13/cobra"
)

var (
	addEnv     string
	addHeaders []string
)

var addCmd = &cobra.Command{
	Use:   "add <name> <command_or_url>",
	Short: "Register an MCP server with the gateway",
	Long: `Register an MCP server to be proxied through the gateway. The server
can be a local stdio command or a remote SSE URL.

Examples:
  agentkeeper-mcp-gateway add filesystem npx -y @modelcontextprotocol/server-filesystem /tmp
  agentkeeper-mcp-gateway add remote-api https://api.example.com/mcp/sse --header "Authorization:Bearer tok"`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		command := strings.Join(args[1:], " ")
		envFlag, _ := cmd.Flags().GetString("env")

		entry := config.ServerEntry{
			Name:    name,
			Command: command,
		}

		// Parse env JSON if provided
		if envFlag != "" {
			var env map[string]string
			if err := json.Unmarshal([]byte(envFlag), &env); err != nil {
				return fmt.Errorf("invalid --env JSON: %w", err)
			}
			entry.Env = env
		}

		// Detect transport
		if strings.HasPrefix(command, "http://") || strings.HasPrefix(command, "https://") {
			entry.Transport = "http"
			entry.URL = command
			entry.Command = ""
		}

		if err := config.AddServer(entry); err != nil {
			return err
		}

		fmt.Printf("Added server: %s\n", name)
		if entry.Transport == "http" {
			fmt.Printf("  URL: %s\n", entry.URL)
		} else {
			fmt.Printf("  Command: %s\n", command)
		}
		return nil
	},
}

func init() {
	addCmd.Flags().StringVar(&addEnv, "env", "", "JSON environment variables for the server process")
	addCmd.Flags().StringSliceVar(&addHeaders, "header", nil, "Headers for SSE connections (key:value)")
	rootCmd.AddCommand(addCmd)
}
