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
	Short: "Fallback/admin registration for a Gateway-native MCP server",
	Long: `Register an MCP server directly with the gateway when there is no
supported local MCP client config to migrate. For normal workstation rollout,
run configure-ide --dry-run and configure-ide first.

The server can be a local stdio command or a remote http(s) URL.

Examples:
  agentkeeper-mcp-gateway add filesystem npx -y @modelcontextprotocol/server-filesystem /tmp
  agentkeeper-mcp-gateway add remote-api https://api.example.com/mcp --header "Authorization:Bearer tok"`,
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

		headerFlags, _ := cmd.Flags().GetStringArray("header")
		if len(headerFlags) > 0 {
			if entry.Transport != "http" {
				return fmt.Errorf("--header applies only to a remote (http/https) server URL")
			}
			headers, err := parseAddHeaders(headerFlags)
			if err != nil {
				return err
			}
			entry.Headers = headers
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

// parseAddHeaders turns repeated --header "Key:Value" flags into request
// headers. The first colon separates the key; values may contain colons.
func parseAddHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, ":")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid --header %q: use key:value", raw)
		}
		headers[key] = strings.TrimSpace(value)
	}
	return headers, nil
}

func init() {
	addCmd.Flags().StringVar(&addEnv, "env", "", "JSON environment variables for the server process")
	addCmd.Flags().StringArrayVar(&addHeaders, "header", nil, "Request header for a remote server (key:value); repeatable")
	rootCmd.AddCommand(addCmd)
}
