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
	Use:   "add [flags] <name> <command_or_url> [args...]",
	Short: "Fallback/admin registration for a Gateway-native MCP server",
	Long: `Register an MCP server directly with the gateway when there is no
supported local MCP client config to migrate. For normal workstation rollout,
run configure-ide --dry-run and configure-ide first.

The server can be a local stdio command or a remote http(s) URL. Everything
after a stdio command is passed to that command, so put add's own flags
before it. To give the command an argument spelled like one of add's flags
(--env, --header, --config), put -- before the command. Flags may also
follow a URL.

Examples:
  agentkeeper-mcp-gateway add filesystem npx -y @modelcontextprotocol/server-filesystem /tmp
  agentkeeper-mcp-gateway add --env '{"API_TOKEN":"..."}' local-api python3 server.py --port 8080
  agentkeeper-mcp-gateway add local-api -- python3 server.py --config server.toml
  agentkeeper-mcp-gateway add remote-api https://api.example.com/mcp --header "Authorization:Bearer tok"`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		server, err := addServerArgs(cmd, args[1:])
		// cobra checked --help before addServerArgs parsed the rest.
		if help, _ := cmd.Flags().GetBool("help"); help {
			return cmd.Help()
		}
		if err != nil {
			return err
		}
		command := strings.Join(server, " ")
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
		if isRemoteURL(command) {
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

// addServerArgs returns the server command (or URL) from the arguments that
// follow <name>. Interspersed flag parsing is off for add (see init), so cobra
// stops at <name> and a command's own flags (`npx -y ...`) reach the gateway
// config untouched. Two places still take add's flags: between <name> and the
// command, where a `--` separator may also sit, and after a URL, which takes
// no arguments of its own (the documented `add <name> <url> --header
// key:value` form). After a stdio command add's flags are refused unless a
// `--` says they are the command's (see misplacedAddFlag).
func addServerArgs(cmd *cobra.Command, rest []string) ([]string, error) {
	flags := cmd.Flags()
	if err := flags.Parse(rest); err != nil {
		return nil, err
	}
	server := flags.Args()
	if len(server) == 0 {
		return nil, fmt.Errorf("requires a server command or URL after the name")
	}
	if isRemoteURL(server[0]) {
		if err := flags.Parse(server[1:]); err != nil {
			return nil, err
		}
		if flags.NArg() > 0 {
			return nil, fmt.Errorf("unexpected argument %q after server URL", flags.Arg(0))
		}
		server = server[:1]
	} else if flags.ArgsLenAtDash() < 0 {
		if flag := misplacedAddFlag(cmd, server[1:]); flag != "" {
			return nil, fmt.Errorf(`%s after the server command would be passed to the server, not applied by add: put it before the server command, or put "--" before the server command to pass it through (add <name> -- <command> [args...])`, flag)
		}
	}
	// --config may have been parsed just now, after the root command applied it.
	config.SetPathOverride(configPath)
	return server, nil
}

// addOwnFlags are the flags the previous release also accepted after a stdio
// command. There they are now the command's arguments, which would silently
// drop the env, headers or config path and keep a token in the command string.
var addOwnFlags = []string{"env", "header", "config"}

// misplacedAddFlag returns the first of add's own flags, as its name only,
// among a stdio command's arguments, or "". A `--` among them ends the
// search: what follows it is explicitly the server's.
func misplacedAddFlag(cmd *cobra.Command, serverArgs []string) string {
	for _, arg := range serverArgs {
		if arg == "--" {
			break
		}
		for _, name := range addOwnFlags {
			long := "--" + name
			if arg == long || strings.HasPrefix(arg, long+"=") {
				return long
			}
			flag := cmd.Flags().Lookup(name)
			if flag == nil || flag.Shorthand == "" {
				continue
			}
			if short := "-" + flag.Shorthand; !strings.HasPrefix(arg, "--") && strings.HasPrefix(arg, short) {
				return short
			}
		}
	}
	return ""
}

func isRemoteURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
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
	// Stop at the first positional argument so flags that follow the server
	// command belong to that command, not to add (see addServerArgs).
	addCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(addCmd)
}
