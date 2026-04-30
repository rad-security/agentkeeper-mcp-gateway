package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/coworkposture"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/machineid"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/skillinventory"
	"github.com/spf13/cobra"
)

var (
	scanInventoryDryRun        bool
	scanInventoryCWD           string
	scanInventoryClaudeVersion string
)

var scanInventoryCmd = &cobra.Command{
	Use:   "scan-inventory",
	Short: "Scan Claude Code inventory and Claude Desktop/Cowork posture; report to AgentKeeper",
	Long: `Walk the developer's laptop for installed Claude Code skills and
configured MCP servers, collect read-only Claude Desktop/Cowork posture, then
POST inventory to /api/v1/claude-code/checkin and posture to /api/v1/scans.

Designed to run as a SessionStart hook in ~/.claude/settings.json:

  "SessionStart": [{
    "matcher": "*",
    "hooks": [{
      "type": "command",
      "command": "/usr/local/bin/agentkeeper-mcp-gateway scan-inventory",
      "timeout": 30
    }]
  }]

Claude Code pipes a JSON envelope on stdin containing the session's cwd; the
subcommand reads it, scans the filesystem, and posts the result. Fail-open by
design — network errors and individual unreadable files never break the hook.

Auth and API URL come from the standard gateway config chain:
  --config flag → $AGENTKEEPER_CONFIG → $XDG_CONFIG_HOME → $HOME/.config → /etc/...

With --dry-run, prints the JSON body it WOULD post and exits without making
the network call.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try stdin for Claude Code's hook envelope (session_id, cwd, ...).
		// Best effort — the flag takes precedence, and invocation without
		// stdin is fine for manual testing.
		cwd := scanInventoryCWD
		claudeVersion := scanInventoryClaudeVersion
		if cwd == "" {
			if stdinCWD, stdinVer := readHookEnvelope(cmd.InOrStdin()); stdinCWD != "" {
				cwd = stdinCWD
				if claudeVersion == "" {
					claudeVersion = stdinVer
				}
			}
		}

		inv, err := skillinventory.Scan(skillinventory.ScanOptions{CWD: cwd})
		if err != nil {
			// Fail-open: log and still exit 0 so SessionStart never blocks.
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: scan error: %v\n", err)
			return nil
		}

		machineID := machineid.Detect()
		payload := skillinventory.BuildPayload(inv, cwd, claudeVersion, machineID)
		posturePayload, postureErr := coworkposture.Scan(coworkposture.ScanOptions{
			AgentVersion: version,
			MachineID:    machineID,
		})
		if postureErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: cowork posture scan error: %v\n", postureErr)
		}

		if scanInventoryDryRun {
			dryRunPayload := struct {
				skillinventory.CheckinPayload
				CoworkPosture *coworkposture.ScanPayload `json:"cowork_posture,omitempty"`
			}{
				CheckinPayload: payload,
			}
			if postureErr == nil && posturePayload.Detected() {
				dryRunPayload.CoworkPosture = &posturePayload
			}
			out, _ := json.MarshalIndent(dryRunPayload, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		}

		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: config error: %v\n", err)
			return nil
		}
		if cfg.APIKey == "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "scan-inventory: no API key — skipping upload (run `agentkeeper-mcp-gateway auth login` or set AGENTKEEPER_API_KEY)")
			return nil
		}

		respBody, err := skillinventory.Send(cfg.APIURL, cfg.APIKey, machineID, payload)
		if err != nil {
			// Log, don't fail — SessionStart must never block Claude Code.
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: upload error: %v\n", err)
			return nil
		}
		var postureRespBody []byte
		if postureErr == nil && posturePayload.Detected() {
			postureRespBody, err = coworkposture.Send(cfg.APIURL, cfg.APIKey, machineID, posturePayload)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: cowork posture upload error: %v\n", err)
				return nil
			}
		}
		if verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: %d skills, %d MCP servers reported; response: %s\n",
				len(inv.Skills), len(inv.MCPServers), truncateForLog(string(respBody), 120))
			if len(postureRespBody) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "scan-inventory: cowork posture score=%d grade=%s checks=%d; response: %s\n",
					posturePayload.Score, posturePayload.Grade, len(posturePayload.Checks), truncateForLog(string(postureRespBody), 120))
			}
		}
		return nil
	},
}

// readHookEnvelope extracts cwd + claude_version from the JSON Claude Code pipes
// on stdin for hook invocations. Best effort — never errors.
//
// When stdin is a TTY (interactive terminal) there is no hook envelope to
// read, and io.ReadAll would block forever waiting for a non-existent EOF.
// Skip the read in that case so that manually invoking `scan-inventory`
// from a shell completes promptly instead of hanging.
func readHookEnvelope(r io.Reader) (cwd, claudeVersion string) {
	if isTerminal(r) {
		return "", ""
	}
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil || len(data) == 0 {
		return "", ""
	}
	var env struct {
		CWD           string `json:"cwd"`
		ClaudeVersion string `json:"claude_version"`
	}
	_ = json.Unmarshal(data, &env)
	return env.CWD, env.ClaudeVersion
}

// isTerminal reports whether r is an *os.File attached to a character device
// (terminal). Returns false for bytes.Buffers, pipes, regular files, and
// anything that isn't an *os.File, so tests and hook invocations keep the
// existing read path.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func truncateForLog(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	scanInventoryCmd.Flags().BoolVar(&scanInventoryDryRun, "dry-run", false, "Print the payload that would be POSTed and exit without sending")
	scanInventoryCmd.Flags().StringVar(&scanInventoryCWD, "cwd", "", "Working directory to scan for project-scoped skills / MCP servers (defaults to stdin)")
	scanInventoryCmd.Flags().StringVar(&scanInventoryClaudeVersion, "claude-version", "", "Claude Code version string (defaults to stdin)")
	rootCmd.AddCommand(scanInventoryCmd)
}
