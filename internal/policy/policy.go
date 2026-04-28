// Package policy evaluates MCP tool calls against dashboard-managed
// access policies: blocked servers, blocked tools, and custom keywords.
package policy

import (
	"encoding/json"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// Result holds the outcome of a policy evaluation.
type Result struct {
	Verdict string // "allow", "warn", "block"
	Reason  string // human-readable explanation
	Rule    string // "blocked_server", "blocked_tool", "custom_keyword", ""
}

// Evaluate checks a tool call against the synced dashboard policy.
// Evaluation order: blocked server → blocked tool → custom keywords → allow.
func Evaluate(p telemetry.SyncPolicy, serverName, toolName string, args map[string]interface{}) Result {
	// 1. Blocked server?
	for _, s := range p.BlockedServers {
		if strings.EqualFold(s, serverName) {
			return Result{
				Verdict: "block",
				Reason:  "Server '" + serverName + "' is blocked by organization policy",
				Rule:    "blocked_server",
			}
		}
	}

	// 2. Blocked tool?
	for srvKey, tools := range p.BlockedTools {
		if !strings.EqualFold(srvKey, serverName) {
			continue
		}
		for _, t := range tools {
			if strings.EqualFold(t, toolName) {
				return Result{
					Verdict: "block",
					Reason:  "Tool '" + serverName + "/" + toolName + "' is blocked by organization policy",
					Rule:    "blocked_tool",
				}
			}
		}
	}

	// 3. Custom keywords in args?
	if len(p.CustomKeywords) > 0 && args != nil {
		argsJSON, err := json.Marshal(args)
		if err == nil {
			argsLower := strings.ToLower(string(argsJSON))
			for _, kw := range p.CustomKeywords {
				if strings.Contains(argsLower, strings.ToLower(kw)) {
					verdict := p.Detection.SensitiveData
					if verdict != "block" {
						verdict = "warn"
					}
					return Result{
						Verdict: verdict,
						Reason:  "Custom keyword '" + kw + "' detected in tool arguments",
						Rule:    "custom_keyword",
					}
				}
			}
		}
	}

	return Result{Verdict: "allow"}
}
