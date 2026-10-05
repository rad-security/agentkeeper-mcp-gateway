package proxy

import (
	"sort"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/policy"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// In Enforce the client should see a clear reason a tool is unavailable rather
// than a tool that silently vanished. A tool blocked by policy or by a poisoned
// definition stays in tools/list under the same name, but its description is
// replaced with the block reason and its schema is emptied, and a server
// blocked whole is represented by a single placeholder tool. Calls to any of
// them keep returning the standard "Blocked by AgentKeeper" result.

const blockedToolSuffix = "agentkeeper_blocked"

// effectiveToolList is the Enforce view the client sees: blocked tools neutered
// in place, and one placeholder per blocked server appended.
func (p *Proxy) effectiveToolList(tools []interface{}, toolMap map[string]string, synced telemetry.SyncPolicy) []interface{} {
	out := p.neuterBlockedTools(tools, toolMap, synced)
	return append(out, p.blockedServerPlaceholders()...)
}

// neuterBlockedTools replaces each blocked tool with a stub and leaves the rest
// unchanged. It carries no server placeholders, so it also serves as the
// per-server effective manifest for evidence.
func (p *Proxy) neuterBlockedTools(tools []interface{}, toolMap map[string]string, synced telemetry.SyncPolicy) []interface{} {
	out := make([]interface{}, 0, len(tools)+1)
	for _, value := range tools {
		tool, ok := value.(map[string]interface{})
		if !ok {
			out = append(out, value)
			continue
		}
		name, _ := tool["name"].(string)
		serverName := toolMap[name]
		originalName := originalMCPName(serverName, name)
		if reason, blocked := p.toolBlockReason(serverName, originalName, name, tool, synced); blocked {
			out = append(out, blockedToolStub(name, reason))
			continue
		}
		out = append(out, tool)
	}
	return out
}

// toolBlockReason reports whether a listed tool is blocked on this route and
// why: the organization's blocked-tool rule, or a poisoned definition the route
// blocks (a critical finding where detections block, or invisible text).
func (p *Proxy) toolBlockReason(serverName, originalName, publicName string, tool map[string]interface{}, synced telemetry.SyncPolicy) (string, bool) {
	if result := policy.Evaluate(synced, serverName, originalName, nil); result.Verdict == "block" {
		return result.Reason, true
	}
	if p.config.DetectionEngine != nil {
		result, found := p.toolDescriptionDetection(definitionAsAdvertised(tool))
		if !found {
			result, found = p.poisonedTool(publicName)
		}
		if found {
			if applyDetectionPolicy(result, synced, p.config.Detection).Verdict == detection.VerdictBlock {
				return blockReasonText(result), true
			}
		}
	}
	return "", false
}

// blockReasonText keeps the stub description within the evidence pipeline's
// field bounds.
func blockReasonText(result detection.Result) string {
	reason := result.Description
	if reason == "" {
		reason = "the tool definition was flagged as poisoned"
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	return reason
}

// blockedToolStub is a listed tool with its description replaced by the block
// reason and an empty schema, so no upstream wording reaches the agent.
func blockedToolStub(name, reason string) map[string]interface{} {
	return map[string]interface{}{
		"name":        name,
		"description": "Blocked by AgentKeeper: " + reason + ". Calls to this tool are refused.",
		"inputSchema": map[string]interface{}{"type": "object"},
	}
}

// OnPolicyApplied tells the client its tool list may have changed after a
// policy or mode change (which tools are blocked, and the effective mode, both
// change what tools/list returns). It emits a notification only when the
// effective signature actually changed, so a steady-state heartbeat is quiet.
func (p *Proxy) OnPolicyApplied() {
	p.startNewlyPermittedUpstreams()
	var synced telemetry.SyncPolicy
	if p.telemetry != nil {
		synced = p.telemetry.Policy()
	}
	mode := "observe"
	if p.enforceMode() {
		mode = "enforce"
	}
	signature := mode + "\x00" + hashJSON(policySignatureView(synced))
	p.shadowMu.Lock()
	changed := p.policySignature != signature
	p.policySignature = signature
	p.shadowMu.Unlock()
	if changed {
		p.emitToolsListChanged()
	}
}

// policySignatureView is the synced policy with its lists sorted, so the same
// policy delivered in a different order does not count as a change.
func policySignatureView(synced telemetry.SyncPolicy) telemetry.SyncPolicy {
	view := synced
	view.BlockedServers = sortedCopy(synced.BlockedServers)
	view.CustomKeywords = sortedCopy(synced.CustomKeywords)
	if synced.BlockedTools != nil {
		view.BlockedTools = make(map[string][]string, len(synced.BlockedTools))
		for server, tools := range synced.BlockedTools {
			view.BlockedTools[server] = sortedCopy(tools)
		}
	}
	return view
}

func sortedCopy(values []string) []string {
	if values == nil {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// blockedServerPlaceholders returns one placeholder tool per configured server
// the policy blocks, so the client sees the server is governed rather than
// finding it simply absent.
func (p *Proxy) blockedServerPlaceholders() []interface{} {
	if p.manager == nil {
		return nil
	}
	names := p.manager.ConfiguredNames()
	sort.Strings(names)
	var out []interface{}
	for _, serverName := range names {
		if !p.serverBlockedByPolicy(serverName) {
			continue
		}
		out = append(out, map[string]interface{}{
			"name":        publicMCPName(serverName, blockedToolSuffix),
			"description": "AgentKeeper blocked the " + serverName + " MCP server. Its tools are unavailable on this workstation.",
			"inputSchema": map[string]interface{}{"type": "object"},
		})
	}
	return out
}
