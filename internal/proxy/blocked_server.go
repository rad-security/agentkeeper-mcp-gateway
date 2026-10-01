package proxy

import (
	"encoding/base64"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/policy"
)

// serverBlockedByPolicy reports whether organization policy denies a whole
// upstream on an enforcing route. Observe never blocks a server: the dashboard
// reports what Enforce would change while the user keeps the full catalog.
func (p *Proxy) serverBlockedByPolicy(serverName string) bool {
	if serverName == "" || p.telemetry == nil || !p.enforceMode() {
		return false
	}
	return policy.Evaluate(p.telemetry.Policy(), serverName, "", nil).Verdict == "block"
}

// upstreamStartPermitted is the server manager's start gate. A blocked server
// is third-party code the organization chose not to run; hiding its tools
// while still launching it would leave it executing on the workstation. The
// gate covers every start path: attach, the Cowork guard's reload, on-demand
// starts and the automatic restart after an exit.
func (p *Proxy) upstreamStartPermitted(name string) bool {
	if !p.serverBlockedByPolicy(name) {
		return true
	}
	p.policySkippedMu.Lock()
	if p.policySkipped == nil {
		p.policySkipped = make(map[string]bool)
	}
	p.policySkipped[name] = true
	p.policySkippedMu.Unlock()
	return false
}

// startNewlyPermittedUpstreams starts upstreams that were skipped at attach
// and are no longer blocked, after a policy or mode change.
func (p *Proxy) startNewlyPermittedUpstreams() {
	p.policySkippedMu.Lock()
	skipped := make([]string, 0, len(p.policySkipped))
	for name := range p.policySkipped {
		skipped = append(skipped, name)
	}
	p.policySkippedMu.Unlock()
	for _, name := range skipped {
		if p.serverBlockedByPolicy(name) {
			continue
		}
		if err := p.manager.EnsureStarted(name); err != nil {
			p.warn("could not start %s after its policy block was lifted: %v", name, err)
			continue
		}
		p.policySkippedMu.Lock()
		delete(p.policySkipped, name)
		p.policySkippedMu.Unlock()
	}
}

// permittedServerNames lists the running upstreams whose resources and prompts
// may be offered to the client.
func (p *Proxy) permittedServerNames() []string {
	p.startNewlyPermittedUpstreams()
	names := p.manager.ServerNames()
	permitted := names[:0]
	for _, name := range names {
		if !p.serverBlockedByPolicy(name) {
			permitted = append(permitted, name)
		}
	}
	return permitted
}

// blockedServerOwning returns the blocked upstream a namespaced tool or prompt
// name belongs to, without consulting or starting that upstream.
func (p *Proxy) blockedServerOwning(publicName string) (string, bool) {
	serverName := p.configuredServerForTool(publicName)
	return serverName, p.serverBlockedByPolicy(serverName)
}

// serverForNamespacedResourceURI reads the upstream name out of a resource URI
// minted by namespacedResourceURI.
func serverForNamespacedResourceURI(uri string) (string, bool) {
	rest, ok := strings.CutPrefix(uri, "agentkeeper://resource/")
	if !ok {
		return "", false
	}
	encodedServer, _, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	serverName, err := base64.RawURLEncoding.DecodeString(encodedServer)
	if err != nil || len(serverName) == 0 {
		return "", false
	}
	return string(serverName), true
}

// blockedServerContentResponse refuses a resource or prompt request to a
// blocked upstream before anything is dispatched, and records the refusal.
func (p *Proxy) blockedServerContentResponse(msg JSONRPCMessage, serverName, method string) *JSONRPCMessage {
	reason := policy.Evaluate(p.telemetry.Policy(), serverName, "", nil).Reason
	p.logToolOutcome(serverName, method, nil, detection.Result{
		Verdict: detection.VerdictBlock, PatternName: "blocked_server",
		Severity: "high", Description: reason, Category: "policy",
	}, logging.ToolCallOutcome{
		CallID: newEvidenceID("call"), AttemptID: newEvidenceID("attempt"), Mode: "enforce",
		PolicyDecision: "block", EvaluationStatus: "evaluated",
		RequiredDisposition: "deny_before_dispatch", AppliedDisposition: "denied_before_dispatch",
	})
	// Resources and prompts do not use the tools/call isError envelope.
	return &JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Error: &JSONRPCError{Code: -32003, Message: "Blocked by AgentKeeper: " + reason + "."}}
}
