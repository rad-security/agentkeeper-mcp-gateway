package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
)

func validResourceResult(raw json.RawMessage) bool {
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return false
	}
	var contents []map[string]json.RawMessage
	if json.Unmarshal(result["contents"], &contents) != nil || contents == nil {
		return false
	}
	for _, content := range contents {
		var uri string
		if json.Unmarshal(content["uri"], &uri) != nil || uri == "" {
			return false
		}
		text, hasText := content["text"]
		blob, hasBlob := content["blob"]
		if hasText == hasBlob {
			return false
		}
		var value *string
		if hasText {
			if json.Unmarshal(text, &value) != nil || value == nil {
				return false
			}
		} else {
			if json.Unmarshal(blob, &value) != nil || value == nil {
				return false
			}
			if _, err := base64.StdEncoding.DecodeString(*value); err != nil {
				return false
			}
		}
	}
	return true
}
func (p *Proxy) invalidResourceResponse(id *json.RawMessage, server string, enforce bool) *JSONRPCMessage {
	outcome := logging.ToolCallOutcome{CallID: newEvidenceID("call"), AttemptID: newEvidenceID("attempt"), Mode: "observe", PolicyDecision: "warn", EvaluationStatus: "invalid_response", RequiredDisposition: "forward", AppliedDisposition: "response_invalid", Dispatched: true, ResultReceived: true, FailureReason: "invalid_resource_response"}
	if enforce {
		outcome.Mode = "enforce"
	}
	p.logToolOutcome(server, "resources/read", nil, detection.Result{Verdict: detection.VerdictWarn, Description: "Upstream resource response did not satisfy the MCP resource schema."}, outcome)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32004, Message: "Invalid resource response from upstream MCP server."}}
}
func (p *Proxy) contentCallFailure(id *json.RawMessage, server, method string, enforce, dispatched bool, err error) *JSONRPCMessage {
	outcome := logging.ToolCallOutcome{CallID: newEvidenceID("call"), AttemptID: newEvidenceID("attempt"), Mode: "observe", PolicyDecision: "pass", EvaluationStatus: "degraded_local", RequiredDisposition: "forward", AppliedDisposition: "dispatch_failed", Dispatched: dispatched, FailureReason: "upstream_call_failed"}
	code := -32603
	message := "Upstream MCP content request failed."
	if enforce {
		outcome.Mode = "enforce"
	}
	if errors.Is(err, context.Canceled) {
		code = -32800
		message = "Request cancelled"
		outcome.FailureReason = "client_cancelled"
		if dispatched {
			outcome.AppliedDisposition = "client_cancelled"
		}
	}
	p.logToolOutcome(server, method, nil, detection.Result{Verdict: detection.VerdictPass}, outcome)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: code, Message: message}}
}
