package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	mcpserver "github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
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
	var data json.RawMessage
	code := -32603
	message := "Upstream MCP content request failed."
	if enforce {
		outcome.Mode = "enforce"
	}
	result := detection.Result{Verdict: detection.VerdictPass}
	var upstreamError *mcpserver.RPCError
	if dispatched && errors.As(err, &upstreamError) {
		code, message, data = upstreamError.Code, upstreamError.Message, upstreamError.Data
		outcome.AppliedDisposition = "result_returned"
		outcome.ResultReceived, outcome.ResultReturned = true, true
		outcome.FailureReason = "upstream_rpc_error"
		outcome.EvaluationStatus = "evaluated"
		if p.config.DetectionEngine != nil {
			raw, _ := json.Marshal(upstreamError)
			result = p.config.DetectionEngine.EvaluateToolResponse(server, method, string(raw))
			policy := telemetry.SyncPolicy{}
			if p.telemetry != nil {
				policy = p.telemetry.Policy()
			}
			result = applyDetectionPolicy(result, policy, p.config.Detection)
		}
		outcome.PolicyDecision = string(result.Verdict)
		if result.Verdict == detection.VerdictBlock && enforce {
			outcome.RequiredDisposition, outcome.AppliedDisposition = "withhold_result", "result_withheld"
			outcome.ResultReturned, outcome.ResponseWithheld = false, true
			code, message, data = -32003, "Blocked by AgentKeeper: upstream error content was withheld.", nil
		}
	}
	if errors.Is(err, context.Canceled) {
		code = -32800
		message = "Request cancelled"
		outcome.FailureReason = "client_cancelled"
		if dispatched {
			outcome.AppliedDisposition = "client_cancelled"
		}
	}
	p.logToolOutcome(server, method, nil, result, outcome)
	return &JSONRPCMessage{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: code, Message: message, Data: data}}
}
