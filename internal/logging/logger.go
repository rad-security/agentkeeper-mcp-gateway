package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// Event represents a logged MCP event.
type Event struct {
	Timestamp   string                 `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	ServerName  string                 `json:"server_name,omitempty"`
	ToolName    string                 `json:"tool_name,omitempty"`
	Verdict     string                 `json:"verdict"`
	Severity    string                 `json:"severity,omitempty"`
	PatternName string                 `json:"pattern_name,omitempty"`
	Category    string                 `json:"category,omitempty"`
	Description string                 `json:"description,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ToolCallOutcome records the policy decision separately from what the
// gateway actually did. A block decision in Observe mode is still forwarded;
// callers must never infer enforcement from Verdict alone.
type ToolCallOutcome struct {
	CallID              string
	AttemptID           string
	DecisionID          string
	ClientName          string
	ConfigSourceHash    string
	RouteRevision       string
	Mode                string
	PolicyDecision      string
	EvaluationStatus    string
	RequiredDisposition string
	AppliedDisposition  string
	Dispatched          bool
	ResultReceived      bool
	ResultReturned      bool
	ResponseWithheld    bool
	FailureReason       string
}

// Logger writes structured events to a JSONL file.
type Logger struct {
	file    *os.File
	mu      sync.Mutex
	logPath string
	verbose bool
	// Buffer for batch telemetry upload
	buffer   []Event
	bufferMu sync.Mutex
}

// NewLogger creates a logger writing to the specified path.
// If path is empty, uses ~/.config/agentkeeper-mcp-gateway/events.jsonl
func NewLogger(logPath string, verbose bool) (*Logger, error) {
	if logPath == "" {
		home, _ := os.UserHomeDir()
		logPath = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: creating log directory: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: opening log file: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}

	return newBufferedLogger(file, logPath, verbose), nil
}

func newBufferedLogger(file *os.File, logPath string, verbose bool) *Logger {
	return &Logger{
		file:    file,
		logPath: logPath,
		verbose: verbose,
		buffer:  make([]Event, 0, 100),
	}
}

// LogToolCall logs an MCP tool call event.
func (l *Logger) LogToolCall(serverName, toolName string, params map[string]interface{}, result detection.Result) {
	l.LogToolCallOutcome(serverName, toolName, params, result, ToolCallOutcome{})
}

// LogToolCallOutcome logs one terminal, correlation-safe MCP call event.
func (l *Logger) LogToolCallOutcome(serverName, toolName string, params map[string]interface{}, result detection.Result, outcome ToolCallOutcome) {
	verdict := result.Verdict
	if verdict == "" {
		verdict = detection.VerdictPass
	}
	context := map[string]interface{}{}
	if outcome.CallID != "" {
		context["tool_call_id"] = outcome.CallID
	}
	if outcome.AttemptID != "" {
		context["attempt_id"] = outcome.AttemptID
	}
	if outcome.DecisionID != "" {
		context["decision_id"] = outcome.DecisionID
	}
	if outcome.ClientName != "" {
		context["client_name"] = outcome.ClientName
	}
	if outcome.ConfigSourceHash != "" {
		context["config_source_hash"] = outcome.ConfigSourceHash
	}
	if outcome.RouteRevision != "" {
		context["route_revision"] = outcome.RouteRevision
	}
	if outcome.Mode != "" {
		context["effective_mode"] = outcome.Mode
	}
	if outcome.PolicyDecision != "" {
		context["policy_decision"] = outcome.PolicyDecision
	}
	if outcome.EvaluationStatus != "" {
		context["evaluation_status"] = outcome.EvaluationStatus
	}
	if outcome.RequiredDisposition != "" {
		context["required_disposition"] = outcome.RequiredDisposition
	}
	if outcome.AppliedDisposition != "" {
		context["applied_disposition"] = outcome.AppliedDisposition
	}
	context["dispatched"] = outcome.Dispatched
	context["result_received"] = outcome.ResultReceived
	context["result_returned"] = outcome.ResultReturned
	context["response_withheld"] = outcome.ResponseWithheld
	if outcome.FailureReason != "" {
		context["failure_reason"] = outcome.FailureReason
	}
	event := Event{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		EventType:   "mcp.tool_call",
		ServerName:  serverName,
		ToolName:    toolName,
		Verdict:     string(verdict),
		Severity:    result.Severity,
		PatternName: result.PatternName,
		Category:    result.Category,
		Description: result.Description,
		Context:     context,
	}

	l.writeEvent(event)
}

// LogDetection logs a detection event (tool poisoning, sensitive data, etc.)
func (l *Logger) LogDetection(serverName, toolName string, result detection.Result) {
	event := Event{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		EventType:   "mcp.threat_detected",
		ServerName:  serverName,
		ToolName:    toolName,
		Verdict:     string(result.Verdict),
		Severity:    result.Severity,
		PatternName: result.PatternName,
		Category:    result.Category,
		Description: result.Description,
	}

	l.writeEvent(event)
}

// LogSessionStart logs gateway startup.
func (l *Logger) LogSessionStart(hostname, osName, gatewayVersion string, servers []string) {
	event := Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		EventType: "mcp.session_start",
		Verdict:   "pass",
		Context: map[string]interface{}{
			"hostname":        hostname,
			"os":              osName,
			"gateway_version": gatewayVersion,
			"servers":         servers,
		},
	}

	l.writeEvent(event)
}

// Warn logs a warning message to stderr.
func (l *Logger) Warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[agentkeeper] "+format+"\n", args...)
}

// Info logs an info message to stderr (only in verbose mode).
func (l *Logger) Info(format string, args ...interface{}) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[agentkeeper] "+format+"\n", args...)
	}
}

// FlushBuffer returns and clears the event buffer for telemetry upload.
func (l *Logger) FlushBuffer() []Event {
	l.bufferMu.Lock()
	defer l.bufferMu.Unlock()
	events := l.buffer
	l.buffer = make([]Event, 0, 100)
	return events
}

// RequeueFront puts events back at the front of the telemetry buffer after a
// failed upload so the gateway does not silently drop local evidence.
func (l *Logger) RequeueFront(events []Event) {
	if len(events) == 0 {
		return
	}
	l.bufferMu.Lock()
	defer l.bufferMu.Unlock()
	next := make([]Event, 0, len(events)+len(l.buffer))
	next = append(next, events...)
	next = append(next, l.buffer...)
	l.buffer = next
}

// Close closes the log file.
func (l *Logger) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) writeEvent(event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	if l.file != nil {
		l.mu.Lock()
		l.file.Write(data)
		l.file.Write([]byte("\n"))
		l.mu.Unlock()
	}

	if remoteIngestable(event) {
		l.bufferMu.Lock()
		l.buffer = append(l.buffer, event)
		l.bufferMu.Unlock()
	}

	// Print to stderr if verbose
	if l.verbose {
		verdict := event.Verdict
		if verdict == "warn" || verdict == "block" {
			fmt.Fprintf(os.Stderr, "[agentkeeper] %s %s/%s → %s: %s (%s)\n",
				event.EventType, event.ServerName, event.ToolName, verdict, event.PatternName, event.Description)
		}
	}
}

func remoteIngestable(event Event) bool {
	return event.ServerName != "" && event.ToolName != ""
}
