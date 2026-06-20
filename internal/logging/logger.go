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
	verdict := result.Verdict
	if verdict == "" {
		verdict = detection.VerdictPass
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
