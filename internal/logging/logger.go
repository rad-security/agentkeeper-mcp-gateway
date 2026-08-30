package logging

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// Event represents a logged MCP event.
type Event struct {
	EventID     string                 `json:"event_id,omitempty"`
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
	buffer         []Event
	bufferMu       sync.Mutex
	bufferDropped  int
	queueDir       string
	rejectedDir    string
	durableQueue   bool
	queueMu        sync.Mutex
	queueEvents    int
	queueBytes     int64
	queueMaxEvents int
	queueMaxBytes  int64
	queueLastError string
}

// EventQueueStatus is safe to expose through local health output. It contains
// counts and limits only, never event content.
type EventQueueStatus struct {
	State             string `json:"state"`
	Durable           bool   `json:"durable"`
	Accepting         bool   `json:"accepting"`
	PendingEvents     int    `json:"pending_events"`
	PendingBytes      int64  `json:"pending_bytes"`
	RejectedEvents    int    `json:"rejected_events"`
	MemoryOnlyDropped int    `json:"memory_only_dropped"`
	MaxEvents         int    `json:"max_events"`
	MaxBytes          int64  `json:"max_bytes"`
	LastError         string `json:"last_error,omitempty"`
}

// NewLogger creates a logger writing to the specified path.
// If path is empty, uses ~/.config/agentkeeper-mcp-gateway/events.jsonl
func NewLogger(logPath string, verbose bool) (*Logger, error) {
	if logPath == "" {
		home, _ := os.UserHomeDir()
		logPath = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: creating log directory: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}
	if info, err := os.Lstat(logPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: refusing non-regular log path %s\n", logPath)
			return newBufferedLogger(nil, logPath, verbose), nil
		}
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: inspecting log file: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: opening log file: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		fmt.Fprintf(os.Stderr, "[agentkeeper] local event log disabled: securing log file: %v\n", err)
		return newBufferedLogger(nil, logPath, verbose), nil
	}

	return newBufferedLogger(file, logPath, verbose), nil
}

func newBufferedLogger(file *os.File, logPath string, verbose bool) *Logger {
	logger := &Logger{
		file:           file,
		logPath:        logPath,
		verbose:        verbose,
		buffer:         make([]Event, 0, 100),
		queueMaxEvents: 100000,
		queueMaxBytes:  256 * 1024 * 1024,
	}
	logger.initDurableQueue()
	return logger
}

// ConfigureQueueLimits applies fleet-managed spool limits. Non-positive values
// keep the safe defaults so a malformed config cannot make the queue unbounded.
func (l *Logger) ConfigureQueueLimits(maxEvents int, maxBytes int64) {
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	if maxEvents > 0 {
		l.queueMaxEvents = maxEvents
	}
	if maxBytes > 0 {
		l.queueMaxBytes = maxBytes
	}
	_ = l.refreshQueueUsageLocked()
}

// QueueStatus reports whether another event can be durably accepted.
func (l *Logger) QueueStatus() EventQueueStatus {
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	if l.durableQueue {
		if err := l.refreshQueueUsageLocked(); err != nil {
			l.queueLastError = err.Error()
		}
	}
	return l.queueStatusLocked()
}

// InspectEventQueue reports on an existing spool without creating files. It is
// used by fleet health and MDM detection commands when no Gateway process is
// running.
func InspectEventQueue(logPath string, maxEvents int, maxBytes int64) EventQueueStatus {
	if logPath == "" {
		home, _ := os.UserHomeDir()
		logPath = filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
	}
	if maxEvents <= 0 {
		maxEvents = 100000
	}
	if maxBytes <= 0 {
		maxBytes = 256 * 1024 * 1024
	}
	root := filepath.Join(filepath.Dir(logPath), "events-v1")
	logger := &Logger{
		queueDir: filepath.Join(root, "queue"), rejectedDir: filepath.Join(root, "rejected"),
		queueMaxEvents: maxEvents, queueMaxBytes: maxBytes,
	}
	if info, err := os.Stat(logger.queueDir); os.IsNotExist(err) {
		return EventQueueStatus{State: "not_initialized", MaxEvents: maxEvents, MaxBytes: maxBytes}
	} else if err != nil || !info.IsDir() {
		message := "event queue path is unavailable"
		if err != nil {
			message = err.Error()
		}
		return EventQueueStatus{State: "unavailable", MaxEvents: maxEvents, MaxBytes: maxBytes, LastError: message}
	}
	logger.durableQueue = true
	if err := logger.refreshQueueUsageLocked(); err != nil {
		logger.queueLastError = err.Error()
	}
	return logger.queueStatusLocked()
}

// AcceptingDurableEvents is the hot-path capacity check. It uses counters kept
// current by queue writes and acknowledgements and avoids rescanning a large
// outage backlog for every MCP call.
func (l *Logger) AcceptingDurableEvents() bool {
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	return l.durableQueue && l.queueEvents < l.queueMaxEvents && l.queueBytes < l.queueMaxBytes && l.queueLastError == ""
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

// PendingEvents returns a stable upload batch. When the owner-only disk queue
// is available, returned events remain pending until ResolveEvents receives an
// explicit terminal acknowledgment, so process restarts cannot lose them.
func (l *Logger) PendingEvents(limit int) ([]Event, bool, error) {
	if !l.durableQueue {
		return l.FlushBuffer(), false, nil
	}
	entries, err := os.ReadDir(l.queueDir)
	if err != nil {
		return nil, true, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if limit <= 0 {
		limit = 100
	}
	events := make([]Event, 0, limit)
	seen := make(map[string]bool, limit)
	for _, entry := range entries {
		if len(events) >= limit {
			break
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(l.queueDir, entry.Name())
		data, readErr := os.ReadFile(path)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, true, readErr
		}
		var event Event
		if decodeErr := json.Unmarshal(data, &event); decodeErr != nil || event.EventID == "" {
			if renameErr := l.quarantineQueuedEvent(path, filepath.Join(l.rejectedDir, entry.Name())); renameErr != nil && !os.IsNotExist(renameErr) {
				return nil, true, fmt.Errorf("quarantining corrupt event %s: %w", entry.Name(), renameErr)
			}
			continue
		}
		events = append(events, event)
		seen[event.EventID] = true
	}

	// Include any event that could not be persisted but is still alive in this
	// process. Persisted entries win so a batch never contains duplicates.
	l.bufferMu.Lock()
	for _, event := range l.buffer {
		if len(events) >= limit {
			break
		}
		if event.EventID != "" && !seen[event.EventID] {
			events = append(events, event)
			seen[event.EventID] = true
		}
	}
	l.bufferMu.Unlock()
	return events, true, nil
}

// ResolveEvents applies per-item acknowledgments. Accepted and duplicate
// events are deleted; terminal rejects are quarantined; missing and retryable
// statuses remain pending.
func (l *Logger) ResolveEvents(statusByEventID map[string]string) error {
	terminal := make(map[string]bool)
	for eventID, status := range statusByEventID {
		if status == "accepted" || status == "duplicate" || status == "rejected" || status == "conflicted" {
			terminal[eventID] = true
		}
	}
	if l.durableQueue {
		l.queueMu.Lock()
		defer l.queueMu.Unlock()
		entries, err := os.ReadDir(l.queueDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			source := filepath.Join(l.queueDir, entry.Name())
			data, err := os.ReadFile(source)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			var event Event
			if err := json.Unmarshal(data, &event); err != nil || event.EventID == "" {
				continue
			}
			status := statusByEventID[event.EventID]
			switch status {
			case "accepted", "duplicate":
				info, _ := os.Stat(source)
				if err := os.Remove(source); err != nil && !os.IsNotExist(err) {
					return err
				}
				l.decrementQueueUsageLocked(info)
			case "rejected", "conflicted":
				info, _ := os.Stat(source)
				if err := os.Rename(source, filepath.Join(l.rejectedDir, entry.Name())); err != nil && !os.IsNotExist(err) {
					return err
				}
				l.decrementQueueUsageLocked(info)
			}
		}
		l.clearCapacityErrorLocked()
	}
	if len(terminal) > 0 {
		l.bufferMu.Lock()
		remaining := l.buffer[:0]
		for _, event := range l.buffer {
			if !terminal[event.EventID] {
				remaining = append(remaining, event)
			}
		}
		l.buffer = remaining
		l.bufferMu.Unlock()
	}
	return nil
}

// Close closes the log file.
func (l *Logger) Close() error {
	if l.file == nil {
		return nil
	}
	_ = l.file.Sync()
	return l.file.Close()
}

func (l *Logger) writeEvent(event Event) {
	persisted := false
	if remoteIngestable(event) && event.EventID == "" {
		event.EventID = newEventID()
		if l.durableQueue {
			if err := l.persistEvent(event); err != nil {
				fmt.Fprintf(os.Stderr, "[agentkeeper] durable event queue unavailable for %s: %v\n", event.EventID, err)
			} else {
				persisted = true
			}
		}
	}
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
		if len(l.buffer) < 1000 {
			l.buffer = append(l.buffer, event)
		} else if !persisted {
			l.bufferDropped++
		}
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

func (l *Logger) initDurableQueue() {
	root := filepath.Join(filepath.Dir(l.logPath), "events-v1")
	l.queueDir = filepath.Join(root, "queue")
	l.rejectedDir = filepath.Join(root, "rejected")
	for _, dir := range []string{root, l.queueDir, l.rejectedDir} {
		if err := ensurePrivateDir(dir); err != nil {
			l.durableQueue = false
			return
		}
	}
	l.durableQueue = true
	l.queueMu.Lock()
	if err := l.refreshQueueUsageLocked(); err != nil {
		l.queueLastError = err.Error()
	}
	l.queueMu.Unlock()
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("refusing non-directory queue path %s", path)
		}
		return os.Chmod(path, 0o700)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing non-directory queue path %s", path)
	}
	return os.Chmod(path, 0o700)
}

func (l *Logger) persistEvent(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	if !l.durableQueue {
		return fmt.Errorf("durable event queue is unavailable")
	}
	if l.queueEvents >= l.queueMaxEvents || l.queueBytes+int64(len(data)+1) > l.queueMaxBytes {
		l.queueLastError = fmt.Sprintf("event queue capacity exceeded: events=%d/%d bytes=%d/%d", l.queueEvents, l.queueMaxEvents, l.queueBytes, l.queueMaxBytes)
		return fmt.Errorf("%s", l.queueLastError)
	}
	name := fmt.Sprintf("%020d-%s.json", time.Now().UTC().UnixNano(), event.EventID)
	payload := append(data, '\n')
	if err := atomicWriteEvent(filepath.Join(l.queueDir, name), payload); err != nil {
		l.queueLastError = err.Error()
		return err
	}
	l.queueEvents++
	l.queueBytes += int64(len(payload))
	l.clearCapacityErrorLocked()
	return nil
}

func (l *Logger) refreshQueueUsageLocked() error {
	entries, err := os.ReadDir(l.queueDir)
	if err != nil {
		return err
	}
	events := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		events++
		bytes += info.Size()
	}
	l.queueEvents = events
	l.queueBytes = bytes
	return nil
}

func (l *Logger) queueStatusLocked() EventQueueStatus {
	status := EventQueueStatus{
		State: "healthy", Durable: l.durableQueue, PendingEvents: l.queueEvents,
		PendingBytes: l.queueBytes, MaxEvents: l.queueMaxEvents, MaxBytes: l.queueMaxBytes,
		LastError: l.queueLastError,
	}
	if entries, err := os.ReadDir(l.rejectedDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				status.RejectedEvents++
			}
		}
	}
	status.Accepting = status.Durable && status.PendingEvents < status.MaxEvents && status.PendingBytes < status.MaxBytes && status.LastError == ""
	l.bufferMu.Lock()
	status.MemoryOnlyDropped = l.bufferDropped
	l.bufferMu.Unlock()
	if !status.Durable {
		status.State = "unavailable"
	} else if status.PendingEvents >= status.MaxEvents || status.PendingBytes >= status.MaxBytes {
		status.State = "full"
	} else if status.PendingEvents*100 >= status.MaxEvents*80 || status.PendingBytes*100 >= status.MaxBytes*80 {
		status.State = "pressure"
	} else if status.LastError != "" {
		status.State = "degraded"
	}
	return status
}

func (l *Logger) quarantineQueuedEvent(source, target string) error {
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	info, _ := os.Stat(source)
	if err := os.Rename(source, target); err != nil {
		return err
	}
	l.decrementQueueUsageLocked(info)
	return nil
}

func (l *Logger) decrementQueueUsageLocked(info os.FileInfo) {
	if info == nil {
		return
	}
	if l.queueEvents > 0 {
		l.queueEvents--
	}
	l.queueBytes -= info.Size()
	if l.queueBytes < 0 {
		l.queueBytes = 0
	}
}

func (l *Logger) clearCapacityErrorLocked() {
	if strings.HasPrefix(l.queueLastError, "event queue capacity exceeded:") && l.queueEvents < l.queueMaxEvents && l.queueBytes < l.queueMaxBytes {
		l.queueLastError = ""
	}
}

func atomicWriteEvent(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".event-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func newEventID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("event-%d", time.Now().UTC().UnixNano())
	}
	return "event-" + hex.EncodeToString(raw[:])
}
