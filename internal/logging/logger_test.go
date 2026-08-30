package logging

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

func TestLogToolCallDefaultsEmptyVerdictToPass(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	logger.LogToolCall("mock", "echo", map[string]interface{}{"text": "hello"}, detection.Result{})

	events := logger.FlushBuffer()
	if len(events) != 1 {
		t.Fatalf("expected one buffered event, got %d", len(events))
	}
	if events[0].Verdict != "pass" {
		t.Fatalf("verdict = %q, want pass", events[0].Verdict)
	}
}

func TestLogToolCallOutcomeSeparatesDecisionFromAppliedDisposition(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolCallOutcome("atlas", "delete", nil, detection.Result{
		Verdict: detection.VerdictBlock,
	}, ToolCallOutcome{
		CallID:              "call-1",
		AttemptID:           "attempt-1",
		Mode:                "observe",
		PolicyDecision:      "block",
		EvaluationStatus:    "evaluated",
		RequiredDisposition: "forward",
		AppliedDisposition:  "result_returned",
		Dispatched:          true,
		ResultReceived:      true,
		ResultReturned:      true,
	})

	events := logger.FlushBuffer()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if got := events[0].Context["policy_decision"]; got != "block" {
		t.Fatalf("policy_decision = %#v", got)
	}
	if got := events[0].Context["applied_disposition"]; got != "result_returned" {
		t.Fatalf("applied_disposition = %#v", got)
	}
	if got := events[0].Context["dispatched"]; got != true {
		t.Fatalf("dispatched = %#v", got)
	}
}

func TestLogSessionStartStaysLocalButDoesNotUpload(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	logger.LogSessionStart("dev-workstation-01", "darwin", "0.1.13", []string{"qa-stdio"})

	if events := logger.FlushBuffer(); len(events) != 0 {
		t.Fatalf("expected lifecycle event to stay out of telemetry buffer, got %+v", events)
	}

	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"event_type":"mcp.session_start"`) {
		t.Fatalf("expected local session_start evidence, got %s", string(contents))
	}
}

func TestNewLoggerFailsOpenWhenLocalPathIsUnwritable(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("nope"), 0600); err != nil {
		t.Fatal(err)
	}

	logger, err := NewLogger(filepath.Join(notDir, "events.jsonl"), false)
	if err != nil {
		t.Fatalf("NewLogger should fail open, got error: %v", err)
	}
	defer logger.Close()

	logger.LogToolCall("mock", "echo", map[string]interface{}{"text": "hello"}, detection.Result{})

	events := logger.FlushBuffer()
	if len(events) != 1 {
		t.Fatalf("expected buffered event despite disabled local file, got %d", len(events))
	}
	if events[0].ServerName != "mock" || events[0].ToolName != "echo" {
		t.Fatalf("unexpected buffered event: %+v", events[0])
	}
}

func TestNewLoggerCreatesAndRepairsOwnerOnlyEventLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(logPath, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logger, err := NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("event log mode = %04o, want 0600", got)
	}
}

func TestNewLoggerRefusesSymlinkLogPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "events.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	logger, err := NewLogger(link, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("mock", "echo", nil, detection.Result{})
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "sentinel\n" {
		t.Fatalf("symlink target was modified: %q", contents)
	}
	if len(logger.FlushBuffer()) != 1 {
		t.Fatal("remote telemetry buffer should remain available when local symlink is refused")
	}
}

func TestDurableEventQueueSurvivesRestartAndAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	first, err := NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	first.LogToolCall("payments", "transfer", nil, detection.Result{})
	pending, durable, err := first.PendingEvents(100)
	if err != nil || !durable || len(pending) != 1 || pending[0].EventID == "" {
		t.Fatalf("initial durable batch=%+v durable=%v err=%v", pending, durable, err)
	}
	eventID := pending[0].EventID
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	pending, durable, err = restarted.PendingEvents(100)
	if err != nil || !durable || len(pending) != 1 || pending[0].EventID != eventID {
		t.Fatalf("restarted durable batch=%+v durable=%v err=%v", pending, durable, err)
	}
	if err := restarted.ResolveEvents(map[string]string{eventID: "accepted"}); err != nil {
		t.Fatal(err)
	}
	pending, _, err = restarted.PendingEvents(100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged event remained pending: %+v err=%v", pending, err)
	}

	for _, path := range []string{
		filepath.Join(dir, "events-v1"),
		filepath.Join(dir, "events-v1", "queue"),
		filepath.Join(dir, "events-v1", "rejected"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("queue directory %s mode=%o, want 0700", path, info.Mode().Perm())
		}
	}
}

func TestConcurrentLoggersShareDurableQueue(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	const count = 12
	loggers := make([]*Logger, count)
	errs := make([]error, count)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			loggers[index], errs[index] = NewLogger(logPath, false)
		}(index)
	}
	close(start)
	wait.Wait()
	for index, logger := range loggers {
		if errs[index] != nil {
			t.Fatalf("logger %d failed: %v", index, errs[index])
		}
		if !logger.durableQueue {
			t.Fatalf("logger %d lost durable queue during concurrent startup", index)
		}
		_ = logger.Close()
	}
}

func TestDurableEventQueueRetainsRetryablePartialAcknowledgment(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("payments", "first", nil, detection.Result{})
	logger.LogToolCall("payments", "second", nil, detection.Result{})
	pending, durable, err := logger.PendingEvents(100)
	if err != nil || !durable || len(pending) != 2 {
		t.Fatalf("pending=%+v durable=%v err=%v", pending, durable, err)
	}
	if err := logger.ResolveEvents(map[string]string{
		pending[0].EventID: "accepted",
		pending[1].EventID: "retryable",
	}); err != nil {
		t.Fatal(err)
	}
	remaining, _, err := logger.PendingEvents(100)
	if err != nil || len(remaining) != 1 || remaining[0].EventID != pending[1].EventID {
		t.Fatalf("partial ack remaining=%+v err=%v", remaining, err)
	}
	if err := logger.ResolveEvents(map[string]string{remaining[0].EventID: "duplicate"}); err != nil {
		t.Fatal(err)
	}
	remaining, _, err = logger.PendingEvents(100)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("duplicate-acknowledged event remained: %+v err=%v", remaining, err)
	}
}

func TestDurableEventQueueEnforcesCapacityAndRecoversAfterAck(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.ConfigureQueueLimits(2, 1024*1024)
	logger.LogToolCall("payments", "first", nil, detection.Result{})
	logger.LogToolCall("payments", "second", nil, detection.Result{})

	status := logger.QueueStatus()
	if status.State != "full" || status.Accepting || status.PendingEvents != 2 {
		t.Fatalf("queue status at capacity = %+v", status)
	}
	if !strings.Contains(status.LastError, "capacity exceeded") && status.LastError != "" {
		t.Fatalf("unexpected capacity error: %q", status.LastError)
	}

	pending, durable, err := logger.PendingEvents(100)
	if err != nil || !durable || len(pending) != 2 {
		t.Fatalf("pending at capacity=%+v durable=%v err=%v", pending, durable, err)
	}
	if err := logger.ResolveEvents(map[string]string{pending[0].EventID: "accepted"}); err != nil {
		t.Fatal(err)
	}
	status = logger.QueueStatus()
	if status.State != "healthy" || !status.Accepting || status.PendingEvents != 1 {
		t.Fatalf("queue did not recover after ack: %+v", status)
	}
	logger.LogToolCall("payments", "replacement", nil, detection.Result{})
	status = logger.QueueStatus()
	if status.PendingEvents != 2 || status.Accepting {
		t.Fatalf("replacement did not refill bounded queue: %+v", status)
	}
}

func TestDurableEventQueueRejectsEventThatExceedsByteLimit(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.ConfigureQueueLimits(100, 64)
	logger.LogToolCall("payments", "oversized", map[string]interface{}{"value": strings.Repeat("x", 256)}, detection.Result{})
	status := logger.QueueStatus()
	if status.PendingEvents != 0 || status.Accepting || status.State != "degraded" {
		t.Fatalf("oversized event queue status = %+v", status)
	}
	if !strings.Contains(status.LastError, "capacity exceeded") {
		t.Fatalf("missing byte-capacity diagnostic: %+v", status)
	}
}
