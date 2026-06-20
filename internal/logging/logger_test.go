package logging

import (
	"os"
	"path/filepath"
	"strings"
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
