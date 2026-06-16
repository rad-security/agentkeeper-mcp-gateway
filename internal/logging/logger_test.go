package logging

import (
	"os"
	"path/filepath"
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
