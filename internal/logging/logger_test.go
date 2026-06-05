package logging

import (
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
