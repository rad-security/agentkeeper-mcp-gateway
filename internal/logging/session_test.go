package logging

import (
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// An event keeps the session of the process that observed it, even when a
// later process uploads it from the durable queue.
func TestEventsCarryTheSessionThatObservedThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	first, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	first.SetSessionID("gw-boot-first")
	first.LogToolCallOutcome("notes", "search", nil, detection.Result{}, ToolCallOutcome{CallID: "call-1"})
	first.LogDefinitionFinding("notes", "search", detection.Result{Verdict: detection.VerdictWarn}, "observe", true)
	_ = first.Close()

	second, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetSessionID("gw-boot-second")
	second.LogToolCallOutcome("notes", "archive", nil, detection.Result{}, ToolCallOutcome{CallID: "call-2", ClientName: "claude-code"})

	events, durable, err := second.PendingEvents(10)
	if err != nil || !durable {
		t.Fatalf("pending events: durable=%v err=%v", durable, err)
	}
	if len(events) != 3 {
		t.Fatalf("events: %+v", events)
	}
	want := map[string]string{"call-1": "gw-boot-first", "call-2": "gw-boot-second"}
	findings := 0
	for _, event := range events {
		session := event.Context["session_id"]
		if callID, ok := event.Context["tool_call_id"].(string); ok {
			if session != want[callID] {
				t.Fatalf("%s carried session %v, want %s", callID, session, want[callID])
			}
			continue
		}
		findings++
		if session != "gw-boot-first" {
			t.Fatalf("definition finding carried session %v", session)
		}
	}
	if findings != 1 {
		t.Fatalf("definition findings: %d", findings)
	}
}

func TestEventsWithoutASessionAreUnchanged(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("notes", "search", nil, detection.Result{})
	events := logger.FlushBuffer()
	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}
	if _, present := events[0].Context["session_id"]; present {
		t.Fatalf("session_id without a session: %v", events[0].Context)
	}
}
