package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadExportEventsFiltersSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	data := strings.Join([]string{
		`{"timestamp":"2026-06-19T23:59:59Z","event_type":"mcp.tool_call","server_name":"old","tool_name":"echo","verdict":"pass"}`,
		`{"timestamp":"2026-06-20T00:00:00Z","event_type":"mcp.tool_call","server_name":"qa-stdio","tool_name":"echo","verdict":"pass"}`,
		`{"timestamp":"2026-06-20T00:00:01Z","event_type":"mcp.threat_detected","server_name":"qa-stdio","tool_name":"get_secret","verdict":"block","pattern_name":"api_key_aws"}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	events, err := readExportEvents(path, "2026-06-20")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].ServerName != "qa-stdio" || events[1].Verdict != "block" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestWriteExportCSVIncludesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(`{"timestamp":"2026-06-20T00:00:00Z","event_type":"mcp.tool_call","server_name":"qa-stdio","tool_name":"echo","verdict":"pass"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := readExportEvents(path, "")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := writeExportCSV(&out, events); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "timestamp,event_type,server_name") {
		t.Fatalf("missing header: %s", text)
	}
	if !strings.Contains(text, "qa-stdio,echo,pass") {
		t.Fatalf("missing event row: %s", text)
	}
}
