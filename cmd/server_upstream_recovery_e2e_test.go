package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func localCrashableGatewayConfig(home string, fixtureEnv map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"mode":     "audit",
		"log_path": filepath.Join(home, "events.jsonl"),
		"servers":  []map[string]interface{}{crashableFixtureServer(fixtureEnv)},
	}
}

func queuedReceiptsForTool(t *testing.T, home, tool string) []receipt.Envelope {
	t.Helper()
	var out []receipt.Envelope
	for _, file := range queuedFiles(t, filepath.Join(home, "receipts-v2", "queue")) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var item receipt.Envelope
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		if item.ToolName == tool {
			out = append(out, item)
		}
	}
	return out
}

func queuedToolEvents(t *testing.T, home, tool string) []logging.Event {
	t.Helper()
	var out []logging.Event
	for _, file := range queuedFiles(t, filepath.Join(home, "events-v1", "queue")) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var event logging.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if event.EventType == "mcp.tool_call" && event.ToolName == tool {
			out = append(out, event)
		}
	}
	return out
}

func callTool(t *testing.T, gw *gatewayProcess, id int, name string) string {
	t.Helper()
	return gw.request(t, id, "tools/call", map[string]interface{}{"name": name, "arguments": map[string]interface{}{}})
}

// G3: after a stdio upstream exits, the next call to one of its listed tools
// must not fail as "unknown tool". Codex issues the next call immediately
// after the failed one, inside the manager's restart backoff window.
func TestCrashedStdioUpstreamServesNextCallImmediately(t *testing.T) {
	home := t.TempDir()
	startLog := filepath.Join(home, "fixture-starts.log")
	gw := startGatewayProcess(t, home, localCrashableGatewayConfig(home, map[string]string{"AK_TEST_START_LOG": startLog}))
	gw.handshake(t)

	crashed := callTool(t, gw, 100, "native_matrix__disconnect")
	if !strings.Contains(crashed, "calling native_matrix/disconnect: EOF") {
		t.Fatalf("crash was not reported as a dispatch failure: %s", crashed)
	}
	next := callTool(t, gw, 101, "native_matrix__echo")
	if strings.Contains(next, "unknown tool") || !strings.Contains(next, "FIXTURE_ECHO_OK") {
		t.Fatalf("listed tool was not served after its upstream exited: %s", next)
	}
	gw.closeStdinAndWait(t, 10*time.Second)

	starts, _ := os.ReadFile(startLog)
	if got := strings.Count(string(starts), "\n"); got < 2 {
		t.Fatalf("upstream starts=%d, want a restart", got)
	}
	if got := queuedReceiptsForTool(t, home, "disconnect"); len(got) != 1 || got[0].AppliedDisposition != "dispatch_failed" || !got[0].Dispatched {
		t.Fatalf("crash receipt=%+v", got)
	}
	if got := queuedReceiptsForTool(t, home, "echo"); len(got) != 1 || got[0].AppliedDisposition != "result_returned" {
		t.Fatalf("recovered call receipt=%+v", got)
	}
}

// When the upstream cannot be brought back, the call fails truthfully and
// still leaves a terminal receipt and event.
func TestUnrecoverableStdioUpstreamReturnsTruthfulErrorWithEvidence(t *testing.T) {
	home := t.TempDir()
	startLog := filepath.Join(home, "fixture-starts.log")
	gw := startGatewayProcess(t, home, localCrashableGatewayConfig(home, map[string]string{
		"AK_TEST_START_LOG":              startLog,
		"AK_TEST_FAIL_AFTER_FIRST_START": "1",
	}))
	gw.handshake(t)

	crashed := callTool(t, gw, 100, "native_matrix__disconnect")
	if !strings.Contains(crashed, "calling native_matrix/disconnect: EOF") {
		t.Fatalf("crash was not reported as a dispatch failure: %s", crashed)
	}
	next := callTool(t, gw, 101, "native_matrix__echo")
	if strings.Contains(next, "unknown tool") || !strings.Contains(next, `upstream MCP server \"native_matrix\" is not running`) {
		t.Fatalf("unavailable upstream was not reported truthfully: %s", next)
	}
	if testing.Verbose() {
		t.Logf("truthful error: %s", next)
	}
	gw.closeStdinAndWait(t, 10*time.Second)

	receipts := queuedReceiptsForTool(t, home, "echo")
	if len(receipts) != 1 {
		t.Fatalf("failed attempt receipts=%+v, want exactly one", receipts)
	}
	if r := receipts[0]; r.AppliedDisposition != "dispatch_failed" || r.RequiredDisposition != "forward" || r.Dispatched || r.ResultReceived || r.ResultReturned || r.FailureReason == "" || !r.Terminal {
		t.Fatalf("failed attempt receipt is not a truthful terminal dispatch failure: %+v", r)
	}
	events := queuedToolEvents(t, home, "echo")
	if len(events) != 1 || events[0].Context["applied_disposition"] != "dispatch_failed" {
		t.Fatalf("failed attempt events=%+v", events)
	}
}

// A name that belongs to no configured upstream is still an unknown tool.
func TestUnknownToolForUnconfiguredServerStaysUnknown(t *testing.T) {
	home := t.TempDir()
	gw := startGatewayProcess(t, home, localCrashableGatewayConfig(home, nil))
	gw.handshake(t)
	response := callTool(t, gw, 100, "not_configured__echo")
	if !strings.Contains(response, "unknown tool: not_configured__echo") {
		t.Fatalf("unconfigured tool response: %s", response)
	}
}
