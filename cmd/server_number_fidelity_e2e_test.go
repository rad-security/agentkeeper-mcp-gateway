package cmd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Numbers a float64 cannot hold exactly: identifiers past 2^53, the int64 and
// uint64 limits, a 30-digit integer, and a decimal, at the top level and
// nested in objects and arrays. Keys are sorted, as the Gateway forwards them.
const (
	fidelityArguments = `{"big":9007199254740993,"decimal":0.1,"huge":123456789012345678901234567890,"ids":[9007199254740993,-9223372036854775808,0.1],"max_uint64":18446744073709551615,"min_int64":-9223372036854775808,"nested":{"id":9007199254740993,"list":[1234567890123456789,{"deep":18446744073709551615}]},"snowflake":1234567890123456789}`
	// Spellings that survive only if the literal itself is preserved.
	fidelitySpellings = `{"below_float64":1e-400,"beyond_float64":1e400,"exponent":1E5,"negative_zero":-0,"trailing_zero":1.0}`
	fidelityResult    = `{"content":[{"type":"text","text":"row 9007199254740993"}],"structuredContent":{"big":9007199254740993,"beyond_float64":1e400,"decimal":0.1,"huge":123456789012345678901234567890,"ids":[1234567890123456789,{"deep":18446744073709551615}],"max_uint64":18446744073709551615,"min_int64":-9223372036854775808,"trailing_zero":1.0}}`
)

// upstreamToolCallArguments returns the arguments of every tools/call the
// fixture upstream received, exactly as they were written to its stdin.
func upstreamToolCallArguments(t *testing.T, requestLog string) []string {
	t.Helper()
	data, err := os.ReadFile(requestLog)
	if err != nil {
		t.Fatal(err)
	}
	var arguments []string
	for _, line := range strings.Split(string(data), "\n") {
		var request struct {
			Method string `json:"method"`
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal([]byte(line), &request) != nil || request.Method != "tools/call" {
			continue
		}
		arguments = append(arguments, string(request.Params.Arguments))
	}
	return arguments
}

// A tool call must reach the upstream, and its result the client, with every
// number as it was written. Rounding through float64 turned
// 9007199254740993 into 9007199254740992 and corrupted database identifiers.
func TestToolCallNumbersSurviveTheGatewayInBothDirections(t *testing.T) {
	api := newPolicyAPI(t, "audit", nil)
	home := t.TempDir()
	fixture := contentFixtureServer("numbers", home)
	fixture["env"].(map[string]string)["AK_TEST_TOOL_RESULT"] = fidelityResult
	gw := startGatewayProcess(t, home, map[string]interface{}{
		"mode": "audit", "api_key": "ak_live_number_fidelity_fixture", "api_url": api.URL,
		"log_path": filepath.Join(home, "events.jsonl"),
		"servers":  []map[string]interface{}{fixture},
	})
	gw.request(t, 1, "initialize", map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "number-fidelity-e2e", "version": "test"}})
	writeRPC(t, gw.stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	deadline := time.Now().Add(10 * time.Second)
	for id := 2; !strings.Contains(gw.request(t, id, "tools/list", map[string]interface{}{}), `"numbers__echo"`); id++ {
		if time.Now().After(deadline) {
			t.Fatalf("fixture tools were never listed; stderr=%s", gw.stderrText())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The requests are written as text so the test client cannot round them.
	calls := []string{fidelityArguments, fidelitySpellings}
	responses := make([]string, len(calls))
	for i, arguments := range calls {
		id := fmt.Sprint(500 + i)
		writeRPC(t, gw.stdin, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"numbers__echo","arguments":`+arguments+`}}`)
		responses[i] = readRPCResponseForIDWithin(t, gw.reader, id, 15*time.Second)
	}
	gw.closeStdinAndWait(t, 10*time.Second)

	received := upstreamToolCallArguments(t, filepath.Join(home, "numbers.requests"))
	for i, want := range calls {
		if i >= len(received) {
			t.Errorf("call %d never reached the upstream: %s", i, responses[i])
			continue
		}
		if received[i] != want {
			t.Errorf("upstream received arguments\n  %s\nwant\n  %s", received[i], want)
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal([]byte(responses[i]), &envelope); err != nil || string(envelope.Result) != fidelityResult {
			t.Errorf("client received\n  %s\nwant result\n  %s (err=%v)", responses[i], fidelityResult, err)
		}
	}

	// Inspection still ran on both calls: each reached the evaluation API with
	// an argument object carrying every key.
	evaluations := api.evaluationSnapshot()
	if len(evaluations) != len(calls) {
		t.Fatalf("expected %d connected evaluations, got %d", len(calls), len(evaluations))
	}
	for i, want := range calls {
		var sent, evaluated map[string]json.RawMessage
		if err := json.Unmarshal([]byte(want), &sent); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(evaluations[i]["params"], &evaluated); err != nil || len(evaluated) != len(sent) {
			t.Errorf("connected evaluation received params=%s (err=%v), want the %d argument keys", evaluations[i]["params"], err, len(sent))
		}
	}
	if events := queuedToolEvents(t, home, "echo"); len(events) != 2 {
		t.Errorf("expected two terminal tool-call events, got %d", len(events))
	}
}
