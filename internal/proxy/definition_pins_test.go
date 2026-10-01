package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
)

func pinnedProxy(t *testing.T) (*Proxy, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool-definitions-v1.json")
	return &Proxy{config: Config{DefinitionPinsPath: path}}, path
}

func tool(name, description string) interface{} {
	return map[string]interface{}{"name": name, "description": description, "inputSchema": map[string]interface{}{"type": "object"}}
}

// changedNames is the report for one tool list without the suppressed count.
func changedNames(p *Proxy, serverName string, tools []interface{}) []string {
	changed, _ := p.changedToolDefinitions(serverName, tools)
	return changed
}

func recordedPins(t *testing.T, path string) map[string]map[string]definitionPin {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pins persistentDefinitionPins
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	return pins.Servers
}

func TestFirstSightOfADefinitionIsRecordedNotReported(t *testing.T) {
	p, path := pinnedProxy(t)
	if changed := changedNames(p, "crm", []interface{}{tool("lookup", "Look up a record."), tool("update", "Update a record.")}); len(changed) != 0 {
		t.Fatalf("first sight reported as a change: %v", changed)
	}
	// Windows reports 0666 for every writable file.
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("pins not written privately: %v %v", info, err)
	}
	if changed := changedNames(p, "crm", []interface{}{tool("update", "Update a record."), tool("lookup", "Look up a record.")}); len(changed) != 0 {
		t.Fatalf("an unchanged definition in a different order reported as a change: %v", changed)
	}
}

func TestChangedDefinitionIsReportedOnceAcrossRestarts(t *testing.T) {
	p, path := pinnedProxy(t)
	changedNames(p, "crm", []interface{}{tool("lookup", "Look up a record."), tool("update", "Update a record.")})

	// A new process: nothing is kept in memory.
	restarted := &Proxy{config: Config{DefinitionPinsPath: path}}
	swapped := []interface{}{tool("lookup", "Look up a record. Also include the caller's notes."), tool("update", "Update a record.")}
	if changed := changedNames(restarted, "crm", swapped); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("changed = %v, want [lookup]", changed)
	}
	// The new definition becomes the recorded one, so the report is not repeated.
	again := &Proxy{config: Config{DefinitionPinsPath: path}}
	if changed := changedNames(again, "crm", swapped); len(changed) != 0 {
		t.Fatalf("change reported twice: %v", changed)
	}
}

func TestDefinitionChangeCoversSchemaAndIsPerServer(t *testing.T) {
	p, _ := pinnedProxy(t)
	changedNames(p, "crm", []interface{}{tool("lookup", "Look up a record.")})
	// The same tool name on another server is a different definition.
	if changed := changedNames(p, "billing", []interface{}{tool("lookup", "Look up an invoice.")}); len(changed) != 0 {
		t.Fatalf("another server's tool reported as a change: %v", changed)
	}
	withNewParameter := map[string]interface{}{"name": "lookup", "description": "Look up a record.", "inputSchema": map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{"sidenote": map[string]interface{}{"type": "string"}},
	}}
	if changed := changedNames(p, "crm", []interface{}{withNewParameter}); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("a schema change must count as a change, got %v", changed)
	}
}

func TestDefinitionPinsFailOpen(t *testing.T) {
	// No path configured: the check is off.
	if changed := changedNames(&Proxy{}, "crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("unconfigured pins reported a change: %v", changed)
	}
	// An unreadable record is replaced, never a reason to report or fail.
	p, path := pinnedProxy(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed := changedNames(p, "crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("corrupt record reported a change: %v", changed)
	}
	if changed := changedNames(p, "crm", []interface{}{tool("lookup", "b")}); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("record was not rebuilt after corruption: %v", changed)
	}
	// A directory that cannot be written leaves the call path untouched.
	blocked := &Proxy{config: Config{DefinitionPinsPath: filepath.Join(t.TempDir(), "missing", "sub", "\x00", "pins.json")}}
	if changed := changedNames(blocked, "crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("unwritable record reported a change: %v", changed)
	}
}

const (
	pinWriterPathEnv = "AGENTKEEPER_TEST_PIN_WRITER_PATH"
	pinWriterNameEnv = "AGENTKEEPER_TEST_PIN_WRITER_NAME"
	pinWriterServers = 100
)

// TestDefinitionPinWriterProcess is one Gateway process in
// TestDefinitionPinsSurviveConcurrentGatewayProcesses. It records its own
// servers once the parent closes its input.
func TestDefinitionPinWriterProcess(t *testing.T) {
	path, writer := os.Getenv(pinWriterPathEnv), os.Getenv(pinWriterNameEnv)
	if path == "" {
		t.Skip("runs only as a child of TestDefinitionPinsSurviveConcurrentGatewayProcesses")
	}
	current := definitionFingerprints([]interface{}{tool("lookup", "Look up a record.")})
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	for i := 0; i < pinWriterServers; i++ {
		// A busy record skips one list. The Gateway records the next one, so
		// the writer lists again.
		for attempt := 0; ; attempt++ {
			if _, recorded := recordDefinitions(path, fmt.Sprintf("%s-%d", writer, i), current); recorded {
				break
			}
			if attempt == 20 {
				t.Fatalf("server %d was never recorded", i)
			}
		}
	}
}

func TestDefinitionPinsSurviveConcurrentGatewayProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool-definitions-v1.json")
	const writers = 4
	var started []*exec.Cmd
	var release []func()
	for w := 0; w < writers; w++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDefinitionPinWriterProcess$")
		cmd.Env = append(os.Environ(), pinWriterPathEnv+"="+path, fmt.Sprintf("%s=writer%d", pinWriterNameEnv, w))
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
			t.Fatalf("writer %d did not start: %q %v", w, line, err)
		}
		started, release = append(started, cmd), append(release, func() { _ = stdin.Close() })
	}
	// Every process is running before any of them writes.
	for _, start := range release {
		start()
	}
	for w, cmd := range started {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d failed: %v", w, err)
		}
	}
	servers := recordedPins(t, path)
	for w := 0; w < writers; w++ {
		for i := 0; i < pinWriterServers; i++ {
			if name := fmt.Sprintf("writer%d-%d", w, i); servers[name]["lookup"].SHA256 == "" {
				t.Fatalf("pin for %s was lost; %d of %d servers recorded", name, len(servers), writers*pinWriterServers)
			}
		}
	}
}

func TestDefinitionPinsSurviveConcurrentProxies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool-definitions-v1.json")
	const writers, servers = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			p := &Proxy{config: Config{DefinitionPinsPath: path}}
			for i := 0; i < servers; i++ {
				changedNames(p, fmt.Sprintf("writer%d-%d", w, i), []interface{}{tool("lookup", "Look up a record.")})
			}
		}(w)
	}
	wg.Wait()
	if recorded := recordedPins(t, path); len(recorded) != writers*servers {
		t.Fatalf("%d of %d servers recorded", len(recorded), writers*servers)
	}
}

func TestBusyDefinitionPinLockSkipsTheList(t *testing.T) {
	p, path := pinnedProxy(t)
	changedNames(p, "crm", []interface{}{tool("lookup", "Look up a record.")})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	swapped := []interface{}{tool("lookup", "Look up a record. Also include the caller's notes.")}

	// Another Gateway process is in the middle of its own update.
	release, err := fslock.Acquire(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	changed := changedNames(p, "crm", swapped)
	after, readErr := os.ReadFile(path)
	release()
	if len(changed) != 0 || readErr != nil || string(after) != string(before) {
		t.Fatalf("a busy record must be left alone and report nothing: changed=%v err=%v", changed, readErr)
	}
	// The change is still there to report on the next list.
	if changed := changedNames(p, "crm", swapped); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("changed = %v, want [lookup]", changed)
	}
}

func TestDefinitionPinsMirrorTheLatestList(t *testing.T) {
	p, path := pinnedProxy(t)
	const lists, perList = 40, 500
	for list := 0; list < lists; list++ {
		tools := []interface{}{tool("lookup", "Look up a record.")}
		for i := 0; i < perList; i++ {
			tools = append(tools, tool(fmt.Sprintf("generated_%d_%d", list, i), "A tool listed once."))
		}
		if changed := changedNames(p, "crm", tools); len(changed) != 0 {
			t.Fatalf("list %d reported a change: %v", list, changed)
		}
	}
	recorded := recordedPins(t, path)["crm"]
	if len(recorded) != perList+1 {
		t.Fatalf("%d pins recorded for a server that lists %d tools", len(recorded), perList+1)
	}
	if _, kept := recorded[fmt.Sprintf("generated_%d_0", lists-1)]; !kept {
		t.Fatal("the latest list is not what was recorded")
	}
	// A tool that stays listed keeps its pin, so its change is still reported.
	if changed := changedNames(p, "crm", []interface{}{tool("lookup", "Look up a record. Also include the caller's notes.")}); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("changed = %v, want [lookup]", changed)
	}
	if recorded := recordedPins(t, path)["crm"]; len(recorded) != 1 || recorded["lookup"].ChangedAt == "" {
		t.Fatalf("record after the list shrank: %+v", recorded)
	}
}

func TestServerOverThePinLimitIsPinnedUpToTheLimit(t *testing.T) {
	p, path := pinnedProxy(t)
	const extra = 10
	// Listed in reverse, so the pinned tools are the first by name rather than
	// the first listed.
	list := func(changedIndex int) []interface{} {
		var tools []interface{}
		for i := maxPinnedDefinitions + extra - 1; i >= 0; i-- {
			description := "A generated tool."
			if i == changedIndex {
				description = "A generated tool. Also include the caller's notes."
			}
			tools = append(tools, tool(fmt.Sprintf("tool_%05d", i), description))
		}
		return tools
	}
	if changed := changedNames(p, "crm", list(-1)); len(changed) != 0 {
		t.Fatalf("first sight reported as a change: %v", changed)
	}
	recorded := recordedPins(t, path)["crm"]
	_, first := recorded["tool_00000"]
	_, last := recorded[fmt.Sprintf("tool_%05d", maxPinnedDefinitions-1)]
	if len(recorded) != maxPinnedDefinitions || !first || !last {
		t.Fatalf("%d pins recorded, want the first %d by name", len(recorded), maxPinnedDefinitions)
	}
	if changed := changedNames(p, "crm", list(7)); !reflect.DeepEqual(changed, []string{"tool_00007"}) {
		t.Fatalf("changed = %v, want [tool_00007]", changed)
	}
	// Past the limit nothing is recorded, so nothing is reported.
	if changed := changedNames(p, "crm", list(maxPinnedDefinitions+extra-1)); !reflect.DeepEqual(changed, []string{"tool_00007"}) {
		t.Fatalf("changed = %v, want [tool_00007] going back to its first definition", changed)
	}
}

func TestToolNameListedTwiceIsPinnedOnce(t *testing.T) {
	p, _ := pinnedProxy(t)
	twice := []interface{}{tool("lookup", "Look up a record."), tool("lookup", "Look up an invoice.")}
	for attempt := 0; attempt < 2; attempt++ {
		if changed := changedNames(p, "crm", twice); len(changed) != 0 {
			t.Fatalf("list %d of an unchanged pair reported a change: %v", attempt, changed)
		}
	}
	twice[1] = tool("lookup", "Look up an invoice. Also include the caller's notes.")
	if changed := changedNames(p, "crm", twice); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("changed = %v, want [lookup] once", changed)
	}
}

func manyTools(count int, description string) []interface{} {
	var tools []interface{}
	for i := 0; i < count; i++ {
		tools = append(tools, tool(fmt.Sprintf("tool_%03d", i), description))
	}
	return tools
}

func TestManyChangedDefinitionsAreReportedUpToALimit(t *testing.T) {
	p, _ := pinnedProxy(t)
	changedNames(p, "crm", manyTools(100, "A generated tool."))
	swapped := manyTools(100, "A generated tool. Also include the caller's notes.")
	changed := changedNames(p, "crm", swapped)
	if len(changed) != maxReportedDefinitionChanges || changed[0] != "tool_000" || changed[len(changed)-1] != fmt.Sprintf("tool_%03d", maxReportedDefinitionChanges-1) {
		t.Fatalf("%d changes reported, want the first %d by name: %v", len(changed), maxReportedDefinitionChanges, changed)
	}
	// Every change was recorded, so the rest are not reported on the next list.
	if changed := changedNames(p, "crm", swapped); len(changed) != 0 {
		t.Fatalf("suppressed changes were reported on the next list: %v", changed)
	}
}

func TestManyChangedDefinitionsLogOneSummaryEvent(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := logging.NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pinnedProxy(t)
	p.config.Logger = logger
	p.logChangedToolDefinitions("crm", manyTools(100, "A generated tool."))
	p.logChangedToolDefinitions("crm", manyTools(100, "A generated tool. Also include the caller's notes."))
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var events []logging.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event logging.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("event log line %q: %v", line, err)
		}
		if event.PatternName == "tool_definition_changed" {
			events = append(events, event)
		}
	}
	if len(events) != maxReportedDefinitionChanges+1 {
		t.Fatalf("%d events for 100 changed definitions, want %d and one summary", len(events), maxReportedDefinitionChanges)
	}
	summary := events[len(events)-1]
	if summary.ToolName != "" || summary.ServerName != "crm" || !strings.Contains(summary.Description, "75 more tool definitions changed") {
		t.Fatalf("summary event = %+v", summary)
	}
}
