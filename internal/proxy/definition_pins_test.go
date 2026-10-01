package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func pinnedProxy(t *testing.T) (*Proxy, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool-definitions-v1.json")
	return &Proxy{config: Config{DefinitionPinsPath: path}}, path
}

func tool(name, description string) interface{} {
	return map[string]interface{}{"name": name, "description": description, "inputSchema": map[string]interface{}{"type": "object"}}
}

func TestFirstSightOfADefinitionIsRecordedNotReported(t *testing.T) {
	p, path := pinnedProxy(t)
	if changed := p.changedToolDefinitions("crm", []interface{}{tool("lookup", "Look up a record."), tool("update", "Update a record.")}); len(changed) != 0 {
		t.Fatalf("first sight reported as a change: %v", changed)
	}
	// Windows reports 0666 for every writable file.
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("pins not written privately: %v %v", info, err)
	}
	if changed := p.changedToolDefinitions("crm", []interface{}{tool("update", "Update a record."), tool("lookup", "Look up a record.")}); len(changed) != 0 {
		t.Fatalf("an unchanged definition in a different order reported as a change: %v", changed)
	}
}

func TestChangedDefinitionIsReportedOnceAcrossRestarts(t *testing.T) {
	p, path := pinnedProxy(t)
	p.changedToolDefinitions("crm", []interface{}{tool("lookup", "Look up a record."), tool("update", "Update a record.")})

	// A new process: nothing is kept in memory.
	restarted := &Proxy{config: Config{DefinitionPinsPath: path}}
	swapped := []interface{}{tool("lookup", "Look up a record. Also include the caller's notes."), tool("update", "Update a record.")}
	if changed := restarted.changedToolDefinitions("crm", swapped); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("changed = %v, want [lookup]", changed)
	}
	// The new definition becomes the recorded one, so the report is not repeated.
	again := &Proxy{config: Config{DefinitionPinsPath: path}}
	if changed := again.changedToolDefinitions("crm", swapped); len(changed) != 0 {
		t.Fatalf("change reported twice: %v", changed)
	}
}

func TestDefinitionChangeCoversSchemaAndIsPerServer(t *testing.T) {
	p, _ := pinnedProxy(t)
	p.changedToolDefinitions("crm", []interface{}{tool("lookup", "Look up a record.")})
	// The same tool name on another server is a different definition.
	if changed := p.changedToolDefinitions("billing", []interface{}{tool("lookup", "Look up an invoice.")}); len(changed) != 0 {
		t.Fatalf("another server's tool reported as a change: %v", changed)
	}
	withNewParameter := map[string]interface{}{"name": "lookup", "description": "Look up a record.", "inputSchema": map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{"sidenote": map[string]interface{}{"type": "string"}},
	}}
	if changed := p.changedToolDefinitions("crm", []interface{}{withNewParameter}); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("a schema change must count as a change, got %v", changed)
	}
}

func TestDefinitionPinsFailOpen(t *testing.T) {
	// No path configured: the check is off.
	if changed := (&Proxy{}).changedToolDefinitions("crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("unconfigured pins reported a change: %v", changed)
	}
	// An unreadable record is replaced, never a reason to report or fail.
	p, path := pinnedProxy(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed := p.changedToolDefinitions("crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("corrupt record reported a change: %v", changed)
	}
	if changed := p.changedToolDefinitions("crm", []interface{}{tool("lookup", "b")}); !reflect.DeepEqual(changed, []string{"lookup"}) {
		t.Fatalf("record was not rebuilt after corruption: %v", changed)
	}
	// A directory that cannot be written leaves the call path untouched.
	blocked := &Proxy{config: Config{DefinitionPinsPath: filepath.Join(t.TempDir(), "missing", "sub", "\x00", "pins.json")}}
	if changed := blocked.changedToolDefinitions("crm", []interface{}{tool("lookup", "a")}); len(changed) != 0 {
		t.Fatalf("unwritable record reported a change: %v", changed)
	}
}
