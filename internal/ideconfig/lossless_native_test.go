package ideconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNativeAndUnsupportedStdioEntriesRetainAllFields(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	path := filepath.Join(root, "client.json")
	original := `{"preferences":{"keep":true},"mcpServers":{"oauth":{"type":"http","url":"https://example.invalid/mcp","oauth":{"clientId":"synthetic"},"disabled":true,"timeout":12345},"stdio":{"command":"node","args":["server.js"],"cwd":"/synthetic/project","envFile":".env","inputs":[{"id":"token"}],"alwaysAllow":["safe"]},"supported":{"command":"node","args":["plain.js"]}}}`
	writeJSON(t, path, original)
	a := mkAdapter(t, path)
	p, err := a.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.NativeKept) != 2 || len(p.Migrated) != 1 {
		t.Fatalf("native=%v migrated=%v", p.NativeKept, p.Migrated)
	}
	if err := a.ApplyManaged(&p); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var beforeDoc, afterDoc map[string]interface{}
	_ = json.Unmarshal([]byte(original), &beforeDoc)
	_ = json.Unmarshal(after, &afterDoc)
	for _, name := range []string{"oauth", "stdio"} {
		before := beforeDoc["mcpServers"].(map[string]interface{})[name]
		after := afterDoc["mcpServers"].(map[string]interface{})[name]
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("%s changed: before=%v after=%v", name, before, after)
		}
	}
}
