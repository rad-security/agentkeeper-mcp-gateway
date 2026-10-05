package proxy

import (
	"errors"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
)

func TestListedToolsReportsOnlyKnownLists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := NewProxy(Config{}, server.NewManager(nil), nil)
	search := map[string]interface{}{"name": "search", "description": "Search notes."}

	p.setCachedTools("notes", []interface{}{search})
	p.setCachedTools("quiet", nil)
	p.setCachedTools("quiet", nil)
	p.setCachedTools("starting", nil)
	p.setCachedTools("crashed", []interface{}{map[string]interface{}{"name": "lookup"}})
	p.handleBackendLifecycle("crashed", "exited", errors.New("synthetic exit"))

	listed := p.ListedTools()
	if tools := listed["notes"]; len(tools) != 1 {
		t.Fatalf("notes: %v", tools)
	}
	if tools, known := listed["quiet"]; !known || tools == nil || len(tools) != 0 {
		t.Fatalf("two empty listings are a known empty list: %v (known %v)", tools, known)
	}
	for _, name := range []string{"starting", "crashed", "never-listed"} {
		if tools, known := listed[name]; known {
			t.Fatalf("%s has no known list but was reported: %v", name, tools)
		}
	}

	listed["notes"][0].(map[string]interface{})["description"] = "changed by a caller"
	if got := p.cachedTools("notes")[0].(map[string]interface{})["description"]; got != "Search notes." {
		t.Fatalf("the snapshot shares the cache's tool maps: %v", got)
	}
}
