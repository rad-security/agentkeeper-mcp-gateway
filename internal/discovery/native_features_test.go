package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNativeClientFeaturesPreservedAndDistinguishedFromAuthentication(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "project", ".mcp.json")
	t.Setenv("AGENTKEEPER_CONFIG", filepath.Join(home, "gateway", "config.json"))
	original := `{"mcpServers":{"features":{"command":"node","args":["fixture.js"],"cwd":"/synthetic/project","envFile":".env","disabled":true},"oauth":{"type":"http","url":"https://mcp.example.invalid/mcp","oauth":{"clientId":"synthetic"}},"static":{"type":"http","url":"https://mcp.example.invalid/mcp","headers":{"Authorization":"Bearer synthetic"}},"plain":{"command":"node","args":["plain.js"]}}}`
	writeFixture(t, source, original)
	result, err := Discover(Options{Home: home, CWD: filepath.Dir(source), Client: ClientClaudeCode})
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range result.Servers {
		switch server.Name {
		case "features":
			if server.Routeability != RouteabilityNativeClientFeatures || server.Routable {
				t.Fatalf("wrong native feature disposition: %+v", server)
			}
		case "oauth":
			if server.Routeability != RouteabilityNativeClientAuth || server.Routable {
				t.Fatalf("wrong auth disposition: %+v", server)
			}
		case "static", "plain":
			if !server.Routable {
				t.Fatalf("supported server was unnecessarily excluded: %+v", server)
			}
		}
	}
	plan, err := MigrateMCPFile(source, ClientClaudeCode, "project", "project_mcp_json", RouteabilityLocalRoutable, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NativeKept) != 2 {
		t.Fatalf("native entries not retained: %+v", plan)
	}
	after, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var beforeDoc, afterDoc struct {
		Servers map[string]interface{} `json:"mcpServers"`
	}
	_ = json.Unmarshal([]byte(original), &beforeDoc)
	_ = json.Unmarshal(after, &afterDoc)
	for _, name := range []string{"features", "oauth"} {
		if !reflect.DeepEqual(beforeDoc.Servers[name], afterDoc.Servers[name]) {
			t.Fatalf("native entry %s mutated: %v", name, afterDoc.Servers[name])
		}
	}
}
