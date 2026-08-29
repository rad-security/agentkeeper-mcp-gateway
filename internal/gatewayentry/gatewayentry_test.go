package gatewayentry

import (
	"encoding/json"
	"testing"
)

func TestAttestRoutesBindsRootAndNestedGatewayWithoutTouchingBackendEnv(t *testing.T) {
	t.Setenv(EnvBinary, "/opt/agentkeeper/bin/agentkeeper-mcp-gateway")
	source := []byte(`{
		"mcpServers": {
			"gateway": {"command":"/opt/agentkeeper/bin/agentkeeper-mcp-gateway","args":["server"]},
			"backend": {"command":"node","env":{"AGENTKEEPER_MCP_CONFIG_SOURCE_HASH":"customer-value"}}
		},
		"projects": {"/work": {"mcpServers": {
			"another-name": {"command":"/opt/agentkeeper/bin/agentkeeper-mcp-gateway","args":["server"],"env":{"AGENTKEEPER_MCP_CONFIG_SOURCE_HASH":"stale"}}
		}}}
	}`)
	bound, sourceHash, routeRevision, err := AttestRoutes("claude-code", source)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(bound, &document); err != nil {
		t.Fatal(err)
	}
	assertEntry := func(entry map[string]interface{}) {
		env := entry["env"].(map[string]interface{})
		if env[EnvClientName] != "claude-code" || env[EnvConfigSourceHash] != sourceHash || env[EnvRouteRevision] != routeRevision {
			t.Fatalf("route entry is not bound to final identity: %+v", env)
		}
	}
	rootServers := document["mcpServers"].(map[string]interface{})
	assertEntry(rootServers["gateway"].(map[string]interface{}))
	projects := document["projects"].(map[string]interface{})
	project := projects["/work"].(map[string]interface{})
	projectServers := project["mcpServers"].(map[string]interface{})
	assertEntry(projectServers["another-name"].(map[string]interface{}))
	backendEnv := rootServers["backend"].(map[string]interface{})["env"].(map[string]interface{})
	if backendEnv[EnvConfigSourceHash] != "customer-value" {
		t.Fatalf("non-gateway backend env was modified: %+v", backendEnv)
	}
	gotHash, gotRevision := RouteIdentity("claude-code", bound)
	if gotHash != sourceHash || gotRevision != routeRevision {
		t.Fatalf("bound document identity is not stable: got %s %s", gotHash, gotRevision)
	}
}

func TestIsGatewayCommandHandlesWindowsPath(t *testing.T) {
	if !IsGatewayCommand(`C:\Program Files\AgentKeeper\agentkeeper-mcp-gateway.exe`) {
		t.Fatal("Windows Gateway path was not recognized")
	}
}

func TestIsGatewayCommandHandlesReleaseAssetName(t *testing.T) {
	if !IsGatewayCommand(`/opt/agentkeeper/agentkeeper-mcp-gateway_darwin_arm64`) {
		t.Fatal("release artifact Gateway path was not recognized")
	}
}
