package gatewayentry

import (
	"encoding/json"
	"testing"
)

func TestIsAttestedRouteAcceptsOnlyWhatAttestRoutesWrote(t *testing.T) {
	t.Setenv(EnvBinary, "/opt/synthetic/agentkeeper-mcp-gateway")
	source := []byte(`{"mcpServers":{"agentkeeper-mcp-gateway":{"command":"/opt/synthetic/agentkeeper-mcp-gateway","args":["server"]}},"numStartups":1}`)
	bound, _, _, err := AttestRoutes("claude-code", source)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Servers map[string]struct {
			Command string            `json:"command"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(bound, &document); err != nil {
		t.Fatal(err)
	}
	entry := document.Servers["agentkeeper-mcp-gateway"]
	if !IsAttestedRoute(entry.Command, entry.Env) {
		t.Fatalf("entry written by AttestRoutes was not recognised: %+v", entry)
	}
	for _, key := range []string{EnvClientName, EnvConfigSourceHash, EnvRouteRevision} {
		edited := map[string]string{}
		for k, v := range entry.Env {
			edited[k] = v
		}
		edited[key] = edited[key] + "-edited"
		if IsAttestedRoute(entry.Command, edited) {
			t.Fatalf("entry with hand-edited %s was accepted", key)
		}
	}
	if IsAttestedRoute(entry.Command, map[string]string{}) {
		t.Fatal("legacy entry without attestation was accepted")
	}
	if IsAttestedRoute("/usr/bin/other-server", entry.Env) {
		t.Fatal("attestation was accepted for a non-Gateway command")
	}
}
