package proxy

import (
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

func TestPolicySignatureIgnoresListOrder(t *testing.T) {
	first := telemetry.SyncPolicy{
		Mode:           "enforce",
		BlockedServers: []string{"notes", "docs-search"},
		BlockedTools:   map[string][]string{"files": {"write_file", "delete_file"}},
		CustomKeywords: []string{"beta", "alpha"},
	}
	second := telemetry.SyncPolicy{
		Mode:           "enforce",
		BlockedServers: []string{"docs-search", "notes"},
		BlockedTools:   map[string][]string{"files": {"delete_file", "write_file"}},
		CustomKeywords: []string{"alpha", "beta"},
	}
	if hashJSON(policySignatureView(first)) != hashJSON(policySignatureView(second)) {
		t.Fatal("the same policy in a different order changed the signature")
	}
	if first.BlockedServers[0] != "notes" {
		t.Fatal("the signature view sorted the synced policy in place")
	}

	changed := second
	changed.BlockedServers = []string{"docs-search"}
	if hashJSON(policySignatureView(second)) == hashJSON(policySignatureView(changed)) {
		t.Fatal("a removed blocked server did not change the signature")
	}
}
