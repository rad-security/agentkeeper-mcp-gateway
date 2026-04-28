package policy

import (
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

func TestBlockedServer(t *testing.T) {
	p := telemetry.SyncPolicy{
		BlockedServers: []string{"evil-server", "risky-db"},
	}
	r := Evaluate(p, "evil-server", "some_tool", map[string]interface{}{"key": "value"})
	if r.Verdict != "block" {
		t.Errorf("expected block for blocked server, got %s", r.Verdict)
	}
	if r.Rule != "blocked_server" {
		t.Errorf("expected rule blocked_server, got %s", r.Rule)
	}
}

func TestBlockedTool(t *testing.T) {
	p := telemetry.SyncPolicy{
		BlockedTools: map[string][]string{
			"github": {"delete_repo", "delete_branch"},
		},
	}
	r := Evaluate(p, "github", "delete_repo", map[string]interface{}{})
	if r.Verdict != "block" {
		t.Errorf("expected block for blocked tool, got %s", r.Verdict)
	}
	if r.Rule != "blocked_tool" {
		t.Errorf("expected rule blocked_tool, got %s", r.Rule)
	}
}

func TestBlockedToolAllowsOtherTools(t *testing.T) {
	p := telemetry.SyncPolicy{
		BlockedTools: map[string][]string{
			"github": {"delete_repo"},
		},
	}
	r := Evaluate(p, "github", "list_repos", map[string]interface{}{})
	if r.Verdict != "allow" {
		t.Errorf("expected allow for non-blocked tool, got %s", r.Verdict)
	}
}

func TestBlockedToolCaseInsensitiveServerName(t *testing.T) {
	p := telemetry.SyncPolicy{
		BlockedTools: map[string][]string{
			"GitHub": {"delete_repo"},
		},
	}
	r := Evaluate(p, "github", "delete_repo", map[string]interface{}{})
	if r.Verdict != "block" {
		t.Errorf("expected block for case-insensitive server name in BlockedTools, got %s", r.Verdict)
	}
	if r.Rule != "blocked_tool" {
		t.Errorf("expected rule blocked_tool, got %s", r.Rule)
	}
}

func TestCustomKeywordMatch(t *testing.T) {
	p := telemetry.SyncPolicy{
		CustomKeywords: []string{"ACME-INTERNAL", "PROJECT-FALCON"},
		Detection: telemetry.DetectionConfig{
			SensitiveData: "warn",
		},
	}
	r := Evaluate(p, "github", "create_issue", map[string]interface{}{
		"body": "This contains ACME-INTERNAL data",
	})
	if r.Verdict != "warn" {
		t.Errorf("expected warn for custom keyword, got %s", r.Verdict)
	}
	if r.Rule != "custom_keyword" {
		t.Errorf("expected rule custom_keyword, got %s", r.Rule)
	}
}

func TestCustomKeywordCaseInsensitive(t *testing.T) {
	p := telemetry.SyncPolicy{
		CustomKeywords: []string{"SECRET-PROJECT"},
		Detection: telemetry.DetectionConfig{
			SensitiveData: "block",
		},
	}
	r := Evaluate(p, "github", "create_issue", map[string]interface{}{
		"body": "mentions secret-project casually",
	})
	if r.Verdict != "block" {
		t.Errorf("expected block for case-insensitive keyword, got %s", r.Verdict)
	}
}

func TestCustomKeywordUsesDetectionMode(t *testing.T) {
	p := telemetry.SyncPolicy{
		CustomKeywords: []string{"CLASSIFIED"},
		Detection: telemetry.DetectionConfig{
			SensitiveData: "block",
		},
	}
	r := Evaluate(p, "test", "test", map[string]interface{}{
		"data": "This is CLASSIFIED information",
	})
	if r.Verdict != "block" {
		t.Errorf("expected block when detection mode is block, got %s", r.Verdict)
	}
}

func TestCustomKeywordDefaultsToWarn(t *testing.T) {
	p := telemetry.SyncPolicy{
		CustomKeywords: []string{"CLASSIFIED"},
		// Detection.SensitiveData is empty string
	}
	r := Evaluate(p, "test", "test", map[string]interface{}{
		"data": "This is CLASSIFIED information",
	})
	if r.Verdict != "warn" {
		t.Errorf("expected warn when detection mode is empty, got %s", r.Verdict)
	}
}

func TestEmptyPolicy(t *testing.T) {
	p := telemetry.SyncPolicy{}
	r := Evaluate(p, "github", "list_repos", map[string]interface{}{"query": "test"})
	if r.Verdict != "allow" {
		t.Errorf("expected allow for empty policy, got %s", r.Verdict)
	}
}

func TestNilArgs(t *testing.T) {
	p := telemetry.SyncPolicy{
		CustomKeywords: []string{"SECRET"},
	}
	r := Evaluate(p, "test", "test", nil)
	if r.Verdict != "allow" {
		t.Errorf("expected allow for nil args, got %s", r.Verdict)
	}
}

func TestServerBlockTakesPriority(t *testing.T) {
	p := telemetry.SyncPolicy{
		BlockedServers: []string{"evil-server"},
		BlockedTools: map[string][]string{
			"evil-server": {"some_tool"},
		},
		CustomKeywords: []string{"keyword"},
	}
	r := Evaluate(p, "evil-server", "some_tool", map[string]interface{}{
		"data": "contains keyword here",
	})
	if r.Verdict != "block" {
		t.Errorf("expected block, got %s", r.Verdict)
	}
	if r.Rule != "blocked_server" {
		t.Errorf("expected blocked_server (first match), got %s", r.Rule)
	}
}
