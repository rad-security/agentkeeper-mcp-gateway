package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

func TestToolCacheClonesAndIgnoresEmptyRefresh(t *testing.T) {
	p := &Proxy{toolCache: make(map[string][]interface{})}
	original := []interface{}{
		map[string]interface{}{
			"name":        "search",
			"description": "Search things",
		},
	}

	p.setCachedTools("atlassian", original)
	original[0].(map[string]interface{})["name"] = "mutated"

	cached := p.cachedTools("atlassian")
	if got := cached[0].(map[string]interface{})["name"]; got != "search" {
		t.Fatalf("cache should not share tool maps with caller, got name=%v", got)
	}

	cached[0].(map[string]interface{})["name"] = "changed-again"
	if got := p.cachedTools("atlassian")[0].(map[string]interface{})["name"]; got != "search" {
		t.Fatalf("cachedTools should return a clone, got name=%v", got)
	}

	p.setCachedTools("atlassian", nil)
	if got := p.cachedTools("atlassian")[0].(map[string]interface{})["name"]; got != "search" {
		t.Fatalf("empty refresh should not overwrite previous usable cache, got name=%v", got)
	}
}

func TestAppendNamespacedToolsDoesNotMutateOriginalTools(t *testing.T) {
	tools := []interface{}{
		map[string]interface{}{
			"name":        "lookup",
			"description": "Lookup item",
		},
	}
	var allTools []interface{}
	toolMap := make(map[string]string)

	appendNamespacedTools(&allTools, toolMap, "ontra", tools)

	if got := tools[0].(map[string]interface{})["name"]; got != "lookup" {
		t.Fatalf("appendNamespacedTools mutated original tool name: %v", got)
	}
	if got := allTools[0].(map[string]interface{})["name"]; got != "ontra__lookup" {
		t.Fatalf("namespaced tool name mismatch: %v", got)
	}
	if got := toolMap["ontra__lookup"]; got != "ontra" {
		t.Fatalf("tool map mismatch: %v", got)
	}
}

func TestToolCachePersistsLastKnownGoodManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &Proxy{toolCache: make(map[string][]interface{})}
	p.setCachedTools("atlas", []interface{}{
		map[string]interface{}{
			"name":        "search",
			"description": "Search accounts",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	})

	cachePath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "tool-cache.json")
	if info, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected persistent tool cache at %s: %v", cachePath, err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file permissions = %o, want 0600", info.Mode().Perm())
	}

	restored := &Proxy{toolCache: make(map[string][]interface{})}
	restored.loadPersistentToolCache()
	tools := restored.cachedTools("atlas")
	if len(tools) != 1 {
		t.Fatalf("expected restored cached tool, got %d", len(tools))
	}
	if got := tools[0].(map[string]interface{})["name"]; got != "search" {
		t.Fatalf("restored cached tool name = %v, want search", got)
	}
}

func TestApplyDetectionPolicyEscalatesConfiguredDetectorBlocks(t *testing.T) {
	result := detection.Result{
		Verdict:     detection.VerdictWarn,
		PatternName: "api_key_aws",
		Severity:    "critical",
		Category:    "sensitive_data",
	}

	escalated := applyDetectionPolicy(result, telemetry.SyncPolicy{
		Detection: telemetry.DetectionConfig{SensitiveData: "block"},
	}, telemetry.DetectionConfig{})
	if escalated.Verdict != detection.VerdictBlock {
		t.Fatalf("sensitive_data verdict = %s, want block", escalated.Verdict)
	}

	threatFromDashboard := applyDetectionPolicy(detection.Result{
		Verdict:  detection.VerdictWarn,
		Category: "threat",
	}, telemetry.SyncPolicy{
		Detection: telemetry.DetectionConfig{Threat: "block"},
	}, telemetry.DetectionConfig{})
	if threatFromDashboard.Verdict != detection.VerdictBlock {
		t.Fatalf("dashboard threat verdict = %s, want block", threatFromDashboard.Verdict)
	}

	threatFromLocalConfig := applyDetectionPolicy(detection.Result{
		Verdict:  detection.VerdictWarn,
		Category: "threat",
	}, telemetry.SyncPolicy{}, telemetry.DetectionConfig{Threat: "block"})
	if threatFromLocalConfig.Verdict != detection.VerdictBlock {
		t.Fatalf("local threat verdict = %s, want block", threatFromLocalConfig.Verdict)
	}
}

func TestCachedToolSummaryIgnoresStaleServersOutsideCurrentConfig(t *testing.T) {
	mgr := server.NewManager([]server.ServerConfig{{
		Name:      "active",
		Transport: "http",
		URL:       "https://example.test/mcp",
	}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}

	p := &Proxy{
		manager: mgr,
		toolCache: map[string][]interface{}{
			"active": {
				map[string]interface{}{"name": "lookup"},
			},
			"stale": {
				map[string]interface{}{"name": "old_one"},
				map[string]interface{}{"name": "old_two"},
			},
		},
		toolStatus: map[string]toolRefreshStatus{
			"active": {Status: "ready"},
			"stale":  {Status: "degraded"},
		},
	}

	backendCount, toolCount, degradedCount := p.cachedToolSummary()
	if backendCount != 1 || toolCount != 1 || degradedCount != 0 {
		t.Fatalf("summary = backends:%d tools:%d degraded:%d, want 1/1/0", backendCount, toolCount, degradedCount)
	}
}
