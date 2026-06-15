package proxy

import "testing"

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
