package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSyncPayloadIncludesDiscoveredServers(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("Authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw_test","policy":{"mode":"audit"}}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.SetVersion("test-version")
	client.SetMode("audit")
	client.SetServers([]ServerInfo{{Name: "routed", Transport: "stdio"}})
	client.SetDiscoveredServers([]DiscoveredServerInfo{{
		Name:         "atlas",
		Client:       "cowork",
		Scope:        "plugin",
		SourceKind:   "cowork_plugin_mcp",
		SourceHash:   "abc123",
		Transport:    "stdio",
		RouteState:   "direct",
		Routeability: "cowork_local_plugin_mcp_routable",
		Routable:     true,
		EnvKeys:      []string{"ATLAS_TOKEN"},
	}})

	client.sync()

	discovered, ok := captured["discovered_servers"].([]any)
	if !ok || len(discovered) != 1 {
		t.Fatalf("discovered_servers missing/wrong: %#v", captured["discovered_servers"])
	}
	got := discovered[0].(map[string]any)
	if got["name"] != "atlas" || got["client"] != "cowork" || got["route_state"] != "direct" {
		t.Fatalf("unexpected discovered server payload: %#v", got)
	}
	if got["source_hash"] != "abc123" {
		t.Fatalf("source_hash missing: %#v", got)
	}
	if client.gatewayID != "gw_test" {
		t.Fatalf("gatewayID = %q", client.gatewayID)
	}
}
