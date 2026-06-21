package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
)

func TestSyncPayloadIncludesDiscoveredServers(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-sync-1")

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

	if captured["machine_id"] != "machine-sync-1" {
		t.Fatalf("machine_id = %#v, want machine-sync-1", captured["machine_id"])
	}

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

func TestEvaluatePayloadIncludesMachineID(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-evaluate-1")

	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/evaluate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"pass"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.gatewayID = "gw_test"

	result := client.Evaluate("atlas", "search", map[string]interface{}{"query": "test"})
	if result == nil || result.Verdict != "pass" {
		t.Fatalf("unexpected evaluate result: %#v", result)
	}
	if captured["machine_id"] != "machine-evaluate-1" {
		t.Fatalf("machine_id = %#v, want machine-evaluate-1", captured["machine_id"])
	}
	if captured["gateway_id"] != "gw_test" {
		t.Fatalf("gateway_id = %#v, want gw_test", captured["gateway_id"])
	}
}

func TestFlushRequeuesEventsUntilDashboardAcknowledges(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-events-retry-1")

	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolCall("qa-stdio", "echo", map[string]interface{}{"text": "hello"}, detection.Result{})

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests++
		if requests == 1 {
			http.Error(w, "temporary outage", http.StatusBadGateway)
			return
		}
		var captured struct {
			Events    []logging.Event `json:"events"`
			MachineID string          `json:"machine_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		if captured.MachineID != "machine-events-retry-1" {
			t.Fatalf("machine_id = %q, want machine-events-retry-1", captured.MachineID)
		}
		if len(captured.Events) != 1 || captured.Events[0].ServerName != "qa-stdio" {
			t.Fatalf("unexpected retried events: %+v", captured.Events)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"received":1}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", logger)
	client.gatewayID = "gw-test"

	client.flush()
	if requests != 1 {
		t.Fatalf("requests after first flush = %d, want 1", requests)
	}
	client.flush()
	if requests != 2 {
		t.Fatalf("requests after second flush = %d, want 2", requests)
	}
	if remaining := logger.FlushBuffer(); len(remaining) != 0 {
		t.Fatalf("expected acknowledged buffer to be empty, got %+v", remaining)
	}
}

func TestFlushRequeuesWhenDashboardAckIsIncomplete(t *testing.T) {
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolCall("qa-stdio", "echo", map[string]interface{}{"text": "hello"}, detection.Result{})

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"ok":true,"inserted":0,"received":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"received":1}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", logger)
	client.flush()
	client.flush()

	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if remaining := logger.FlushBuffer(); len(remaining) != 0 {
		t.Fatalf("expected buffer empty after complete ack, got %+v", remaining)
	}
}

func TestFlushUploadsOnlyDashboardIngestableEvents(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-events-filter-1")

	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogSessionStart("dev-workstation-01", "darwin", "0.1.13", []string{"qa-stdio"})
	logger.LogToolCall("qa-stdio", "echo", map[string]interface{}{"text": "hello"}, detection.Result{})

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var captured struct {
			Events    []logging.Event `json:"events"`
			MachineID string          `json:"machine_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		if captured.MachineID != "machine-events-filter-1" {
			t.Fatalf("machine_id = %q, want machine-events-filter-1", captured.MachineID)
		}
		if len(captured.Events) != 1 {
			t.Fatalf("uploaded events = %+v, want only the tool call", captured.Events)
		}
		if captured.Events[0].EventType != "mcp.tool_call" ||
			captured.Events[0].ServerName != "qa-stdio" ||
			captured.Events[0].ToolName != "echo" {
			t.Fatalf("unexpected uploaded event: %+v", captured.Events[0])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"received":1}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", logger)
	client.flush()

	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if remaining := logger.FlushBuffer(); len(remaining) != 0 {
		t.Fatalf("expected acknowledged buffer to be empty, got %+v", remaining)
	}
}
