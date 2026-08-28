package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
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

	result := client.Evaluate("atlas", "search", map[string]interface{}{"query": "test"}, "call-test-1", "attempt-test-1")
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

func TestEvaluateV2DoesNotDoubleTimeoutOnServerFailure(t *testing.T) {
	store, err := receipt.NewStore(filepath.Join(t.TempDir(), "receipts"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v2/mcp/evaluate" {
			t.Fatalf("unexpected legacy retry after v2 server failure: %s", r.URL.Path)
		}
		http.Error(w, "temporarily unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.SetReceiptStore(store)
	if result := client.Evaluate("atlas", "search", nil, "call-test-1", "attempt-test-1"); result != nil {
		t.Fatalf("failed connected evaluation should return nil for local fallback, got %#v", result)
	}
	if requests != 1 {
		t.Fatalf("server failure should make one request, got %d", requests)
	}
}

func TestEvaluateV2FallsBackWhenEndpointIsUnsupported(t *testing.T) {
	store, err := receipt.NewStore(filepath.Join(t.TempDir(), "receipts"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/api/v2/mcp/evaluate" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"pass"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.SetReceiptStore(store)
	result := client.Evaluate("atlas", "search", nil, "call-test-1", "attempt-test-1")
	if result == nil || result.Verdict != "pass" {
		t.Fatalf("legacy fallback result = %#v", result)
	}
	if len(paths) != 2 || paths[0] != "/api/v2/mcp/evaluate" || paths[1] != "/api/v1/mcp/evaluate" {
		t.Fatalf("unexpected fallback path sequence: %v", paths)
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

func TestSignedReceiptRegistrationAndPerItemAcknowledgment(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-receipt-1")
	store, err := receipt.NewStore(t.TempDir(), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	registered := false
	uploaded := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["effective_mode"] != "observe" || payload["signer_key_id"] != store.SignerKeyID() {
				t.Fatalf("unexpected registration: %#v", payload)
			}
			registered = true
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","route_assignment":{"desired_mode":"enforce","desired_revision":7}}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"audit"}}`))
		case "/api/v2/mcp/receipts":
			var payload struct {
				GatewayID string             `json:"gateway_id"`
				Receipts  []receipt.Envelope `json:"receipts"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Receipts) != 1 || payload.Receipts[0].AppliedDisposition != "result_returned" {
				t.Fatalf("unexpected receipts: %+v", payload.Receipts)
			}
			uploaded = true
			_, _ = w.Write([]byte(`{"ok":true,"acks":[{"receipt_id":"` + payload.Receipts[0].ReceiptID + `","status":"accepted"}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.SetVersion("0.2.0-test")
	client.SetReceiptStore(store)
	client.SetRouteContext("claude-desktop", "sha256:source", "route:test")
	appliedMode := ""
	var appliedRevision int64
	client.SetModeChangeHandler(func(mode string, revision int64) {
		appliedMode = mode
		appliedRevision = revision
	})
	client.sync()
	if appliedMode != "enforce" || appliedRevision != 7 {
		t.Fatalf("route assignment not applied: mode=%q revision=%d", appliedMode, appliedRevision)
	}
	if mode, revision := client.currentMode(); mode != "enforce" || revision != 7 {
		t.Fatalf("effective assignment not retained: mode=%q revision=%d", mode, revision)
	}
	client.RecordReceipt(receipt.Input{
		CallID: "call-12345678", AttemptID: "attempt-12345678", Phase: "terminal",
		ServerName: "atlas", ToolName: "search", PolicyDecision: "pass",
		EvaluationStatus: "evaluated", RequiredDisposition: "forward",
		AppliedDisposition: "result_returned", EffectiveMode: "observe",
		Dispatched: true, ResultReceived: true, ResultReturned: true, Terminal: true,
	})
	client.flushReceipts()

	if !registered || !uploaded {
		t.Fatalf("registered=%v uploaded=%v", registered, uploaded)
	}
	queued, err := store.Peek(100)
	if err != nil || len(queued) != 0 {
		t.Fatalf("queue after ack=%+v err=%v", queued, err)
	}
}
