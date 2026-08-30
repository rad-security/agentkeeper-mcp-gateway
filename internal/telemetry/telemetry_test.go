package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

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

func TestLastKnownGoodPolicyAndAssignmentSurviveOfflineRestart(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-policy-cache-1")
	root := t.TempDir()
	receiptRoot := filepath.Join(root, "receipts")
	cachePath := filepath.Join(root, "policy-cache-v1.json")
	store, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","route_assignment":{"desired_mode":"enforce","desired_revision":9}}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","policy":{"mode":"enforce","blocked_tools":{"payments":["transfer"]},"detection":{"threat":"block","sensitive_data":"block"}}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))

	client := NewClient(srv.URL, "test-key", nil)
	client.SetMode("audit")
	client.SetReceiptStore(store)
	if err := client.SetPolicyCache(cachePath); err != nil {
		t.Fatal(err)
	}
	client.sync()
	if got := client.Policy().BlockedTools["payments"]; len(got) != 1 || got[0] != "transfer" {
		t.Fatalf("online policy not cached: %+v", client.Policy())
	}
	if info, err := os.Stat(cachePath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("policy cache mode=%o, want 0600", info.Mode().Perm())
	}
	srv.Close()

	restartedStore, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewClient("http://127.0.0.1:1", "test-key", nil)
	restarted.SetMode("audit")
	restarted.SetReceiptStore(restartedStore)
	if err := restarted.SetPolicyCache(cachePath); err != nil {
		t.Fatal(err)
	}
	if mode, revision := restarted.EffectiveMode(); mode != "enforce" || revision != 9 {
		t.Fatalf("effective mode=%q revision=%d after restore", mode, revision)
	}
	var appliedMode string
	var appliedRevision int64
	restarted.SetModeChangeHandler(func(mode string, revision int64) {
		appliedMode = mode
		appliedRevision = revision
	})
	if appliedMode != "enforce" || appliedRevision != 9 {
		t.Fatalf("restored assignment mode=%q revision=%d", appliedMode, appliedRevision)
	}
	if got := restarted.Policy().BlockedTools["payments"]; len(got) != 1 || got[0] != "transfer" {
		t.Fatalf("offline restart lost policy: %+v", restarted.Policy())
	}
}

func TestMissingPolicyCacheAfterEstablishedEnforceFailsClosed(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-policy-cache-missing")
	root := t.TempDir()
	receiptRoot := filepath.Join(root, "receipts")
	cachePath := filepath.Join(root, "policy-cache-v1.json")
	store, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","route_assignment":{"desired_mode":"enforce","desired_revision":19}}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","policy":{"mode":"enforce","blocked_tools":{"payments":["transfer"]}}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))

	client := NewClient(srv.URL, "test-key", nil)
	client.SetMode("audit")
	client.SetRouteContext("claude-code", "sha256:source", "route:19")
	client.SetReceiptStore(store)
	if err := client.SetPolicyCache(cachePath); err != nil {
		t.Fatal(err)
	}
	client.sync()
	if _, err := os.Stat(client.policyStatePath); err != nil {
		t.Fatalf("established policy state was not persisted: %v", err)
	}
	if err := os.Remove(client.policyCachePath); err != nil {
		t.Fatal(err)
	}
	srv.Close()

	restartedStore, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewClient("http://127.0.0.1:1", "test-key", nil)
	restarted.SetMode("audit")
	restarted.SetRouteContext("claude-code", "sha256:source", "route:19")
	restarted.SetReceiptStore(restartedStore)
	if err := restarted.SetPolicyCache(cachePath); err == nil {
		t.Fatal("missing policy snapshot after established Enforce assignment was accepted")
	}
	if mode, revision := restarted.EffectiveMode(); mode != "enforce" || revision != 19 {
		t.Fatalf("missing-cache restart mode=%q revision=%d", mode, revision)
	}
	if got := restarted.Policy().BlockedServers; len(got) != 1 || got[0] != "*" {
		t.Fatalf("missing-cache restart did not fail closed: %+v", restarted.Policy())
	}

	firstBoot := NewClient("http://127.0.0.1:1", "test-key", nil)
	firstBoot.SetMode("audit")
	firstBoot.SetRouteContext("cursor", "sha256:new", "route:new")
	firstBoot.SetReceiptStore(restartedStore)
	if err := firstBoot.SetPolicyCache(filepath.Join(root, "fresh-policy-cache.json")); err != nil {
		t.Fatalf("true first boot should remain Observe: %v", err)
	}
	if mode, _ := firstBoot.EffectiveMode(); mode != "observe" {
		t.Fatalf("true first boot mode=%q, want observe", mode)
	}
}

func TestPolicyCacheIsScopedAndBoundToRouteIdentity(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-policy-cache-routes")
	root := t.TempDir()
	receiptRoot := filepath.Join(root, "receipts")
	baseCachePath := filepath.Join(root, "policy-cache-v1.json")
	store, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			var payload struct {
				ConnectedClients []string `json:"connected_clients"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.ConnectedClients) == 1 && payload.ConnectedClients[0] == "claude-code" {
				_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-route-cache","route_assignment":{"desired_mode":"enforce","desired_revision":11}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-route-cache","route_assignment":{"desired_mode":"observe","desired_revision":12}}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-route-cache","policy":{"mode":"enforce","blocked_servers":["payments"]}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	newRouteClient := func(clientName, configHash, routeRevision string) *Client {
		client := NewClient(srv.URL, "test-key", nil)
		client.SetMode("audit")
		client.SetRouteContext(clientName, configHash, routeRevision)
		client.SetReceiptStore(store)
		if err := client.SetPolicyCache(baseCachePath); err != nil {
			t.Fatal(err)
		}
		return client
	}
	claude := newRouteClient("claude-code", "sha256:claude", "route:claude")
	cursor := newRouteClient("cursor", "sha256:cursor", "route:cursor")
	if claude.policyCachePath == cursor.policyCachePath {
		t.Fatalf("route-scoped caches collided at %s", claude.policyCachePath)
	}
	claude.sync()
	cursor.sync()

	restartedStore, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	restart := func(clientName, configHash, routeRevision string) *Client {
		client := NewClient("http://127.0.0.1:1", "test-key", nil)
		client.SetMode("audit")
		client.SetRouteContext(clientName, configHash, routeRevision)
		client.SetReceiptStore(restartedStore)
		if err := client.SetPolicyCache(baseCachePath); err != nil {
			t.Fatal(err)
		}
		return client
	}
	restartedClaude := restart("claude-code", "sha256:claude", "route:claude")
	if mode, revision := restartedClaude.EffectiveMode(); mode != "enforce" || revision != 11 {
		t.Fatalf("Claude route restored mode=%q revision=%d", mode, revision)
	}
	restartedCursor := restart("cursor", "sha256:cursor", "route:cursor")
	if mode, revision := restartedCursor.EffectiveMode(); mode != "observe" || revision != 12 {
		t.Fatalf("Cursor route restored mode=%q revision=%d", mode, revision)
	}

	claudeSnapshot, err := os.ReadFile(claude.policyCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor.policyCachePath, claudeSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	swapped := NewClient("http://127.0.0.1:1", "test-key", nil)
	swapped.SetMode("audit")
	swapped.SetRouteContext("cursor", "sha256:cursor", "route:cursor")
	swapped.SetReceiptStore(restartedStore)
	if err := swapped.SetPolicyCache(baseCachePath); err == nil {
		t.Fatal("signed cache from a different route identity was accepted")
	}
	if mode, _ := swapped.EffectiveMode(); mode != "enforce" {
		t.Fatalf("route-identity mismatch restored mode=%q, want fail-closed enforce", mode)
	}
}

func TestTamperedOrExpiredPolicyFailsClosedOnlyAfterTrustWasEstablished(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-policy-cache-2")
	root := t.TempDir()
	receiptRoot := filepath.Join(root, "receipts")
	cachePath := filepath.Join(root, "policy-cache-v1.json")
	store, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/mcp/gateways/register" {
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","route_assignment":{"desired_mode":"enforce","desired_revision":3}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-policy-cache","policy":{"blocked_servers":["payments"]}}`))
	}))
	client := NewClient(srv.URL, "test-key", nil)
	client.now = func() time.Time { return fixedNow }
	client.policyCacheTTL = time.Minute
	client.SetMode("enforce")
	client.SetReceiptStore(store)
	if err := client.SetPolicyCache(cachePath); err != nil {
		t.Fatal(err)
	}
	client.sync()
	srv.Close()

	restartedStore, err := receipt.NewStore(receiptRoot, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	expired := NewClient("http://127.0.0.1:1", "test-key", nil)
	expired.now = func() time.Time { return fixedNow.Add(2 * time.Minute) }
	expired.SetMode("enforce")
	expired.SetReceiptStore(restartedStore)
	if err := expired.SetPolicyCache(cachePath); err != nil {
		t.Fatal(err)
	}
	if got := expired.Policy().BlockedServers; len(got) != 1 || got[0] != "*" {
		t.Fatalf("expired enforce policy did not fail closed: %+v", expired.Policy())
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(`"payments"`), []byte(`"attacker"`), 1)
	if err := os.WriteFile(cachePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := NewClient("http://127.0.0.1:1", "test-key", nil)
	invalid.SetMode("audit")
	invalid.SetReceiptStore(restartedStore)
	if err := invalid.SetPolicyCache(cachePath); err == nil {
		t.Fatal("tampered policy cache was accepted")
	}
	if mode, _ := invalid.EffectiveMode(); mode != "enforce" {
		t.Fatalf("tampered policy cache restored mode=%q, want fail-closed enforce", mode)
	}
	if got := invalid.Policy().BlockedServers; len(got) != 1 || got[0] != "*" {
		t.Fatalf("tampered established policy did not fail closed: %+v", invalid.Policy())
	}

	firstBoot := NewClient("http://127.0.0.1:1", "test-key", nil)
	firstBoot.SetMode("enforce")
	if got := firstBoot.Policy().BlockedServers; len(got) != 0 {
		t.Fatalf("true first boot unexpectedly failed closed: %+v", firstBoot.Policy())
	}
}

func TestFailedEventUploadReplaysAfterLoggerRestart(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-event-restart-1")
	root := t.TempDir()
	logPath := filepath.Join(root, "events.jsonl")
	logger, err := logging.NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolCall("payments", "transfer", nil, detection.Result{})
	var accepted atomic.Bool
	var replayedEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accepted.Load() {
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		var payload struct {
			Events []logging.Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Events) != 1 || payload.Events[0].EventID == "" {
			t.Fatalf("unexpected replay payload: %+v", payload.Events)
		}
		replayedEventID = payload.Events[0].EventID
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"received":1}`))
	}))
	defer srv.Close()

	first := NewClient(srv.URL, "test-key", logger)
	first.flush()
	pending, _, err := logger.PendingEvents(100)
	if err != nil || len(pending) != 1 {
		t.Fatalf("failed upload was not durable: %+v err=%v", pending, err)
	}
	originalEventID := pending[0].EventID
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	restartedLogger, err := logging.NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedLogger.Close()
	accepted.Store(true)
	restarted := NewClient(srv.URL, "test-key", restartedLogger)
	restarted.flush()
	if replayedEventID != originalEventID {
		t.Fatalf("replayed event id=%q, want %q", replayedEventID, originalEventID)
	}
	pending, _, err = restartedLogger.PendingEvents(100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged replay remained pending: %+v err=%v", pending, err)
	}
}

func TestEventPartialAcknowledgmentsRetainOnlyRetryableItems(t *testing.T) {
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("payments", "first", nil, detection.Result{})
	logger.LogToolCall("payments", "second", nil, detection.Result{})
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload struct {
			Events []logging.Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if len(payload.Events) != 2 {
				t.Fatalf("first batch size=%d, want 2", len(payload.Events))
			}
			_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"acks":[{"event_id":"` + payload.Events[0].EventID + `","status":"accepted"},{"event_id":"` + payload.Events[1].EventID + `","status":"retryable"}]}`))
			return
		}
		if len(payload.Events) != 1 {
			t.Fatalf("retry batch size=%d, want 1", len(payload.Events))
		}
		_, _ = w.Write([]byte(`{"ok":true,"inserted":0,"acks":[{"event_id":"` + payload.Events[0].EventID + `","status":"duplicate"}]}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "test-key", logger)
	client.flush()
	remaining, _, err := logger.PendingEvents(100)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("partial ack remaining=%+v err=%v", remaining, err)
	}
	client.flush()
	remaining, _, err = logger.PendingEvents(100)
	if err != nil || len(remaining) != 0 || requests != 2 {
		t.Fatalf("final queue=%+v requests=%d err=%v", remaining, requests, err)
	}
}

func TestEventPartialAcknowledgmentsRetainMemoryFallbackItems(t *testing.T) {
	notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDirectory, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, err := logging.NewLogger(filepath.Join(notDirectory, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("payments", "first", nil, detection.Result{})
	logger.LogToolCall("payments", "second", nil, detection.Result{})

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload struct {
			Events []logging.Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"acks":[{"event_id":"` + payload.Events[0].EventID + `","status":"accepted"},{"event_id":"` + payload.Events[1].EventID + `","status":"retryable"}]}`))
			return
		}
		if len(payload.Events) != 1 {
			t.Fatalf("memory retry batch size=%d, want 1", len(payload.Events))
		}
		_, _ = w.Write([]byte(`{"ok":true,"inserted":0,"acks":[{"event_id":"` + payload.Events[0].EventID + `","status":"duplicate"}]}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", logger)
	client.flush()
	client.flush()
	if requests != 2 {
		t.Fatalf("memory fallback requests=%d, want 2", requests)
	}
}

func TestEventUploadWithoutExplicitAcknowledgmentRemainsPending(t *testing.T) {
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	logger.LogToolCall("payments", "transfer", nil, detection.Result{})
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"ok":true,"inserted":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"inserted":1,"received":1}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "test-key", logger)
	client.flush()
	pending, _, err := logger.PendingEvents(100)
	if err != nil || len(pending) != 1 {
		t.Fatalf("unacknowledged event was lost: %+v err=%v", pending, err)
	}
	client.flush()
	pending, _, err = logger.PendingEvents(100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged retry remained pending: %+v err=%v", pending, err)
	}
}
