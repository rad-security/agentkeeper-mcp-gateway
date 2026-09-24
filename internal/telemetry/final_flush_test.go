package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func finalFlushFixture(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body map[string]interface{})) (*Client, *logging.Logger, *receipt.Store) {
	t.Helper()
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-final-flush")
	root := t.TempDir()
	logger, err := logging.NewLogger(filepath.Join(root, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	store, err := receipt.NewStore(filepath.Join(root, "receipts-v2"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111"}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"audit"}}`))
		default:
			handler(w, r, body)
		}
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, "test-key", logger)
	client.SetReceiptStore(store)
	return client, logger, store
}

func enqueueFinalCallEvidence(t *testing.T, logger *logging.Logger, store *receipt.Store) {
	t.Helper()
	logger.LogToolCall("native_matrix", "echo", nil, detection.Result{})
	if _, err := store.Enqueue(receipt.Input{
		CallID: "call-final-flush", AttemptID: "attempt-final-flush", Phase: "terminal",
		ServerName: "native_matrix", ToolName: "echo", PolicyDecision: "pass",
		EvaluationStatus: "evaluated", RequiredDisposition: "forward",
		AppliedDisposition: "result_returned", EffectiveMode: "observe",
		Dispatched: true, ResultReceived: true, ResultReturned: true, Terminal: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func ackAll(w http.ResponseWriter, body map[string]interface{}, key, idKey string) {
	items, _ := body[key].([]interface{})
	acks := make([]map[string]string, 0, len(items))
	for _, raw := range items {
		item, _ := raw.(map[string]interface{})
		id, _ := item[idKey].(string)
		acks = append(acks, map[string]string{idKey: id, "status": "accepted"})
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "acks": acks})
}

func TestStopWaitsForFinalEvidenceUpload(t *testing.T) {
	var uploads atomic.Int32
	client, logger, store := finalFlushFixture(t, func(w http.ResponseWriter, r *http.Request, body map[string]interface{}) {
		time.Sleep(200 * time.Millisecond) // a real network round trip
		switch r.URL.Path {
		case "/api/v1/mcp/events":
			uploads.Add(1)
			ackAll(w, body, "events", "event_id")
		case "/api/v2/mcp/receipts":
			uploads.Add(1)
			ackAll(w, body, "receipts", "receipt_id")
		default:
			http.NotFound(w, r)
		}
	})
	client.Start()
	enqueueFinalCallEvidence(t, logger, store)
	client.Stop()
	client.Stop() // idempotent

	if uploads.Load() != 2 {
		t.Fatalf("final flush uploads=%d, want events and receipts uploaded before Stop returned", uploads.Load())
	}
	if pending, _, err := logger.PendingEvents(100); err != nil || len(pending) != 0 {
		t.Fatalf("events still queued after Stop: %d err=%v", len(pending), err)
	}
	if queued, err := store.Peek(100); err != nil || len(queued) != 0 {
		t.Fatalf("receipts still queued after Stop: %d err=%v", len(queued), err)
	}
}

func TestStopWithinBoundsHungUploadAndKeepsEvidenceQueued(t *testing.T) {
	release := make(chan struct{})
	client, logger, store := finalFlushFixture(t, func(w http.ResponseWriter, r *http.Request, _ map[string]interface{}) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	client.Start()
	enqueueFinalCallEvidence(t, logger, store)
	started := time.Now()
	client.StopWithin(300 * time.Millisecond)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("StopWithin took %s with a hung backend; want it bounded by its budget", elapsed)
	}
	if pending, _, err := logger.PendingEvents(100); err != nil || len(pending) == 0 {
		t.Fatalf("unacknowledged events were dropped: %d err=%v", len(pending), err)
	}
	if queued, err := store.Peek(100); err != nil || len(queued) != 1 {
		t.Fatalf("unacknowledged receipt was dropped: %d err=%v", len(queued), err)
	}
}

func TestStopWithoutStartDoesNotBlock(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "test-key", nil)
	done := make(chan struct{})
	go func() {
		client.Stop()
		client.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on a client that never started")
	}
}
