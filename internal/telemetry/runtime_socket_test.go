package telemetry

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func TestRuntimeClientEvaluatesWithoutAPIKey(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "ak-telemetry-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	socket := filepath.Join(tempDir, "runtime.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var request struct {
			RequestType string         `json:"request_type"`
			Operation   string         `json:"operation"`
			Payload     map[string]any `json:"payload"`
		}
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&request); err != nil {
			done <- err
			return
		}
		if request.RequestType != "gateway_api" || request.Operation != "evaluate" || request.Payload["tool_name"] != "read_file" {
			done <- &telemetryTestError{"unexpected runtime broker request"}
			return
		}
		_, err = conn.Write([]byte(`{"status":200,"body":{"verdict":"block","pattern_name":"test"}}` + "\n"))
		done <- err
	}()

	client := NewRuntimeClient(socket, nil)
	result := client.Evaluate("filesystem", "read_file", map[string]any{"path": "/tmp/test"}, "call-test-1", "attempt-test-1")
	if result == nil || result.Verdict != "block" || result.PatternName != "test" {
		t.Fatalf("runtime broker result not applied: %+v", result)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeClientRegistersAndFlushesSignedReceipts(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "managed-runtime-receipt-test")
	tempDir, err := os.MkdirTemp("/tmp", "ak-runtime-receipt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	socket := filepath.Join(tempDir, "runtime.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	store, err := receipt.NewStore(filepath.Join(tempDir, "receipts"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := store.Enqueue(receipt.Input{
		CallID: "call-managed-1", AttemptID: "attempt-managed-1", Phase: "terminal",
		ServerName: "filesystem", ToolName: "read_file", PolicyDecision: "pass",
		EvaluationStatus: "evaluated", RequiredDisposition: "forward",
		AppliedDisposition: "result_returned", EffectiveMode: "observe",
		Dispatched: true, ResultReceived: true, ResultReturned: true, Terminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		for index := 0; index < 2; index++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				done <- acceptErr
				return
			}
			var request struct {
				RequestType string         `json:"request_type"`
				Operation   string         `json:"operation"`
				Payload     map[string]any `json:"payload"`
			}
			decodeErr := json.NewDecoder(bufio.NewReader(conn)).Decode(&request)
			if decodeErr != nil {
				_ = conn.Close()
				done <- decodeErr
				return
			}
			if index == 0 {
				if request.RequestType != "gateway_api" || request.Operation != "register" {
					_ = conn.Close()
					done <- &telemetryTestError{"expected v2 registration through runtime broker"}
					return
				}
				_, decodeErr = conn.Write([]byte(`{"status":200,"body":{"ok":true,"gateway_id":"9b3a12b8-86a1-4a51-9e42-99b48ef51c9b","route_assignment":{"desired_mode":"observe","desired_revision":1}}}` + "\n"))
			} else {
				if request.Operation != "receipts" {
					_ = conn.Close()
					done <- &telemetryTestError{"expected receipt upload through runtime broker"}
					return
				}
				receipts, ok := request.Payload["receipts"].([]any)
				if !ok || len(receipts) != 1 {
					_ = conn.Close()
					done <- &telemetryTestError{"expected one signed receipt"}
					return
				}
				_, decodeErr = conn.Write([]byte(`{"status":200,"body":{"ok":true,"acks":[{"receipt_id":"` + envelope.ReceiptID + `","status":"accepted"}]}}` + "\n"))
			}
			_ = conn.Close()
			if decodeErr != nil {
				done <- decodeErr
				return
			}
		}
		done <- nil
	}()

	client := NewRuntimeClient(socket, nil)
	client.SetReceiptStore(store)
	client.SetRouteContext("claude-code", "config-hash", "route-revision")
	if !client.syncV2() {
		t.Fatal("managed runtime v2 registration failed")
	}
	client.flushReceipts()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	remaining, err := store.Peek(10)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("accepted managed receipt was not resolved: remaining=%d err=%v", len(remaining), err)
	}
}

type telemetryTestError struct{ message string }

func (err *telemetryTestError) Error() string { return err.message }
