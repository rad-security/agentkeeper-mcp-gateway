package telemetry

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
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
	result := client.Evaluate("filesystem", "read_file", map[string]any{"path": "/tmp/test"})
	if result == nil || result.Verdict != "block" || result.PatternName != "test" {
		t.Fatalf("runtime broker result not applied: %+v", result)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type telemetryTestError struct{ message string }

func (err *telemetryTestError) Error() string { return err.message }
