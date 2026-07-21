package runtimebroker

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEnterpriseCapabilitiesMatchReleaseContract(t *testing.T) {
	capabilities := EnterpriseCapabilities()
	if capabilities.SchemaVersion != 1 || capabilities.RuntimeSocketAuth.Protocol != Protocol {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}
	if capabilities.RuntimeSocketAuth.CredentialExposure != "none" ||
		capabilities.ManagedRouting.RemoveManagedFlag != "--remove-managed-routing" {
		t.Fatalf("credential or removal contract drifted: %+v", capabilities)
	}
	if capabilities.RuntimeSocketAuth.Supported != (runtime.GOOS == "linux") {
		t.Fatalf("platform support mismatch: %+v", capabilities)
	}
}

func TestParseManagedConfigRejectsIncompatibleCredentialMode(t *testing.T) {
	valid := []byte(`{"schema_version":1,"ownership_id":"agentkeeper.universal.v1","protocol":"agentkeeper-runtime-gateway-v1","credential_mode":"runtime_broker_only","runtime_socket":"/run/agentkeeper/runtime.sock"}`)
	cfg, err := ParseManagedConfig(valid)
	if err != nil || cfg.RuntimeSocket != "/run/agentkeeper/runtime.sock" {
		t.Fatalf("valid config rejected: cfg=%+v err=%v", cfg, err)
	}
	invalid := []byte(`{"schema_version":1,"ownership_id":"agentkeeper.universal.v1","protocol":"agentkeeper-runtime-gateway-v1","credential_mode":"api_key","runtime_socket":"/run/agentkeeper/runtime.sock"}`)
	if _, err := ParseManagedConfig(invalid); err == nil {
		t.Fatal("API-key credential mode must be rejected")
	}
}

func TestPostUsesAllowlistedUnixSocketEnvelope(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "ak-broker-")
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
		var request brokerRequest
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&request); err != nil {
			done <- err
			return
		}
		if request.RequestType != "gateway_api" || request.Operation != "evaluate" {
			done <- &testError{"unexpected broker request"}
			return
		}
		_, err = conn.Write([]byte(`{"status":200,"body":{"verdict":"allow"}}` + "\n"))
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var result struct {
		Verdict string `json:"verdict"`
	}
	status, err := Post(ctx, socket, "evaluate", map[string]any{"server_name": "github"}, &result)
	if err != nil || status != 200 || result.Verdict != "allow" {
		t.Fatalf("post failed: status=%d result=%+v err=%v", status, result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := Post(ctx, socket, "arbitrary", map[string]any{}, nil); err == nil {
		t.Fatal("arbitrary operations must be rejected")
	}
}

type testError struct{ message string }

func (err *testError) Error() string { return err.message }
