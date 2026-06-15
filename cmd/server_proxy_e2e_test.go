package cmd_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type capturedAPIRequest struct {
	path string
	body map[string]any
}

func TestE2E33_ServerProxiesConfiguredMCPToolCall(t *testing.T) {
	home := t.TempDir()
	configPath := writeGatewayConfig(t, home, `{
		"mode": "audit",
		"servers": [{
			"name": "atlas",
			"command": "/bin/sh",
			"args": ["-c", "while IFS= read -r line; do case \"$line\" in *\\\"method\\\":\\\"initialize\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fake-atlas\",\"version\":\"test\"}}}' ;; *\\\"method\\\":\\\"tools/list\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"list_accounts\",\"description\":\"List accounts\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]}}' ;; *\\\"method\\\":\\\"tools/call\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"atlas-ok\"}]}}' ;; esac; done"]
		}]
	}`)

	cmd := exec.Command(binary, "--config", configPath, "server")
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_COWORK_GUARD=0",
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	}()

	reader := bufio.NewReader(stdout)
	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":100,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"test"}}}`)
	initResp := readRPCLine(t, reader)
	if !strings.Contains(initResp, `"id":100`) || !strings.Contains(initResp, `"agentkeeper-mcp-gateway"`) {
		t.Fatalf("unexpected initialize response: %s stderr=%s", initResp, stderr.String())
	}

	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":101,"method":"tools/list","params":{}}`)
	listResp := readRPCLine(t, reader)
	if !strings.Contains(listResp, `"atlas__list_accounts"`) {
		t.Fatalf("gateway did not expose namespaced backend tool: %s stderr=%s", listResp, stderr.String())
	}

	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"atlas__list_accounts","arguments":{}}}`)
	callResp := readRPCLine(t, reader)
	if !strings.Contains(callResp, `"id":102`) || !strings.Contains(callResp, "atlas-ok") {
		t.Fatalf("gateway did not proxy backend tool call: %s stderr=%s", callResp, stderr.String())
	}

	logPath := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("gateway did not create local event log at %s: %v", logPath, err)
	}
}

func TestE2E33b_ServerExposesSlowEnterpriseToolList(t *testing.T) {
	home := t.TempDir()
	backend := filepath.Join(home, "slow-enterprise-mcp.sh")
	if err := os.WriteFile(backend, []byte(`#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *\"method\":\"initialize\"*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"slow-enterprise","version":"test"}}}' ;;
    *\"method\":\"tools/list\"*) sleep 15; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search_accounts","description":"Search enterprise accounts","inputSchema":{"type":"object","properties":{}}}]}}' ;;
  esac
done
`), 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := writeGatewayConfig(t, home, `{
		"mode": "audit",
		"servers": [{
			"name": "ontra-enterprise",
			"command": "`+backend+`"
		}]
	}`)

	cmd := exec.Command(binary, "--config", configPath, "server")
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_COWORK_GUARD=0",
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	}()

	reader := bufio.NewReader(stdout)
	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":110,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"test"}}}`)
	_ = readRPCLine(t, reader)

	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":111,"method":"tools/list","params":{}}`)
	listResp := readRPCLineWithin(t, reader, 22*time.Second)
	if !strings.Contains(listResp, `"ontra-enterprise__search_accounts"`) {
		t.Fatalf("gateway dropped slow enterprise backend tool: %s stderr=%s", listResp, stderr.String())
	}
}

func TestE2E34_ServerReportsProxiedToolCallToAgentKeeperAPI(t *testing.T) {
	requests := make(chan capturedAPIRequest, 10)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		requests <- capturedAPIRequest{path: r.URL.Path, body: body}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw_e2e","policy":{"mode":"audit"}}`))
		case "/api/v1/mcp/evaluate":
			_, _ = w.Write([]byte(`{"verdict":"pass"}`))
		case "/api/v1/mcp/events":
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	home := t.TempDir()
	configPath := writeGatewayConfig(t, home, `{
		"mode": "audit",
		"api_key": "ak_live_test_e2e",
		"api_url": "`+api.URL+`",
		"servers": [{
			"name": "atlas",
			"command": "/bin/sh",
			"args": ["-c", "while IFS= read -r line; do case \"$line\" in *\\\"method\\\":\\\"initialize\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fake-atlas\",\"version\":\"test\"}}}' ;; *\\\"method\\\":\\\"tools/list\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"list_accounts\",\"description\":\"List accounts\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]}}' ;; *\\\"method\\\":\\\"tools/call\\\"*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"atlas-ok\"}]}}' ;; esac; done"]
		}]
	}`)

	cmd := exec.Command(binary, "--config", configPath, "server")
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"AGENTKEEPER_COWORK_GUARD=0",
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	}()

	reader := bufio.NewReader(stdout)
	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":200,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"test"}}}`)
	_ = readRPCLine(t, reader)
	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":201,"method":"tools/list","params":{}}`)
	_ = readRPCLine(t, reader)
	writeRPC(t, stdin, `{"jsonrpc":"2.0","id":202,"method":"tools/call","params":{"name":"atlas__list_accounts","arguments":{"account_id":"acct_test"}}}`)
	callResp := readRPCLine(t, reader)
	if !strings.Contains(callResp, "atlas-ok") {
		t.Fatalf("gateway did not proxy backend tool call: %s stderr=%s", callResp, stderr.String())
	}

	evaluate := waitForAPIPath(t, requests, "/api/v1/mcp/evaluate", 6*time.Second)
	if evaluate["server_name"] != "atlas" || evaluate["tool_name"] != "list_accounts" || evaluate["source"] != "agentkeeper-mcp-gateway" {
		t.Fatalf("unexpected evaluate payload: %#v", evaluate)
	}
	if evaluate["gateway_id"] != "gw_e2e" {
		t.Fatalf("evaluate did not include synced gateway id: %#v", evaluate)
	}

	events := waitForAPIPath(t, requests, "/api/v1/mcp/events", 7*time.Second)
	rawEvents, ok := events["events"].([]any)
	if !ok || len(rawEvents) == 0 {
		t.Fatalf("events upload missing events array: %#v", events)
	}
	var sawToolCall bool
	for _, raw := range rawEvents {
		event, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if event["event_type"] == "mcp.tool_call" && event["server_name"] == "atlas" && event["tool_name"] == "list_accounts" {
			sawToolCall = true
			break
		}
	}
	if !sawToolCall {
		t.Fatalf("events upload did not contain routed atlas/list_accounts tool call: %#v", rawEvents)
	}
}

func writeRPC(t *testing.T, stdin interface {
	Write([]byte) (int, error)
}, payload string) {
	t.Helper()
	if !json.Valid([]byte(payload)) {
		t.Fatalf("invalid test JSON: %s", payload)
	}
	if _, err := stdin.Write([]byte(payload + "\n")); err != nil {
		t.Fatal(err)
	}
}

func readRPCLine(t *testing.T, reader *bufio.Reader) string {
	return readRPCLineWithin(t, reader, 5*time.Second)
}

func readRPCLineWithin(t *testing.T, reader *bufio.Reader, timeout time.Duration) string {
	t.Helper()
	ch := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			errCh <- err
			return
		}
		ch <- line
	}()
	select {
	case line := <-ch:
		return line
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(timeout):
		t.Fatal("timed out waiting for gateway JSON-RPC response")
	}
	return ""
}

func waitForAPIPath(t *testing.T, requests <-chan capturedAPIRequest, path string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case req := <-requests:
			if req.path == path {
				return req.body
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", path)
		}
	}
}
