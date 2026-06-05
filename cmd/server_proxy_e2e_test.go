package cmd_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for gateway JSON-RPC response")
	}
	return ""
}
