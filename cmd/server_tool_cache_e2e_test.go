package cmd_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An upstream that answers at once, or after four seconds when a marker file
// exists: a server started with npx on a cold cache.
const slowStartBackend = `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *\"method\":\"initialize\"*)
      if [ -f "$AGENTKEEPER_TEST_SLOW" ]; then sleep 4; fi
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"notes","version":"test"}}}' ;;
    *\"method\":\"tools/list\"*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"Search notes.","inputSchema":{"type":"object","properties":{}}}]}}' ;;
  esac
done
`

// The tools a server listed in the last session are offered at once in the
// next one, while the server is still starting. A clean exit used to erase
// them, so a client that does not re-list after tools/list_changed saw no
// tools from a slow server.
func TestE2ECachedToolsSurviveACleanExitAndCoverASlowStart(t *testing.T) {
	home := t.TempDir()
	slow := filepath.Join(home, "slow-start")
	backend := filepath.Join(home, "notes-mcp.sh")
	if err := os.WriteFile(backend, []byte(slowStartBackend), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := writeGatewayConfig(t, home, `{"mode": "audit", "servers": [{"name": "notes", "command": "`+backend+`"}]}`)

	firstList := func(retryUntilListed bool) (string, time.Duration) {
		cmd := exec.Command(binary, "--config", configPath, "server")
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "AGENTKEEPER_COWORK_GUARD=0", "AGENTKEEPER_TEST_SLOW=" + slow}
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
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}()
		reader := bufio.NewReader(stdout)
		writeRPC(t, stdin, `{"jsonrpc":"2.0","id":130,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"test"}}}`)
		_ = readRPCResponseForIDWithin(t, reader, "130", 10*time.Second)
		writeRPC(t, stdin, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
		started := time.Now()
		writeRPC(t, stdin, `{"jsonrpc":"2.0","id":131,"method":"tools/list","params":{}}`)
		list := readRPCResponseForIDWithin(t, reader, "131", 10*time.Second)
		elapsed := time.Since(started)
		for attempt := 0; retryUntilListed && !strings.Contains(list, `"notes__search"`) && attempt < 20; attempt++ {
			time.Sleep(250 * time.Millisecond)
			writeRPC(t, stdin, `{"jsonrpc":"2.0","id":132,"method":"tools/list","params":{}}`)
			list = readRPCResponseForIDWithin(t, reader, "132", 10*time.Second)
		}
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatalf("gateway exit failed: %v stderr=%s", err, stderr.String())
		}
		return list, elapsed
	}

	if list, _ := firstList(true); !strings.Contains(list, `"notes__search"`) {
		t.Fatalf("first session never listed the tool: %s", list)
	}
	cache, err := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "tool-cache.json"))
	if err != nil || !strings.Contains(string(cache), `"search"`) {
		t.Fatalf("the tool cache did not survive a clean exit: %s (err=%v)", cache, err)
	}

	if err := os.WriteFile(slow, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	list, elapsed := firstList(false)
	if !strings.Contains(list, `"notes__search"`) {
		t.Fatalf("first tools/list of a session with a slow server omitted its cached tool (answered in %v): %s", elapsed, list)
	}
	if elapsed > 3500*time.Millisecond {
		t.Fatalf("first tools/list waited %v for the slow server", elapsed)
	}
}
