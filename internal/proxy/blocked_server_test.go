package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// An upstream skipped at attach because policy blocks it must come up once it
// is no longer blocked (the block was removed, or the route returned to
// Observe) without waiting for the client to restart the Gateway.
func TestUpstreamSkippedByPolicyStartsOnceTheBlockIsLifted(t *testing.T) {
	t.Setenv("HOME", scratchHome(t))
	t.Setenv("AGENTKEEPER_MACHINE_ID", "synthetic-blocked-server")
	dir := t.TempDir()
	startLog := filepath.Join(dir, "starts")
	script := filepath.Join(dir, "backend.sh")
	body := `#!/bin/sh
echo started >> "` + startLog + `"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/sync" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"enforce","blocked_servers":["fixture"]}}`))
	}))
	defer api.Close()
	tc := telemetry.NewClient(api.URL, "synthetic-key", nil)
	if !tc.Start() {
		t.Fatal("fixture policy was not synced")
	}
	defer tc.Stop()

	mgr := server.NewManager([]server.ServerConfig{{Name: "fixture", Command: script}})
	defer mgr.StopAll()
	p := NewProxy(Config{EnforceMode: true, GatewayVersion: "test"}, mgr, tc)
	defer p.Close()

	id := json.RawMessage(`1`)
	if _, err := p.handleInitialize(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-11-25"}`)}); err != nil {
		t.Fatal(err)
	}
	<-p.startToolRefresh()
	if mgr.Get("fixture") != nil {
		t.Fatal("blocked upstream was started in Enforce")
	}
	if _, err := os.Stat(startLog); !os.IsNotExist(err) {
		t.Fatalf("blocked upstream process ran: %v", err)
	}

	p.SetEnforceMode(false)
	<-p.startToolRefresh()
	if mgr.Get("fixture") == nil {
		t.Fatal("upstream stayed down after its block was lifted")
	}
	tools, _ := p.cachedNamespacedTools()
	listed, _ := json.Marshal(tools)
	if !strings.Contains(string(listed), "fixture__echo") {
		t.Fatalf("lifted upstream's tools were not listed: %s", listed)
	}
}

func TestServerForNamespacedResourceURI(t *testing.T) {
	uri := namespacedResourceURI("team server", "fixture://notes/1")
	if name, ok := serverForNamespacedResourceURI(uri); !ok || name != "team server" {
		t.Fatalf("got %q ok=%v", name, ok)
	}
	for _, other := range []string{"", "fixture://notes/1", "agentkeeper://resource/", "agentkeeper://resource/%%%/abc", "agentkeeper://resource/onlyserver"} {
		if name, ok := serverForNamespacedResourceURI(other); ok {
			t.Fatalf("%q decoded to %q", other, name)
		}
	}
}

// blockedFixture starts a proxy on an enforcing route whose policy blocks the
// one configured upstream.
func blockedFixture(t *testing.T) (*Proxy, *server.Manager, string) {
	t.Helper()
	t.Setenv("HOME", scratchHome(t))
	t.Setenv("AGENTKEEPER_MACHINE_ID", "synthetic-blocked-server")
	dir := t.TempDir()
	startLog := filepath.Join(dir, "starts")
	script := filepath.Join(dir, "backend.sh")
	body := `#!/bin/sh
echo started >> "` + startLog + `"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{},"prompts":{}}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"prompts/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"prompts":[{"name":"greet"}]}}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/sync" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"enforce","blocked_servers":["fixture"]}}`))
	}))
	t.Cleanup(api.Close)
	tc := telemetry.NewClient(api.URL, "synthetic-key", nil)
	if !tc.Start() {
		t.Fatal("fixture policy was not synced")
	}
	t.Cleanup(tc.Stop)
	mgr := server.NewManager([]server.ServerConfig{{Name: "fixture", Command: script}})
	t.Cleanup(mgr.StopAll)
	p := NewProxy(Config{EnforceMode: true, GatewayVersion: "test"}, mgr, tc)
	t.Cleanup(p.Close)
	id := json.RawMessage(`1`)
	if _, err := p.handleInitialize(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-11-25"}`)}); err != nil {
		t.Fatal(err)
	}
	<-p.startToolRefresh()
	return p, mgr, startLog
}

// The Cowork guard restarts upstreams after it routes a new source. No start
// path may launch a server the policy blocks.
func TestNoStartPathLaunchesABlockedUpstream(t *testing.T) {
	_, mgr, startLog := blockedFixture(t)
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureStarted("fixture"); err == nil {
		t.Fatal("EnsureStarted launched a blocked upstream")
	}
	if mgr.Get("fixture") != nil {
		t.Fatal("blocked upstream is running")
	}
	if _, err := os.Stat(startLog); !os.IsNotExist(err) {
		t.Fatalf("blocked upstream process ran: %v", err)
	}
}

// Listing prompts or resources is enough to bring back an upstream whose
// block was lifted; the client need not ask for tools first.
func TestLiftedBlockTakesEffectOnPromptsList(t *testing.T) {
	p, mgr, _ := blockedFixture(t)
	p.SetEnforceMode(false)
	id := json.RawMessage(`2`)
	response, err := p.handlePromptsList(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Method: "prompts/list"})
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Get("fixture") == nil {
		t.Fatal("upstream stayed down after its block was lifted")
	}
	if !strings.Contains(string(response.Result), "fixture__greet") {
		t.Fatalf("lifted upstream's prompts were not listed: %s", response.Result)
	}
}

// An upstream that is already running when it becomes blocked keeps running
// until the Gateway restarts, but nothing it sends may reach the client.
func TestNotificationsFromABlockedUpstreamAreDropped(t *testing.T) {
	p, _, _ := blockedFixture(t)
	var out bytes.Buffer
	p.outputMu.Lock()
	p.output = &out
	p.outputMu.Unlock()
	p.forwardBackendNotification("fixture", "notifications/message", json.RawMessage(`{"level":"info","data":"from a blocked server"}`))
	if out.Len() != 0 {
		t.Fatalf("blocked upstream's notification reached the client: %s", out.String())
	}
	p.SetEnforceMode(false)
	p.forwardBackendNotification("fixture", "notifications/message", json.RawMessage(`{"level":"info","data":"observe"}`))
	if !strings.Contains(out.String(), "observe") {
		t.Fatalf("Observe dropped an upstream notification: %s", out.String())
	}
}

// scratchHome is a HOME the Gateway may still be writing its tool cache into
// while the test tears down; t.TempDir fails the test if the directory is not
// empty at that moment.
func scratchHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("", "gateway-proxy-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	return home
}
