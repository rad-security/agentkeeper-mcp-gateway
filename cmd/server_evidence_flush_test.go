package cmd_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestCrashableMCPHelper is an owned stdio MCP provider used by Gateway
// end-to-end tests. It answers with the request's own JSON-RPC id, lists
// `echo` and `disconnect`, and exits without replying when `disconnect` runs.
// AK_TEST_START_LOG records one line per process start; when
// AK_TEST_FAIL_AFTER_FIRST_START=1 every start after the first exits at once.
func TestCrashableMCPHelper(t *testing.T) {
	if os.Getenv("AK_TEST_CRASHABLE_MCP") != "1" {
		return
	}
	starts := 0
	if path := os.Getenv("AK_TEST_START_LOG"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			starts = strings.Count(string(data), "\n")
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(2)
		}
		fmt.Fprintf(file, "%d\n", os.Getpid())
		_ = file.Close()
	}
	if starts > 0 && os.Getenv("AK_TEST_FAIL_AFTER_FIRST_START") == "1" {
		os.Exit(3)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     *json.RawMessage `json:"id"`
			Method string           `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		var result interface{} = map[string]interface{}{}
		switch request.Method {
		case "initialize":
			result = map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}, "serverInfo": map[string]interface{}{"name": "crashable-fixture", "version": "test"}}
		case "tools/list":
			result = map[string]interface{}{"tools": []map[string]interface{}{
				{"name": "echo", "description": "Returns a fixed inert string", "inputSchema": map[string]interface{}{"type": "object"}},
				{"name": "disconnect", "description": "Terminates this fixture process", "inputSchema": map[string]interface{}{"type": "object"}},
			}}
		case "tools/call":
			if request.Params.Name == "disconnect" {
				os.Exit(0)
			}
			result = map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "FIXTURE_ECHO_OK"}}}
		}
		_ = encoder.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	os.Exit(0)
}

func crashableFixtureServer(extraEnv map[string]string) map[string]interface{} {
	env := map[string]string{"CK_E2E_BINARY": binary, "AK_TEST_CRASHABLE_MCP": "1"}
	for key, value := range extraEnv {
		env[key] = value
	}
	return map[string]interface{}{"name": "native_matrix", "command": os.Args[0], "args": []string{"-test.run=^TestCrashableMCPHelper$"}, "env": env}
}

// evidenceAPI is a fake AgentKeeper backend that records evidence uploads.
type evidenceAPI struct {
	*httptest.Server
	mu       sync.Mutex
	receipts []map[string]interface{}
	events   []map[string]interface{}
	release  chan struct{}
	// Optional per-route assignment returned by registration, and the
	// effective mode/revision each registration reported (dashboard ACK input).
	assignedMode     string
	assignedRevision int64
	registrations    []map[string]interface{}
}

func (a *evidenceAPI) assign(mode string, revision int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.assignedMode, a.assignedRevision = mode, revision
}

func (a *evidenceAPI) registrationSnapshot() []map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]interface{}(nil), a.registrations...)
}

func (a *evidenceAPI) snapshot() (receipts, events []map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]interface{}(nil), a.receipts...), append([]map[string]interface{}(nil), a.events...)
}

// newEvidenceAPI acknowledges every uploaded event and receipt after ackDelay
// (modelling a real network round trip). With hang=true evidence uploads never
// receive a response until the Gateway disconnects or the test ends.
func newEvidenceAPI(t *testing.T, ackDelay time.Duration, hang bool) *evidenceAPI {
	t.Helper()
	api := &evidenceAPI{release: make(chan struct{})}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			api.mu.Lock()
			api.registrations = append(api.registrations, body)
			mode, revision := api.assignedMode, api.assignedRevision
			api.mu.Unlock()
			if revision > 0 {
				fmt.Fprintf(w, `{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","route_assignment":{"desired_mode":%q,"desired_revision":%d}}`, mode, revision)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111"}`))
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"audit"}}`))
		case "/api/v2/mcp/evaluate", "/api/v1/mcp/evaluate":
			_, _ = w.Write([]byte(`{"verdict":"pass","decision_id":"decision-12345678","evaluation_status":"evaluated"}`))
		case "/api/v1/mcp/events", "/api/v2/mcp/receipts":
			if hang {
				select {
				case <-r.Context().Done():
				case <-api.release:
				}
				return
			}
			select {
			case <-time.After(ackDelay):
			case <-r.Context().Done():
				return
			}
			key, idKey := "events", "event_id"
			if r.URL.Path == "/api/v2/mcp/receipts" {
				key, idKey = "receipts", "receipt_id"
			}
			items, _ := body[key].([]interface{})
			acks := make([]map[string]string, 0, len(items))
			api.mu.Lock()
			for _, raw := range items {
				item, _ := raw.(map[string]interface{})
				if key == "events" {
					api.events = append(api.events, item)
				} else {
					api.receipts = append(api.receipts, item)
				}
				id, _ := item[idKey].(string)
				acks = append(acks, map[string]string{idKey: id, "status": "accepted"})
			}
			api.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "acks": acks, "inserted": len(acks)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() {
		close(api.release)
		api.Close()
	})
	return api
}

type gatewayProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	stderr *bytes.Buffer
	done   chan error
}

func startGatewayProcess(t *testing.T, home string, cfg map[string]interface{}, extraEnv ...string) *gatewayProcess {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "gateway.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return startGatewayProcessWithConfigPath(t, home, configPath, extraEnv...)
}

func startGatewayProcessWithConfigPath(t *testing.T, home, configPath string, extraEnv ...string) *gatewayProcess {
	t.Helper()
	cmd := exec.Command(binary, "server", "--no-auto-auth", "--config", configPath)
	cmd.Env = append([]string{"HOME=" + home, "XDG_CONFIG_HOME=" + home, "PATH=" + os.Getenv("PATH"), "AGENTKEEPER_COWORK_GUARD=0", "AGENTKEEPER_MACHINE_ID=machine-evidence-e2e"}, extraEnv...)
	cmd.Dir = home
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayProcess{cmd: cmd, stdin: stdin, reader: bufio.NewReader(stdout), stderr: &bytes.Buffer{}, done: make(chan error, 1)}
	cmd.Stderr = &lockedWriter{w: gw.stderr}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { gw.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-gw.done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-gw.done
		}
	})
	return gw
}

// lockedWriter lets tests read captured stderr while the process still runs.
type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (g *gatewayProcess) request(t *testing.T, id int, method string, params interface{}) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	writeRPC(t, g.stdin, string(raw))
	return readRPCResponseForIDWithin(t, g.reader, fmt.Sprint(id), 15*time.Second)
}

func (g *gatewayProcess) handshake(t *testing.T) {
	t.Helper()
	g.request(t, 1, "initialize", map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "evidence-e2e", "version": "test"}})
	writeRPC(t, g.stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	deadline := time.Now().Add(10 * time.Second)
	for id := 2; ; id++ {
		if strings.Contains(g.request(t, id, "tools/list", map[string]interface{}{}), `"native_matrix__echo"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture tools were never listed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// closeStdinAndWait models `codex exec` closing the Gateway's stdin right
// after its final tool result and returns how long the process took to exit.
func (g *gatewayProcess) closeStdinAndWait(t *testing.T, bound time.Duration) time.Duration {
	t.Helper()
	started := time.Now()
	if err := g.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-g.done:
		g.done <- err // keep Cleanup non-blocking
		if err != nil {
			t.Fatalf("gateway exited with %v; stderr=%s", err, g.stderrText())
		}
	case <-time.After(bound):
		t.Fatalf("gateway did not exit within %s after stdin EOF; stderr=%s", bound, g.stderrText())
	}
	return time.Since(started)
}

func (g *gatewayProcess) stderrText() string {
	if lw, ok := g.cmd.Stderr.(*lockedWriter); ok {
		lw.mu.Lock()
		defer lw.mu.Unlock()
	}
	return g.stderr.String()
}

func queuedFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func evidenceGatewayConfig(home, apiURL string) map[string]interface{} {
	return map[string]interface{}{
		"mode":     "audit",
		"api_key":  "ak_live_evidence_flush_fixture",
		"api_url":  apiURL,
		"log_path": filepath.Join(home, "events.jsonl"),
		"servers":  []map[string]interface{}{crashableFixtureServer(nil)},
	}
}

func TestStdinEOFUploadsFinalEvidenceBeforeExit(t *testing.T) {
	api := newEvidenceAPI(t, 300*time.Millisecond, false)
	home := t.TempDir()
	gw := startGatewayProcess(t, home, evidenceGatewayConfig(home, api.URL))
	gw.handshake(t)
	response := gw.request(t, 100, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}})
	if !strings.Contains(response, "FIXTURE_ECHO_OK") {
		t.Fatalf("final call was not proxied: %s", response)
	}
	// The client disconnects immediately, before the 5s periodic uploader runs.
	gw.closeStdinAndWait(t, 10*time.Second)

	receipts, events := api.snapshot()
	var sawReceipt, sawEvent bool
	for _, item := range receipts {
		if item["tool_name"] == "echo" && item["applied_disposition"] == "result_returned" {
			sawReceipt = true
		}
	}
	for _, item := range events {
		if item["event_type"] == "mcp.tool_call" && item["tool_name"] == "echo" {
			sawEvent = true
		}
	}
	if !sawReceipt || !sawEvent {
		t.Fatalf("final call evidence was not uploaded before exit: receipt=%v event=%v receipts=%d events=%d stderr=%s", sawReceipt, sawEvent, len(receipts), len(events), gw.stderrText())
	}
	if left := queuedFiles(t, filepath.Join(home, "receipts-v2", "queue")); len(left) != 0 {
		t.Fatalf("acknowledged receipts remained queued after exit: %v", left)
	}
	if left := queuedFiles(t, filepath.Join(home, "events-v1", "queue")); len(left) != 0 {
		t.Fatalf("acknowledged events remained queued after exit: %v", left)
	}
}

func TestStdinEOFFinalEvidenceFlushIsBoundedWhenBackendHangs(t *testing.T) {
	api := newEvidenceAPI(t, 0, true)
	home := t.TempDir()
	gw := startGatewayProcess(t, home, evidenceGatewayConfig(home, api.URL))
	gw.handshake(t)
	response := gw.request(t, 100, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}})
	if !strings.Contains(response, "FIXTURE_ECHO_OK") {
		t.Fatalf("final call was not proxied: %s", response)
	}
	elapsed := gw.closeStdinAndWait(t, 10*time.Second)
	if elapsed > 5*time.Second {
		t.Fatalf("exit after stdin EOF took %s with an unresponsive backend; want a bounded final flush", elapsed)
	}
	// Unacknowledged evidence must stay durable for the next start.
	if left := queuedFiles(t, filepath.Join(home, "receipts-v2", "queue")); len(left) == 0 {
		t.Fatal("unacknowledged receipt was lost instead of remaining queued")
	}
	if left := queuedFiles(t, filepath.Join(home, "events-v1", "queue")); len(left) == 0 {
		t.Fatal("unacknowledged events were lost instead of remaining queued")
	}
}

// The final flush must fit inside the 5s signal bound (which exits 1) even
// while owned backends are also being stopped.
func TestTerminationSignalFinalFlushStaysInsideSignalBound(t *testing.T) {
	api := newEvidenceAPI(t, 0, true)
	home := t.TempDir()
	gw := startGatewayProcess(t, home, evidenceGatewayConfig(home, api.URL))
	gw.handshake(t)
	response := gw.request(t, 100, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}})
	if !strings.Contains(response, "FIXTURE_ECHO_OK") {
		t.Fatalf("final call was not proxied: %s", response)
	}
	started := time.Now()
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-gw.done:
		gw.done <- err
		if err != nil {
			t.Fatalf("SIGTERM exit was not clean (forced-exit bound hit?): %v stderr=%s", err, gw.stderrText())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("gateway did not exit after SIGTERM")
	}
	if elapsed := time.Since(started); elapsed > 4500*time.Millisecond {
		t.Fatalf("SIGTERM shutdown took %s", elapsed)
	}
	if left := queuedFiles(t, filepath.Join(home, "receipts-v2", "queue")); len(left) == 0 {
		t.Fatal("unacknowledged receipt was lost on SIGTERM")
	}
}
