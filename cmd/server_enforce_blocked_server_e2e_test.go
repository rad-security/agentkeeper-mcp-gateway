package cmd_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestContentMCPHelper is an owned stdio MCP provider that serves a tool, a
// resource and a prompt. AK_TEST_START_LOG records one line per process start
// and AK_TEST_REQUEST_LOG records every request line it receives.
func TestContentMCPHelper(t *testing.T) {
	if os.Getenv("AK_TEST_CONTENT_MCP") != "1" {
		return
	}
	label := os.Getenv("AK_TEST_CONTENT_LABEL")
	appendLine := func(path, line string) {
		if path == "" {
			return
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(2)
		}
		fmt.Fprintln(file, line)
		_ = file.Close()
	}
	appendLine(os.Getenv("AK_TEST_START_LOG"), fmt.Sprint(os.Getpid()))
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		appendLine(os.Getenv("AK_TEST_REQUEST_LOG"), scanner.Text())
		var request struct {
			ID     *json.RawMessage `json:"id"`
			Method string           `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		var result interface{} = map[string]interface{}{}
		switch request.Method {
		case "initialize":
			result = map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{
				"tools": map[string]interface{}{}, "resources": map[string]interface{}{}, "prompts": map[string]interface{}{},
			}, "serverInfo": map[string]interface{}{"name": "content-fixture", "version": "test"}}
		case "tools/list":
			result = map[string]interface{}{"tools": []map[string]interface{}{
				{"name": "echo", "description": "Returns a fixed inert string", "inputSchema": map[string]interface{}{"type": "object"}},
			}}
		case "tools/call":
			result = map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "CONTENT_TOOL_" + label}}}
		case "resources/list":
			result = map[string]interface{}{"resources": []map[string]interface{}{{"uri": "fixture://" + label + "/notes", "name": "notes"}}}
		case "resources/read":
			result = map[string]interface{}{"contents": []map[string]interface{}{{"uri": "fixture://" + label + "/notes", "text": "CONTENT_RESOURCE_" + label}}}
		case "prompts/list":
			result = map[string]interface{}{"prompts": []map[string]interface{}{{"name": "greet", "description": "A fixed prompt"}}}
		case "prompts/get":
			result = map[string]interface{}{"messages": []map[string]interface{}{{"role": "user", "content": map[string]interface{}{"type": "text", "text": "CONTENT_PROMPT_" + label}}}}
		}
		_ = encoder.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	os.Exit(0)
}

func contentFixtureServer(name, dir string) map[string]interface{} {
	return map[string]interface{}{"name": name, "command": os.Args[0], "args": []string{"-test.run=^TestContentMCPHelper$"}, "env": map[string]string{
		// CK_E2E_BINARY stops the helper's TestMain from rebuilding the Gateway.
		"CK_E2E_BINARY": binary, "AK_TEST_CONTENT_MCP": "1", "AK_TEST_CONTENT_LABEL": name,
		"AK_TEST_START_LOG":   filepath.Join(dir, name+".starts"),
		"AK_TEST_REQUEST_LOG": filepath.Join(dir, name+".requests"),
	}}
}

// policyAPI is a fake AgentKeeper backend that serves a fixed policy and route
// assignment and records what the Gateway asks it to evaluate.
type policyAPI struct {
	*httptest.Server
	mu          sync.Mutex
	evaluations []map[string]json.RawMessage
}

func (a *policyAPI) evaluationSnapshot() []map[string]json.RawMessage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]json.RawMessage(nil), a.evaluations...)
}

func newPolicyAPI(t *testing.T, mode string, blockedServers []string) *policyAPI {
	t.Helper()
	api := &policyAPI{}
	policy, _ := json.Marshal(map[string]interface{}{"mode": mode, "blocked_servers": blockedServers, "detection": map[string]string{"threat": "warn", "sensitive_data": "warn"}})
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			if mode == "enforce" {
				_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","route_assignment":{"desired_mode":"enforce","desired_revision":1}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111"}`))
		case "/api/v1/mcp/sync":
			fmt.Fprintf(w, `{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":%s}`, policy)
		case "/api/v2/mcp/evaluate", "/api/v1/mcp/evaluate":
			api.mu.Lock()
			api.evaluations = append(api.evaluations, body)
			api.mu.Unlock()
			_, _ = w.Write([]byte(`{"verdict":"pass","decision_id":"decision-12345678","evaluation_status":"evaluated"}`))
		case "/api/v1/mcp/events", "/api/v2/mcp/receipts":
			_, _ = w.Write([]byte(`{"ok":true,"acks":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	return api
}

func startContentGateway(t *testing.T, api *policyAPI) (*gatewayProcess, string) {
	t.Helper()
	home := t.TempDir()
	cfg := map[string]interface{}{
		"mode": "audit", "api_key": "ak_live_blocked_server_fixture", "api_url": api.URL,
		"log_path": filepath.Join(home, "events.jsonl"),
		"servers":  []map[string]interface{}{contentFixtureServer("allowed", home), contentFixtureServer("blocked", home)},
	}
	gw := startGatewayProcess(t, home, cfg)
	gw.request(t, 1, "initialize", map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "blocked-server-e2e", "version": "test"}})
	writeRPC(t, gw.stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	deadline := time.Now().Add(10 * time.Second)
	for id := 2; ; id++ {
		if strings.Contains(gw.request(t, id, "tools/list", map[string]interface{}{}), `"allowed__echo"`) {
			return gw, home
		}
		if time.Now().After(deadline) {
			t.Fatalf("allowed fixture tools were never listed; stderr=%s", gw.stderrText())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func startCount(t *testing.T, home, name string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, name+".starts"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

// A server blocked by organization policy must not run on the workstation at
// all in Enforce, and none of its tools, resources or prompts may be reachable.
func TestEnforceBlockedServerIsNeverStartedOrServed(t *testing.T) {
	api := newPolicyAPI(t, "enforce", []string{"blocked"})
	gw, home := startContentGateway(t, api)
	if stderr := gw.stderrText(); !strings.Contains(stderr, "starting in enforce mode") {
		t.Fatalf("route did not start in Enforce:\n%s", stderr)
	}

	tools := gw.request(t, 100, "tools/list", map[string]interface{}{})
	resources := gw.request(t, 101, "resources/list", map[string]interface{}{})
	prompts := gw.request(t, 102, "prompts/list", map[string]interface{}{})
	for label, listing := range map[string]string{"tools/list": tools, "resources/list": resources, "prompts/list": prompts} {
		if strings.Contains(listing, "blocked") {
			t.Fatalf("%s exposes the blocked server: %s", label, listing)
		}
	}
	if !strings.Contains(resources, "fixture://allowed/notes") || !strings.Contains(prompts, "allowed__greet") {
		t.Fatalf("allowed server content is missing: %s %s", resources, prompts)
	}

	// Address the blocked server directly, as a client that remembered the
	// names from an earlier Observe session would.
	var listed struct {
		Result struct {
			Resources []struct {
				URI string `json:"uri"`
			} `json:"resources"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resources), &listed); err != nil || len(listed.Result.Resources) != 1 {
		t.Fatalf("unexpected resources/list: %s", resources)
	}
	blockedURI := "agentkeeper://resource/" + base64.RawURLEncoding.EncodeToString([]byte("blocked")) + "/" + base64.RawURLEncoding.EncodeToString([]byte("fixture://blocked/notes"))
	for label, response := range map[string]string{
		"tools/call":     gw.request(t, 110, "tools/call", map[string]interface{}{"name": "blocked__echo", "arguments": map[string]interface{}{}}),
		"resources/read": gw.request(t, 111, "resources/read", map[string]interface{}{"uri": blockedURI}),
		"prompts/get":    gw.request(t, 112, "prompts/get", map[string]interface{}{"name": "blocked__greet"}),
	} {
		if strings.Contains(response, "CONTENT_") {
			t.Fatalf("%s returned content from the blocked server: %s", label, response)
		}
		if !strings.Contains(response, "Blocked by AgentKeeper") {
			t.Fatalf("%s to a blocked server was not refused as a policy block: %s", label, response)
		}
	}
	if read := gw.request(t, 120, "resources/read", map[string]interface{}{"uri": listed.Result.Resources[0].URI}); !strings.Contains(read, "CONTENT_RESOURCE_allowed") {
		t.Fatalf("allowed resource was not served: %s", read)
	}
	gw.closeStdinAndWait(t, 10*time.Second)

	if starts := startCount(t, home, "blocked"); starts != 0 {
		t.Fatalf("blocked server process was started %d time(s)", starts)
	}
	if starts := startCount(t, home, "allowed"); starts != 1 {
		t.Fatalf("allowed server started %d time(s), want 1", starts)
	}
}

// Observe must keep serving a server the policy would block, so the dashboard
// can show what Enforce would change before anything is taken away.
func TestObserveStillServesServerThePolicyWouldBlock(t *testing.T) {
	api := newPolicyAPI(t, "audit", []string{"blocked"})
	gw, home := startContentGateway(t, api)
	deadline := time.Now().Add(10 * time.Second)
	for id := 200; ; id++ {
		if strings.Contains(gw.request(t, id, "tools/list", map[string]interface{}{}), `"blocked__echo"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Observe hid the would-block server; stderr=%s", gw.stderrText())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if response := gw.request(t, 300, "tools/call", map[string]interface{}{"name": "blocked__echo", "arguments": map[string]interface{}{}}); !strings.Contains(response, "CONTENT_TOOL_blocked") {
		t.Fatalf("Observe did not forward the would-block call: %s", response)
	}
	if resources := gw.request(t, 301, "resources/list", map[string]interface{}{}); !strings.Contains(resources, "fixture://blocked/notes") {
		t.Fatalf("Observe hid the would-block server's resources: %s", resources)
	}
	gw.closeStdinAndWait(t, 10*time.Second)
	if starts := startCount(t, home, "blocked"); starts != 1 {
		t.Fatalf("would-block server started %d time(s) in Observe, want 1", starts)
	}
}

// MCP lets a client omit `arguments`. The connected evaluation must still see
// an argument object, and the upstream must not be sent a null in its place.
func TestToolCallWithoutArgumentsIsEvaluatedAndForwardedFaithfully(t *testing.T) {
	api := newPolicyAPI(t, "audit", nil)
	gw, home := startContentGateway(t, api)
	if response := gw.request(t, 400, "tools/call", map[string]interface{}{"name": "allowed__echo"}); !strings.Contains(response, "CONTENT_TOOL_allowed") {
		t.Fatalf("call without arguments was not forwarded: %s", response)
	}
	gw.closeStdinAndWait(t, 10*time.Second)

	evaluations := api.evaluationSnapshot()
	if len(evaluations) != 1 {
		t.Fatalf("expected one connected evaluation, got %d", len(evaluations))
	}
	if params := strings.TrimSpace(string(evaluations[0]["params"])); params != "{}" {
		t.Fatalf("connected evaluation received params=%s, want an empty object", params)
	}
	requests, err := os.ReadFile(filepath.Join(home, "allowed.requests"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(requests), "\n") {
		if strings.Contains(line, `"tools/call"`) && strings.Contains(line, `"arguments":null`) {
			t.Fatalf("upstream was sent null arguments: %s", line)
		}
	}
}
