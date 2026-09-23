package cmd_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func TestServerTerminationRecordsDispatchedCancellationBeforeExit(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			entered := make(chan struct{}, 1)
			cancelled := make(chan struct{}, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     *int64 `json:"id"`
					Method string `json:"method"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					return
				}
				switch req.Method {
				case "initialize":
					json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}})
				case "tools/list":
					json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": map[string]interface{}{"tools": []map[string]interface{}{{"name": "slow", "inputSchema": map[string]interface{}{"type": "object"}}}}})
				case "tools/call":
					entered <- struct{}{}
					<-r.Context().Done()
					cancelled <- struct{}{}
				default:
					w.WriteHeader(http.StatusAccepted)
				}
			}))
			defer backend.Close()
			home := t.TempDir()
			cfg := filepath.Join(home, "gateway.json")
			raw, _ := json.Marshal(map[string]interface{}{"mode": "audit", "log_path": filepath.Join(home, "events.jsonl"), "servers": []map[string]interface{}{{"name": "fixture", "transport": "http", "url": backend.URL}}})
			if err := os.WriteFile(cfg, raw, 0600); err != nil {
				t.Fatal(err)
			}
			proc := exec.Command(binary, "server", "--no-auto-auth", "--config", cfg)
			proc.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home, "PATH=" + os.Getenv("PATH"), "AGENTKEEPER_COWORK_GUARD=0"}
			proc.Dir = home
			input, err := proc.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := proc.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := proc.Start(); err != nil {
				t.Fatal(err)
			}
			defer proc.Process.Kill()
			messages := make(chan map[string]interface{}, 20)
			go func() {
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					var m map[string]interface{}
					if json.Unmarshal(scanner.Bytes(), &m) == nil {
						messages <- m
					}
				}
			}()
			send := func(id int, method string, params interface{}) {
				raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
				fmt.Fprintln(input, string(raw))
			}
			waitID := func(id int) {
				t.Helper()
				deadline := time.After(5 * time.Second)
				for {
					select {
					case m := <-messages:
						if m["id"] == float64(id) {
							return
						}
					case <-deadline:
						t.Fatalf("no response to %d", id)
					}
				}
			}
			send(1, "initialize", map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "shutdown-test", "version": "1"}})
			waitID(1)
			send(2, "tools/list", map[string]interface{}{})
			waitID(2)
			send(3, "tools/call", map[string]interface{}{"name": "fixture__slow", "arguments": map[string]interface{}{}})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream never dispatched")
			}
			if err := proc.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- proc.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("shutdown exceeded bound")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("upstream request was not cancelled")
			}
			files, err := filepath.Glob(filepath.Join(home, "receipts-v2", "queue", "*.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("receipts=%v err=%v", files, err)
			}
			raw, err = os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			var item receipt.Envelope
			if err := json.Unmarshal(raw, &item); err != nil {
				t.Fatal(err)
			}
			if item.AppliedDisposition != "client_cancelled" || !item.Dispatched || item.ResultReceived || item.ResultReturned || item.ResponseWithheld {
				t.Fatalf("false terminal outcome: %+v", item)
			}
		})
	}
}

// This process is an owned MCP provider which deliberately ignores stdin EOF.
func TestStubbornMCPHelper(t *testing.T) {
	if os.Getenv("AK_TEST_STUBBORN_MCP") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("AK_TEST_PID_FILE"), []byte(fmt.Sprint(os.Getpid())), 0600); err != nil {
		os.Exit(2)
	}
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var request struct {
			ID     *json.RawMessage `json:"id"`
			Method string           `json:"method"`
		}
		if json.Unmarshal(scan.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		result := json.RawMessage(`{}`)
		if request.Method == "initialize" {
			result = json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}`)
		}
		if request.Method == "tools/list" {
			result = json.RawMessage(`{"tools":[]}`)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestTerminationBoundsCleanupAcrossStubbornBackends(t *testing.T) {
	home := t.TempDir()
	var servers []map[string]interface{}
	var pids []string
	for i := 0; i < 3; i++ {
		pid := filepath.Join(home, fmt.Sprintf("provider-%d.pid", i))
		pids = append(pids, pid)
		servers = append(servers, map[string]interface{}{"name": fmt.Sprintf("stubborn%d", i), "command": os.Args[0], "args": []string{"-test.run=^TestStubbornMCPHelper$"}, "env": map[string]string{"CK_E2E_BINARY": binary, "AK_TEST_STUBBORN_MCP": "1", "AK_TEST_PID_FILE": pid}})
	}
	raw, _ := json.Marshal(map[string]interface{}{"mode": "audit", "servers": servers, "log_path": filepath.Join(home, "events.jsonl")})
	cfg := filepath.Join(home, "gateway.json")
	os.WriteFile(cfg, raw, 0600)
	proc := exec.Command(binary, "server", "--no-auto-auth", "--config", cfg)
	proc.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home, "PATH=" + os.Getenv("PATH"), "AGENTKEEPER_COWORK_GUARD=0"}
	proc.Dir = home
	input, err := proc.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer proc.Process.Kill()
	childrenStopped := false
	defer func() {
		if childrenStopped {
			return
		}
		for _, file := range pids {
			if data, err := os.ReadFile(file); err == nil {
				var pid int
				fmt.Sscan(string(data), &pid)
				if pid > 0 {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	}()
	fmt.Fprintln(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"shutdown-test","version":"1"}}}`)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ready := true
		for _, pid := range pids {
			if _, err := os.Stat(pid); err != nil {
				ready = false
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("providers did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	if err := proc.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5500 * time.Millisecond):
		t.Fatal("termination exceeded complete lifecycle bound")
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("backend cleanup accumulated grace periods: %s", elapsed)
	}
	for _, file := range pids {
		data, _ := os.ReadFile(file)
		var pid int
		fmt.Sscan(string(data), &pid)
		if syscall.Kill(pid, 0) == nil {
			t.Fatalf("owned provider %d remains running", pid)
		}
	}
	childrenStopped = true
}
