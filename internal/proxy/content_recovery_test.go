package proxy

import (
	"bytes"
	"encoding/json"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/server"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestMalformedResourcesEmitExactlyOneTruthfulTerminal(t *testing.T) {
	variants := []string{`{"contents":[{"uri":"qa://record/1","text":null}]}`, `{"contents":[{"uri":"qa://record/1","blob":null}]}`, `{}`, `{"contents":null}`, `{"contents":[null]}`, `{"contents":[{"uri":4,"text":"x"}]}`, `{"contents":[{"uri":"qa://record/1"}]}`, `{"contents":[{"uri":"qa://record/1","blob":"!invalid"}]}`, `{"contents":[{"uri":"qa://record/1","text":"x","blob":"AQ=="}]}`}
	for _, templated := range []bool{false, true} {
		for index, raw := range variants {
			t.Run(map[bool]string{false: "listed", true: "template"}[templated]+string(rune('A'+index)), func(t *testing.T) {
				b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var q struct {
						ID     *int64 `json:"id"`
						Method string `json:"method"`
					}
					_ = json.NewDecoder(r.Body).Decode(&q)
					w.Header().Set("Content-Type", "application/json")
					result := json.RawMessage(raw)
					if q.Method == "initialize" {
						result = json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{"resources":{}}}`)
					}
					if q.Method == "notifications/initialized" {
						w.WriteHeader(202)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": result})
				}))
				defer b.Close()
				root := t.TempDir()
				store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
				if err != nil {
					t.Fatal(err)
				}
				logger, err := logging.NewLogger(filepath.Join(root, "events.jsonl"), false)
				if err != nil {
					t.Fatal(err)
				}
				defer logger.Close()
				m := server.NewManager([]server.ServerConfig{{Name: "fixture", Transport: "http", URL: b.URL}})
				_ = m.StartAll()
				defer m.StopAll()
				p := NewProxy(Config{ReceiptStore: store, Logger: logger}, m, nil)
				defer p.Close()
				uri := "qa://record/1"
				if templated {
					p.resourceTemplates = []resourceTemplateRoute{{ServerName: "fixture", Template: "qa://record/{id}", Matcher: compileResourceTemplate("qa://record/{id}")}}
				} else {
					uri = namespacedResourceURI("fixture", uri)
					p.resourceMap[uri] = resourceRoute{ServerName: "fixture", OriginalURI: "qa://record/1"}
				}
				params, _ := json.Marshal(map[string]string{"uri": uri})
				id := json.RawMessage(`1`)
				result, err := p.handleResourcesRead(JSONRPCMessage{JSONRPC: "2.0", ID: &id, Params: params})
				if err != nil || result.Error == nil || result.Error.Code != -32004 {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				queued, err := store.Peek(100)
				if err != nil || len(queued) != 1 {
					t.Fatalf("receipts=%v err=%v", queued, err)
				}
				r := queued[0]
				if r.AppliedDisposition != "response_invalid" || r.EvaluationStatus != "invalid_response" || r.RequiredDisposition != "forward" || r.PolicyDecision != "warn" || !r.Dispatched || !r.ResultReceived || r.ResultReturned || r.ResponseWithheld || !r.Terminal || r.FailureReason != "invalid_resource_response" {
					t.Fatalf("untruthful terminal: %+v", r)
				}
				events, _, err := logger.PendingEvents(100)
				if err != nil || len(events) != 1 {
					t.Fatalf("events=%v err=%v", events, err)
				}
			})
		}
	}
}
func TestContentCancellationDoesNotStallFollowingTool(t *testing.T) {
	for _, method := range []string{"resources/read", "prompts/get"} {
		t.Run(method, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			cancelled := make(chan struct{}, 1)
			completed := make(chan struct{}, 1)
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					ID     *int64 `json:"id"`
					Method string `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&q)
				w.Header().Set("Content-Type", "application/json")
				result := json.RawMessage(`{}`)
				switch q.Method {
				case "initialize":
					result = json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{"resources":{},"prompts":{},"tools":{}}}`)
				case "notifications/initialized":
					w.WriteHeader(202)
					return
				case "notifications/cancelled":
					cancelled <- struct{}{}
					w.WriteHeader(202)
					return
				case "tools/call":
					result = json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`)
					completed <- struct{}{}
				default:
					if q.Method == method {
						entered <- struct{}{}
						<-r.Context().Done()
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": result})
			}))
			defer b.Close()
			m := server.NewManager([]server.ServerConfig{{Name: "fixture", Transport: "http", URL: b.URL}})
			_ = m.StartAll()
			defer m.StopAll()
			store, err := receipt.NewStore(t.TempDir(), "test")
			if err != nil {
				t.Fatal(err)
			}
			p := NewProxy(Config{ReceiptStore: store}, m, nil)
			p.resourceMap["qa://record/1"] = resourceRoute{ServerName: "fixture", OriginalURI: "qa://record/1"}
			p.promptMap["fixture__slow"] = "fixture"
			p.toolMap["fixture__fast"] = "fixture"
			input, writer := io.Pipe()
			var output bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- p.run(input, &output) }()
			first, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": map[string]interface{}{"uri": "qa://record/1", "name": "fixture__slow"}})
			_, _ = writer.Write(append(first, '\n'))
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not dispatch")
			}
			_, _ = io.WriteString(writer, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n")
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation was not forwarded")
			}
			_, _ = io.WriteString(writer, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"fixture__fast\",\"arguments\":{}}}\n")
			select {
			case <-completed:
			case <-time.After(2 * time.Second):
				t.Fatal("following tool stalled")
			}
			_ = writer.Close()
			<-done
			p.Close()
			receipts, err := store.Peek(100)
			if err != nil {
				t.Fatal(err)
			}
			cancelTerminals := 0
			for _, r := range receipts {
				if r.ToolName == method && r.AppliedDisposition == "client_cancelled" {
					cancelTerminals++
					if !r.Dispatched || r.ResultReceived || r.ResultReturned {
						t.Fatalf("wrong cancellation receipt: %+v", r)
					}
				}
			}
			if cancelTerminals != 1 {
				t.Fatalf("terminal count=%d", cancelTerminals)
			}
		})
	}
}
