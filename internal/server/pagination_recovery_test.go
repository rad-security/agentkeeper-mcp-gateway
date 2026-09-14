package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEveryCatalogFollowsOpaqueCursorAndRejectsLoops(t *testing.T) {
	for _, kind := range []string{"tools", "resources", "resourceTemplates", "prompts"} {
		t.Run(kind, func(t *testing.T) {
			pages := 0
			loop := false
			cursor := "opaque + / ? = " + kind
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					ID     *int64                 `json:"id"`
					Method string                 `json:"method"`
					Params map[string]interface{} `json:"params"`
				}
				_ = json.NewDecoder(r.Body).Decode(&q)
				w.Header().Set("Content-Type", "application/json")
				var result interface{}
				if q.Method == "initialize" {
					result = map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}, "prompts": map[string]interface{}{}}}
				} else if strings.HasPrefix(q.Method, "notifications/") {
					w.WriteHeader(202)
					return
				} else {
					pages++
					page := map[string]interface{}{kind: []interface{}{map[string]interface{}{"name": "item"}}}
					if q.Params["cursor"] == nil || loop {
						page["nextCursor"] = cursor
					} else if q.Params["cursor"] != cursor {
						t.Errorf("cursor changed: %v", q.Params)
					}
					result = page
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": result})
			}))
			defer b.Close()
			m := NewManager([]ServerConfig{{Name: "fixture", Transport: "http", URL: b.URL}})
			_ = m.StartAll()
			defer m.StopAll()
			s := m.Get("fixture")
			list := s.ListTools
			if kind == "resources" {
				list = s.ListResources
			}
			if kind == "resourceTemplates" {
				list = s.ListResourceTemplates
			}
			if kind == "prompts" {
				list = s.ListPrompts
			}
			got, err := list()
			if err != nil || len(got) != 2 || pages != 2 {
				t.Fatalf("got=%v pages=%d err=%v", got, pages, err)
			}
			loop = true
			if _, err := list(); err == nil || !strings.Contains(err.Error(), "repeated") {
				t.Fatalf("loop not bounded: %v", err)
			}
		})
	}
}
func TestExpiredHTTPSessionRecoversOnlyOnNextIndependentCall(t *testing.T) {
	initializations, calls := 0, 0
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		var result interface{}
		switch q.Method {
		case "initialize":
			initializations++
			w.Header().Set("Mcp-Session-Id", "session")
			result = map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}
		case "notifications/initialized":
			w.WriteHeader(202)
			return
		case "tools/call":
			calls++
			if calls == 1 {
				http.Error(w, "expired", 404)
				return
			}
			result = map[string]interface{}{"content": []interface{}{}}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	defer b.Close()
	m := NewManager([]ServerConfig{{Name: "fixture", Transport: "http", URL: b.URL}})
	_ = m.StartAll()
	defer m.StopAll()
	s := m.Get("fixture")
	if _, err := s.Call("tools/call", json.RawMessage(`{"name":"record","arguments":{}}`)); err == nil {
		t.Fatal("first failed call was silently retried")
	}
	if calls != 1 {
		t.Fatal("unsafe automatic replay", calls)
	}
	if _, err := s.Call("tools/call", json.RawMessage(`{"name":"record","arguments":{}}`)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || initializations != 2 {
		t.Fatalf("calls=%d initializations=%d", calls, initializations)
	}
}
