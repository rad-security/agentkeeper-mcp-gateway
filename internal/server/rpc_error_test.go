package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestUpstreamRPCErrorPreservesCodeMessageAndData(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32042,"message":"synthetic quota exhausted","data":{"retryAfter":12,"detail":["one",null]}}}`)
	assertError := func(t *testing.T, err error) {
		t.Helper()
		var rpc *RPCError
		if !errors.As(err, &rpc) {
			t.Fatalf("error lost type: %T %v", err, err)
		}
		if rpc.Code != -32042 || rpc.Message != "synthetic quota exhausted" || string(rpc.Data) != `{"retryAfter":12,"detail":["one",null]}` {
			t.Fatalf("error lost fields: %+v", rpc)
		}
	}
	t.Run("http JSON and streamable SSE decode", func(t *testing.T) { _, err := parseJSONRPCResult(raw, 7); assertError(t, err) })
	t.Run("streamable SSE error is not skipped", func(t *testing.T) {
		_, err := readSSEResult(strings.NewReader("data: "+string(raw)+"\n\n"), 7, nil)
		assertError(t, err)
	})
	t.Run("stdio and legacy SSE dispatch", func(t *testing.T) {
		ch := make(chan rpcResponse, 1)
		s := &Server{pending: map[int64]chan rpcResponse{7: ch}}
		s.dispatchRPCPayload(raw)
		assertError(t, (<-ch).err)
	})
	t.Run("successful result remains unchanged", func(t *testing.T) {
		r, err := parseJSONRPCResult([]byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[]}}`), 7)
		if err != nil || string(r) != `{"content":[]}` {
			t.Fatalf("result=%s err=%v", r, err)
		}
	})
	t.Run("null data preserved", func(t *testing.T) {
		_, err := parseJSONRPCResult([]byte(`{"id":7,"error":{"code":-32041,"message":"error","data":null}}`), 7)
		var rpc *RPCError
		if !errors.As(err, &rpc) || string(rpc.Data) != "null" {
			t.Fatalf("null data changed: %v", err)
		}
		_, marshalErr := json.Marshal(rpc)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
	})
}
