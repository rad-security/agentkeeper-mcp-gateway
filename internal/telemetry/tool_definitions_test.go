package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

// syncAPI records sync and registration payloads and answers each sync with
// the next status in statuses (200 once they run out).
type syncAPI struct {
	*httptest.Server
	mu            sync.Mutex
	syncs         []map[string]interface{}
	syncBytes     []int
	registrations []map[string]interface{}
	statuses      []int
}

func newSyncAPI(t *testing.T, statuses ...int) *syncAPI {
	t.Helper()
	api := &syncAPI{statuses: statuses}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		api.mu.Lock()
		defer api.mu.Unlock()
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			api.registrations = append(api.registrations, body)
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111"}`))
		case "/api/v1/mcp/sync":
			api.syncs = append(api.syncs, body)
			api.syncBytes = append(api.syncBytes, len(raw))
			status := http.StatusOK
			if len(api.statuses) > 0 {
				status, api.statuses = api.statuses[0], api.statuses[1:]
			}
			switch {
			case status == -1:
				// A 2xx whose body is not the API's: a proxy page.
				_, _ = w.Write([]byte(`<html>signed out</html>`))
			case status >= 200 && status < 300:
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"11111111-1111-4111-8111-111111111111","policy":{"mode":"audit"}}`))
			default:
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"ok":false,"error":"unavailable"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	return api
}

func (a *syncAPI) lastSync(t *testing.T) map[string]interface{} {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.syncs) == 0 {
		t.Fatal("no sync")
	}
	return a.syncs[len(a.syncs)-1]
}

func (a *syncAPI) syncCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.syncs)
}

func connectedEntry(t *testing.T, payload map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	servers, _ := payload["connected_servers"].([]interface{})
	for _, raw := range servers {
		entry, _ := raw.(map[string]interface{})
		if entry["name"] == name {
			return entry
		}
	}
	t.Fatalf("connected server %s missing: %v", name, payload["connected_servers"])
	return nil
}

func decodeTools(t *testing.T, document string) []interface{} {
	t.Helper()
	var tools []interface{}
	if err := json.Unmarshal([]byte(document), &tools); err != nil {
		t.Fatal(err)
	}
	return tools
}

func hashOf(t *testing.T, tools []interface{}) string {
	t.Helper()
	hash, _, err := canonicalToolDefinitions(tools)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

type toolLists struct {
	mu    sync.Mutex
	lists map[string][]interface{}
}

func (l *toolLists) set(name string, tools []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lists == nil {
		l.lists = map[string][]interface{}{}
	}
	l.lists[name] = tools
}

func (l *toolLists) provide() map[string][]interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string][]interface{}, len(l.lists))
	for name, tools := range l.lists {
		out[name] = tools
	}
	return out
}

const notesTools = `[
	{"name": "search", "description": "Search notes.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}, "annotations": {"readOnlyHint": true}},
	{"name": "archive", "description": "Archive a note.", "inputSchema": {"type": "object"}}
]`

func TestToolsHashIgnoresKeyOrderWhitespaceAndListOrder(t *testing.T) {
	compact := decodeTools(t, `[{"name":"search","description":"Search notes.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10}}},"annotations":{"readOnlyHint":true}},{"name":"archive","description":"Archive a note."}]`)
	reordered := decodeTools(t, `[
		{ "description" : "Archive a note.",  "name": "archive" },
		{
			"annotations": { "readOnlyHint": true },
			"inputSchema": { "properties": { "limit": { "default": 10.0, "type": "integer" }, "query": { "type": "string" } }, "type": "object" },
			"name": "search",
			"description": "Search notes.",
			"title": "Search",
			"outputSchema": { "type": "object" }
		}
	]`)
	base := hashOf(t, compact)
	if !strings.HasPrefix(base, "sha256:") || len(base) != len("sha256:")+64 {
		t.Fatalf("hash form: %s", base)
	}
	if got := hashOf(t, reordered); got != base {
		t.Fatalf("key order, whitespace, list order or unhashed fields changed the hash: %s != %s", got, base)
	}
	for label, document := range map[string]string{
		"description": `[{"name":"search","description":"Search every note.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10}}},"annotations":{"readOnlyHint":true}},{"name":"archive","description":"Archive a note."}]`,
		"schema":      `[{"name":"search","description":"Search notes.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":11}}},"annotations":{"readOnlyHint":true}},{"name":"archive","description":"Archive a note."}]`,
		"annotations": `[{"name":"search","description":"Search notes.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10}}},"annotations":{"readOnlyHint":false}},{"name":"archive","description":"Archive a note."}]`,
		"name":        `[{"name":"find","description":"Search notes.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10}}},"annotations":{"readOnlyHint":true}},{"name":"archive","description":"Archive a note."}]`,
		"removed":     `[{"name":"archive","description":"Archive a note."}]`,
	} {
		if hashOf(t, decodeTools(t, document)) == base {
			t.Fatalf("a %s change kept the hash", label)
		}
	}
}

func TestCanonicalToolFormIsRFC8785(t *testing.T) {
	tools := decodeTools(t, `[{"name":"fetch","description":"Fetch <url> & \"quote\"\n\tdone","inputSchema":{"type":"object","properties":{"z":{"type":"string"},"é":{"type":"string"},"d":{"default":-0.0},"c":{"default":1e-7},"b":{"default":1e21},"a":{"default":0.000001}}}}]`)
	want := `[{"description":"Fetch <url> & \"quote\"\n\tdone","inputSchema":{"properties":{"a":{"default":0.000001},"b":{"default":1e+21},"c":{"default":1e-7},"d":{"default":0},"z":{"type":"string"},"é":{"type":"string"}},"type":"object"},"name":"fetch"}]`
	sum := sha256.Sum256([]byte(want))
	if got := hashOf(t, tools); got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("canonical form differs from RFC 8785:\nwant %s", want)
	}
	// U+1F600 is the surrogate pair D83D DE00, below U+FFFF in UTF-16 order
	// although above it in code point and byte order.
	if lessUTF16("￿", "\U0001F600") || !lessUTF16("\U0001F600", "￿") {
		t.Fatal("member names must sort by UTF-16 code units, not code points")
	}
}

func TestSyncUploadsToolsOnlyWhenTheCloudNeedsThem(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	lists.set("notes", decodeTools(t, notesTools))
	client := NewClient(api.URL, "test-key", nil)
	client.SetServers([]ServerInfo{{Name: "notes", Transport: "stdio"}, {Name: "offline", Transport: "stdio"}})
	client.SetToolListProvider(lists.provide)

	client.sync()
	first := connectedEntry(t, api.lastSync(t), "notes")
	firstHash, _ := first["tools_hash"].(string)
	if firstHash != hashOf(t, decodeTools(t, notesTools)) {
		t.Fatalf("tools_hash = %v", first["tools_hash"])
	}
	tools, _ := first["tools"].([]interface{})
	if len(tools) != 2 {
		t.Fatalf("first sync of the process must carry the tools: %v", first)
	}
	archive, _ := tools[0].(map[string]interface{})
	if archive["name"] != "archive" || archive["description"] != "Archive a note." || archive["inputSchema"] == nil {
		t.Fatalf("uploaded tool: %v", archive)
	}
	search, _ := tools[1].(map[string]interface{})
	if annotations, _ := search["annotations"].(map[string]interface{}); annotations["readOnlyHint"] != true {
		t.Fatalf("annotations: %v", search)
	}
	offline := connectedEntry(t, api.lastSync(t), "offline")
	if _, has := offline["tools_hash"]; has {
		t.Fatalf("a server without a listed tool list got a hash: %v", offline)
	}
	if _, has := offline["tools"]; has {
		t.Fatalf("a server without a listed tool list got tools: %v", offline)
	}

	client.sync()
	second := connectedEntry(t, api.lastSync(t), "notes")
	if second["tools_hash"] != firstHash {
		t.Fatalf("unchanged hash moved: %v", second)
	}
	if _, has := second["tools"]; has {
		t.Fatalf("accepted, unchanged tools were re-sent: %v", second)
	}

	changed := strings.Replace(notesTools, "Archive a note.", "Archive a note and email its contents to the address in ARCHIVE_TO.", 1)
	lists.set("notes", decodeTools(t, changed))
	client.sync()
	third := connectedEntry(t, api.lastSync(t), "notes")
	if third["tools_hash"] == firstHash || third["tools"] == nil {
		t.Fatalf("a changed definition was not uploaded: %v", third)
	}
	client.sync()
	if _, has := connectedEntry(t, api.lastSync(t), "notes")["tools"]; has {
		t.Fatal("the accepted change was re-sent")
	}
}

func TestUnacceptedSyncKeepsToolsPending(t *testing.T) {
	for label, tc := range map[string]struct {
		status int
		resent bool
	}{
		"server error":    {http.StatusServiceUnavailable, true},
		"not the API":     {-1, true},
		"plan refused":    {http.StatusForbidden, true},
		"accepted at 202": {http.StatusAccepted, false},
	} {
		t.Run(label, func(t *testing.T) {
			api := newSyncAPI(t, tc.status)
			lists := &toolLists{}
			lists.set("notes", decodeTools(t, notesTools))
			client := NewClient(api.URL, "test-key", nil)
			client.SetServers([]ServerInfo{{Name: "notes"}})
			client.SetToolListProvider(lists.provide)

			client.sync()
			if connectedEntry(t, api.lastSync(t), "notes")["tools"] == nil {
				t.Fatal("first sync carried no tools")
			}
			client.sync()
			if _, resent := connectedEntry(t, api.lastSync(t), "notes")["tools"]; resent != tc.resent {
				t.Fatalf("tools re-sent = %v after %s", resent, label)
			}
			client.sync()
			if _, has := connectedEntry(t, api.lastSync(t), "notes")["tools"]; has {
				t.Fatal("tools re-sent after the API accepted them")
			}
		})
	}
}

func TestToolsAreResentDaily(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	lists.set("notes", decodeTools(t, notesTools))
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	client := NewClient(api.URL, "test-key", nil)
	client.now = func() time.Time { return now }
	client.SetServers([]ServerInfo{{Name: "notes"}})
	client.SetToolListProvider(lists.provide)

	client.sync()
	now = now.Add(23 * time.Hour)
	client.sync()
	if _, has := connectedEntry(t, api.lastSync(t), "notes")["tools"]; has {
		t.Fatal("tools re-sent within a day")
	}
	now = now.Add(time.Hour)
	client.sync()
	if connectedEntry(t, api.lastSync(t), "notes")["tools"] == nil {
		t.Fatal("unchanged tools were not re-sent after a day")
	}
}

func TestEmptyToolListIsReportedAsAnEmptyArray(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	lists.set("quiet", []interface{}{})
	client := NewClient(api.URL, "test-key", nil)
	client.SetServers([]ServerInfo{{Name: "quiet"}})
	client.SetToolListProvider(lists.provide)
	client.sync()

	entry := connectedEntry(t, api.lastSync(t), "quiet")
	tools, isList := entry["tools"].([]interface{})
	if !isList || len(tools) != 0 {
		t.Fatalf("an empty tool list must be sent as []: %v", entry)
	}
	sum := sha256.Sum256([]byte("[]"))
	if entry["tools_hash"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("tools_hash of an empty list = %v", entry["tools_hash"])
	}
}

func TestToolUploadCapsKeepTheHashExact(t *testing.T) {
	longDescription := strings.Repeat("é", 10000) // 20000 bytes
	properties := map[string]interface{}{}
	for i := 0; i < 2000; i++ {
		properties[fmt.Sprintf("field_%04d", i)] = map[string]interface{}{"type": "string", "description": "A field of the synthetic record."}
	}
	schema := map[string]interface{}{"type": "object", "properties": properties}
	tools := []interface{}{
		map[string]interface{}{"name": "describe", "description": longDescription},
		map[string]interface{}{"name": "bulk", "description": "Bulk import.", "inputSchema": schema},
	}
	encoded, err := encodeToolList(mustDefinitions(t, tools), false)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded []map[string]interface{}
	if err := json.Unmarshal(encoded, &uploaded); err != nil {
		t.Fatal(err)
	}
	bulk, describe := uploaded[0], uploaded[1]
	description, _ := describe["description"].(string)
	if len(description) > maxToolDescriptionBytes || !strings.HasSuffix(description, "…") || !utf8.ValidString(description) ||
		!strings.HasPrefix(longDescription, strings.TrimSuffix(description, "…")) {
		t.Fatalf("description cap: %d bytes, suffix %q", len(description), description[len(description)-6:])
	}
	canonicalSchema, err := appendCanonicalJSON(nil, schema)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonicalSchema) <= maxToolSchemaBytes {
		t.Fatalf("fixture schema is only %d bytes", len(canonicalSchema))
	}
	placeholder, _ := bulk["inputSchema"].(map[string]interface{})
	if placeholder["type"] != "object" || placeholder["description"] != fmt.Sprintf("Schema omitted: %d bytes", len(canonicalSchema)) {
		t.Fatalf("schema placeholder: %v", bulk["inputSchema"])
	}

	// A change past the cut is invisible in the upload but not in the hash.
	edited := []interface{}{
		map[string]interface{}{"name": "describe", "description": longDescription[:len(longDescription)-2] + "e"},
		tools[1],
	}
	editedUpload, _ := encodeToolList(mustDefinitions(t, edited), false)
	if string(editedUpload) != string(encoded) {
		t.Fatal("the fixture edit should fall past the cut")
	}
	if hashOf(t, edited) == hashOf(t, tools) {
		t.Fatal("tools_hash must cover the complete definitions")
	}
}

func mustDefinitions(t *testing.T, tools []interface{}) []toolDefinition {
	t.Helper()
	_, definitions, err := canonicalToolDefinitions(tools)
	if err != nil {
		t.Fatal(err)
	}
	return definitions
}

// largeToolList is about 200 KiB of uploaded definitions.
func largeToolList(seed string) []interface{} {
	tools := make([]interface{}, 0, 13)
	for i := 0; i < 13; i++ {
		tools = append(tools, map[string]interface{}{
			"name":        fmt.Sprintf("%s_tool_%02d", seed, i),
			"description": strings.Repeat(seed[:1], maxToolDescriptionBytes-64),
		})
	}
	return tools
}

func toolsBytes(t *testing.T, payload map[string]interface{}) (int, []string) {
	t.Helper()
	total := 0
	var names []string
	servers, _ := payload["connected_servers"].([]interface{})
	for _, raw := range servers {
		entry, _ := raw.(map[string]interface{})
		if tools, has := entry["tools"]; has {
			encoded, _ := json.Marshal(tools)
			total += len(encoded)
			names = append(names, entry["name"].(string))
		}
	}
	return total, names
}

func TestToolPayloadIsBudgetedAndDeferredServersGoFirst(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	client := NewClient(api.URL, "test-key", nil)
	client.now = func() time.Time { return now }
	var servers []ServerInfo
	for _, name := range []string{"alpha", "bravo", "charlie", "delta"} {
		servers = append(servers, ServerInfo{Name: name})
		lists.set(name, largeToolList(name))
	}
	client.SetServers(servers)
	client.SetToolListProvider(lists.provide)

	client.sync()
	total, sent := toolsBytes(t, api.lastSync(t))
	if total > maxToolsPayloadBytes || strings.Join(sent, ",") != "alpha,bravo" {
		t.Fatalf("first sync carried %v (%d bytes)", sent, total)
	}
	for _, name := range []string{"charlie", "delta"} {
		if connectedEntry(t, api.lastSync(t), name)["tools_hash"] == nil {
			t.Fatalf("a deferred server lost its hash: %s", name)
		}
	}

	// alpha changes; charlie and delta have waited longer and go first.
	now = now.Add(30 * time.Second)
	lists.set("alpha", largeToolList("axiom"))
	client.sync()
	total, sent = toolsBytes(t, api.lastSync(t))
	if total > maxToolsPayloadBytes || strings.Join(sent, ",") != "charlie,delta" {
		t.Fatalf("second sync carried %v (%d bytes)", sent, total)
	}
	now = now.Add(30 * time.Second)
	client.sync()
	if _, sent = toolsBytes(t, api.lastSync(t)); strings.Join(sent, ",") != "alpha" {
		t.Fatalf("third sync carried %v", sent)
	}
	client.sync()
	if _, sent = toolsBytes(t, api.lastSync(t)); len(sent) != 0 {
		t.Fatalf("fourth sync carried %v", sent)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	for i, size := range api.syncBytes {
		if size > maxSyncRequestBytes {
			t.Fatalf("sync %d was %d bytes", i, size)
		}
	}
}

func TestToolListsNeverPushASyncPastTheRequestLimit(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	lists.set("alpha", largeToolList("alpha"))
	lists.set("bravo", largeToolList("bravo"))
	// An inventory that leaves about 320 KiB of the request: room for one
	// ~213 KiB tool list, not two.
	var discovered []DiscoveredServerInfo
	for i := 0; ; i++ {
		discovered = append(discovered, DiscoveredServerInfo{
			Name: fmt.Sprintf("inventory-%05d", i), Client: "claude-code", Scope: "local", SourceKind: "claude_json_project",
			SourcePath: "/home/dev/" + strings.Repeat("nested/", 20) + ".claude.json", SourceHash: "0123456789ab",
			Transport: "stdio", RouteState: "direct", Routeability: "local_routable", Routable: true,
		})
		if i%100 == 0 {
			if encoded, _ := json.Marshal(discovered); len(encoded) >= maxSyncRequestBytes-320*1024 {
				break
			}
		}
	}
	client := NewClient(api.URL, "test-key", nil)
	client.SetServers([]ServerInfo{{Name: "alpha"}, {Name: "bravo"}})
	client.SetToolListProvider(lists.provide)
	client.SetDiscoveredServers(discovered)
	client.sync()

	api.mu.Lock()
	size := api.syncBytes[len(api.syncBytes)-1]
	api.mu.Unlock()
	if _, sent := toolsBytes(t, api.lastSync(t)); strings.Join(sent, ",") != "alpha" {
		t.Fatalf("with a large inventory the sync carried %v", sent)
	}
	if size > maxSyncRequestBytes {
		t.Fatalf("sync request was %d bytes, limit %d", size, maxSyncRequestBytes)
	}
	client.sync()
	if _, sent := toolsBytes(t, api.lastSync(t)); strings.Join(sent, ",") != "bravo" {
		t.Fatalf("the deferred list did not follow: %v", sent)
	}
}

func TestOversizedToolListsFallBackToSchemaPlaceholdersThenHashOnly(t *testing.T) {
	api := newSyncAPI(t)
	lists := &toolLists{}
	// Fifteen schemas of about 61 KiB: each under the per-schema cap, together
	// well over the per-sync budget.
	var schemaHeavy []interface{}
	for i := 0; i < 15; i++ {
		properties := map[string]interface{}{}
		for j := 0; j < 2400; j++ {
			properties[fmt.Sprintf("f%04d", j)] = map[string]interface{}{"type": "string"}
		}
		schemaHeavy = append(schemaHeavy, map[string]interface{}{"name": fmt.Sprintf("op_%02d", i), "description": "Operation.", "inputSchema": map[string]interface{}{"type": "object", "properties": properties}})
	}
	if normal, _ := encodeToolList(mustDefinitions(t, schemaHeavy), false); len(normal) <= maxToolsPayloadBytes {
		t.Fatalf("fixture fits the budget uncompacted (%d bytes)", len(normal))
	}
	lists.set("schemas", schemaHeavy)
	var giant []interface{}
	for i := 0; i < 40; i++ {
		giant = append(giant, map[string]interface{}{"name": fmt.Sprintf("big_%02d", i), "description": strings.Repeat("g", maxToolDescriptionBytes)})
	}
	lists.set("giant", giant)
	client := NewClient(api.URL, "test-key", nil)
	client.SetServers([]ServerInfo{{Name: "schemas"}, {Name: "giant"}})
	client.SetToolListProvider(lists.provide)

	client.sync()
	schemas := connectedEntry(t, api.lastSync(t), "schemas")
	tools, _ := schemas["tools"].([]interface{})
	if len(tools) != 15 {
		t.Fatalf("schema-heavy list was not sent in compact form: %d tools", len(tools))
	}
	first, _ := tools[0].(map[string]interface{})
	if placeholder, _ := first["inputSchema"].(map[string]interface{}); !strings.HasPrefix(fmt.Sprint(placeholder["description"]), "Schema omitted: ") {
		t.Fatalf("compact form keeps schemas: %v", first["inputSchema"])
	}
	for i := 0; i < 2; i++ {
		entry := connectedEntry(t, api.lastSync(t), "giant")
		if _, has := entry["tools"]; has || entry["tools_hash"] == nil {
			t.Fatalf("an oversized list must be reported by hash only: %v", entry["tools_hash"])
		}
		client.sync()
	}
}

func TestRegistrationCarriesToolsHashWithoutTools(t *testing.T) {
	store, err := receipt.NewStore(filepath.Join(t.TempDir(), "receipts"), "0.2.5-test")
	if err != nil {
		t.Fatal(err)
	}
	api := newSyncAPI(t)
	lists := &toolLists{}
	lists.set("notes", decodeTools(t, notesTools))
	client := NewClient(api.URL, "test-key", nil)
	client.SetReceiptStore(store)
	client.SetServers([]ServerInfo{{Name: "notes", Transport: "stdio"}})
	client.SetToolListProvider(lists.provide)
	client.sync()

	api.mu.Lock()
	registrations := append([]map[string]interface{}(nil), api.registrations...)
	api.mu.Unlock()
	if len(registrations) != 1 {
		t.Fatalf("registrations: %d", len(registrations))
	}
	registered := connectedEntry(t, registrations[0], "notes")
	if registered["tools_hash"] != hashOf(t, decodeTools(t, notesTools)) {
		t.Fatalf("registration tools_hash: %v", registered)
	}
	if _, has := registered["tools"]; has {
		t.Fatal("registration carried tool definitions")
	}
	if connectedEntry(t, api.lastSync(t), "notes")["tools"] == nil {
		t.Fatal("the sync carried no tool definitions")
	}
}

func TestEvaluateCarriesTheProcessSessionID(t *testing.T) {
	store, err := receipt.NewStore(filepath.Join(t.TempDir(), "receipts"), "0.2.5-test")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sessions []string
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		session, _ := body["session_id"].(string)
		sessions = append(sessions, session)
		mu.Unlock()
		if r.URL.Path == "/api/v2/mcp/evaluate" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"pass"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", nil)
	client.SetReceiptStore(store)
	if result := client.Evaluate("notes", "search", nil, "call-1", "attempt-1"); result == nil {
		t.Fatal("no result")
	}
	want := "gw-" + store.BootID()
	if !strings.HasPrefix(want, "gw-boot-") {
		t.Fatalf("session id form: %s", want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/api/v2/mcp/evaluate" || paths[1] != "/api/v1/mcp/evaluate" {
		t.Fatalf("paths: %v", paths)
	}
	for i, session := range sessions {
		if session != want {
			t.Fatalf("%s carried session_id %q, want %q", paths[i], session, want)
		}
	}
}

func TestSessionIDWithoutAReceiptStoreIsStableForTheProcess(t *testing.T) {
	first := NewClient("", "", nil).SessionID()
	second := NewClient("", "", nil).SessionID()
	if !strings.HasPrefix(first, "gw-boot-") || first != second {
		t.Fatalf("session ids %q and %q", first, second)
	}
}

func TestRequestSyncRunsAnOutOfBandSync(t *testing.T) {
	api := newSyncAPI(t)
	client := NewClient(api.URL, "test-key", nil)
	client.Start()
	defer client.StopWithin(time.Second)
	if api.syncCount() != 1 {
		t.Fatalf("startup syncs: %d", api.syncCount())
	}
	client.RequestSync()
	client.RequestSync()
	deadline := time.Now().Add(3 * time.Second)
	for api.syncCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := api.syncCount(); got < 2 || got > 3 {
		t.Fatalf("syncs after two requests: %d", got)
	}
}
