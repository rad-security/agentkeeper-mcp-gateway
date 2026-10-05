package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Tool definition upload. Every sync carries, for each connected server whose
// tool list the Gateway holds, tools_hash: a hash of the complete definitions.
// The definitions themselves are attached only when that hash differs from
// the last one the API accepted for the server, on the first sync of the
// process, and at least once a day, so the console keeps a history of
// definition changes without the Gateway re-sending every manifest.
const (
	// maxToolDescriptionBytes bounds one uploaded description; a longer one
	// is cut at a character boundary and ends in "…".
	maxToolDescriptionBytes = 16 * 1024
	// maxToolSchemaBytes bounds one uploaded inputSchema; a larger one is
	// replaced by a placeholder that records its size.
	maxToolSchemaBytes = 64 * 1024
	// maxToolsPayloadBytes bounds the tool lists one sync carries. Servers
	// that do not fit stay pending for the next sync.
	maxToolsPayloadBytes = 512 * 1024
	// maxSyncRequestBytes bounds a whole sync request. The runtime broker
	// refuses a message over 1 MiB, and tool lists must never cost a sync.
	maxSyncRequestBytes = 960 * 1024
	// toolDefinitionRefresh is how often an unchanged tool list is re-sent.
	toolDefinitionRefresh = 24 * time.Hour
)

// toolDefinitionFields are the parts of a tool definition that are hashed
// and uploaded.
var toolDefinitionFields = []string{"name", "description", "inputSchema", "annotations"}

// connectedServer is one connected_servers entry of a sync payload. Tools is
// pre-encoded so the bytes counted against the budget are the bytes sent; an
// empty list is sent as [].
type connectedServer struct {
	Name      string          `json:"name"`
	Transport string          `json:"transport,omitempty"`
	ToolsHash string          `json:"tools_hash,omitempty"`
	Tools     json.RawMessage `json:"tools,omitempty"`
}

// uploadedTool is one tool as connected_servers[].tools carries it.
type uploadedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// toolDefinition is one tool reduced to toolDefinitionFields.
type toolDefinition struct {
	name      string
	fields    map[string]interface{}
	canonical []byte
}

// toolUploadState is what the API last accepted for one server.
type toolUploadState struct {
	acceptedHash  string
	acceptedAt    time.Time
	pendingSince  time.Time
	oversizedHash string
}

// toolUpload is a tool list a sync carries, accepted with the sync.
type toolUpload struct {
	server string
	hash   string
}

// connectedSnapshot is the connected_servers of one sync with the
// definitions behind each entry; nil for a server whose list is not known.
type connectedSnapshot struct {
	entries     []connectedServer
	definitions [][]toolDefinition
}

// SetToolListProvider sets how the Gateway's listed tools are read for
// definition upload: per upstream name, the tools as advertised. A server
// absent from the map has no known list and is reported without a hash. The
// provider must not start or list an upstream.
func (c *Client) SetToolListProvider(provider func() map[string][]interface{}) {
	c.toolMu.Lock()
	defer c.toolMu.Unlock()
	c.toolLists = provider
}

// connectedServersSnapshot returns the connected_servers entries with their
// tools_hash, without tool lists.
func (c *Client) connectedServersSnapshot() connectedSnapshot {
	c.serversMu.RLock()
	servers := append([]ServerInfo(nil), c.servers...)
	c.serversMu.RUnlock()
	c.toolMu.Lock()
	provider := c.toolLists
	c.toolMu.Unlock()
	var lists map[string][]interface{}
	if provider != nil {
		lists = provider()
	}
	snapshot := connectedSnapshot{
		entries:     make([]connectedServer, len(servers)),
		definitions: make([][]toolDefinition, len(servers)),
	}
	for i, server := range servers {
		snapshot.entries[i] = connectedServer{Name: server.Name, Transport: server.Transport}
		tools, known := lists[server.Name]
		if !known {
			continue
		}
		hash, definitions, err := canonicalToolDefinitions(tools)
		if err != nil {
			if c.logger != nil {
				c.logger.Info("tool definitions of %s were not hashed: %v", server.Name, err)
			}
			continue
		}
		snapshot.entries[i].ToolsHash = hash
		snapshot.definitions[i] = definitions
	}
	return snapshot
}

// attachDueToolLists attaches the tool lists that are due to snapshot, whose
// entries payload already holds, within the per-sync budget, and returns the
// uploads the sync then carries.
func (c *Client) attachDueToolLists(snapshot connectedSnapshot, payload map[string]interface{}) []toolUpload {
	base, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	// Two budgets: the tool lists themselves, and what they add to the
	// request, which includes each list's member name.
	toolsLeft := maxToolsPayloadBytes
	requestLeft := maxSyncRequestBytes - len(base)
	const memberOverhead = len(`,"tools":`)
	now := c.now()

	c.toolMu.Lock()
	defer c.toolMu.Unlock()
	if c.toolStates == nil {
		c.toolStates = map[string]*toolUploadState{}
	}
	connected := map[string]bool{}
	type candidate struct {
		index int
		state *toolUploadState
	}
	var due []candidate
	for i, entry := range snapshot.entries {
		connected[entry.Name] = true
		if entry.ToolsHash == "" {
			continue
		}
		state := c.toolStates[entry.Name]
		if state == nil {
			state = &toolUploadState{}
			c.toolStates[entry.Name] = state
		}
		if state.acceptedHash == entry.ToolsHash && now.Sub(state.acceptedAt) < toolDefinitionRefresh {
			state.pendingSince = time.Time{}
			continue
		}
		if state.oversizedHash == entry.ToolsHash {
			continue
		}
		if state.pendingSince.IsZero() {
			state.pendingSince = now
		}
		due = append(due, candidate{index: i, state: state})
	}
	for name := range c.toolStates {
		if !connected[name] {
			delete(c.toolStates, name)
		}
	}
	// The longest-waiting lists go first, so a large list deferred once is
	// not passed over again by smaller ones.
	sort.SliceStable(due, func(i, j int) bool {
		a, b := due[i].state.pendingSince, due[j].state.pendingSince
		if !a.Equal(b) {
			return a.Before(b)
		}
		return snapshot.entries[due[i].index].Name < snapshot.entries[due[j].index].Name
	})

	var uploads []toolUpload
	for _, item := range due {
		entry := &snapshot.entries[item.index]
		encoded, err := encodeToolList(snapshot.definitions[item.index], false)
		if err == nil && len(encoded) > maxToolsPayloadBytes {
			// A list too large for any sync goes without input schemas,
			// each replaced by a placeholder that records its size.
			encoded, err = encodeToolList(snapshot.definitions[item.index], true)
		}
		if err != nil || len(encoded) > maxToolsPayloadBytes {
			item.state.oversizedHash = entry.ToolsHash
			if c.logger != nil {
				c.logger.Warn("tool definitions of %s exceed the %d KiB upload limit; only their hash is reported", entry.Name, maxToolsPayloadBytes/1024)
			}
			continue
		}
		if len(encoded) > toolsLeft || len(encoded)+memberOverhead > requestLeft {
			continue
		}
		entry.Tools = encoded
		toolsLeft -= len(encoded)
		requestLeft -= len(encoded) + memberOverhead
		uploads = append(uploads, toolUpload{server: entry.Name, hash: entry.ToolsHash})
	}
	return uploads
}

// acceptToolUploads records the tool lists of a sync the API accepted.
func (c *Client) acceptToolUploads(uploads []toolUpload) {
	if len(uploads) == 0 {
		return
	}
	now := c.now()
	c.toolMu.Lock()
	defer c.toolMu.Unlock()
	for _, upload := range uploads {
		state := c.toolStates[upload.server]
		if state == nil {
			continue
		}
		state.acceptedHash, state.acceptedAt, state.pendingSince = upload.hash, now, time.Time{}
	}
}

// canonicalToolDefinitions reduces a tools/list result to its definitions,
// sorted by name, and hashes their canonical form:
//
//	"sha256:" + hex(SHA-256(canonical JSON array of {name, description, inputSchema, annotations}))
//
// Each object keeps only the fields the tool has; the array is sorted by name
// (then by canonical form) in UTF-16 code unit order. The canonical JSON is
// RFC 8785: members sorted by name, numbers in ECMAScript form, minimal string
// escaping, no whitespace. Key order and formatting in what the server sent
// therefore never change the hash; any change to a definition does.
func canonicalToolDefinitions(tools []interface{}) (string, []toolDefinition, error) {
	definitions := make([]toolDefinition, 0, len(tools))
	for _, value := range tools {
		tool, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		fields := make(map[string]interface{}, len(toolDefinitionFields))
		for _, key := range toolDefinitionFields {
			if field, present := tool[key]; present {
				fields[key] = field
			}
		}
		canonical, err := appendCanonicalJSON(nil, fields)
		if err != nil {
			return "", nil, err
		}
		name, err := toolName(tool["name"])
		if err != nil {
			return "", nil, err
		}
		definitions = append(definitions, toolDefinition{name: name, fields: fields, canonical: canonical})
	}
	sort.SliceStable(definitions, func(i, j int) bool {
		if definitions[i].name != definitions[j].name {
			return lessUTF16(definitions[i].name, definitions[j].name)
		}
		return lessUTF16(string(definitions[i].canonical), string(definitions[j].canonical))
	})
	sum := sha256.New()
	sum.Write([]byte{'['})
	for i, definition := range definitions {
		if i > 0 {
			sum.Write([]byte{','})
		}
		sum.Write(definition.canonical)
	}
	sum.Write([]byte{']'})
	return "sha256:" + hex.EncodeToString(sum.Sum(nil)), definitions, nil
}

func toolName(value interface{}) (string, error) {
	if name, ok := value.(string); ok {
		return name, nil
	}
	canonical, err := appendCanonicalJSON(nil, value)
	return string(canonical), err
}

// encodeToolList encodes definitions as connected_servers[].tools carries
// them, with the per-tool caps. compact replaces every input schema with its
// size placeholder. The result is what json.Marshal writes, so it is also
// what the request carries.
func encodeToolList(definitions []toolDefinition, compact bool) (json.RawMessage, error) {
	tools := make([]uploadedTool, 0, len(definitions))
	for _, definition := range definitions {
		tool := uploadedTool{Name: definition.name}
		if description, present := definition.fields["description"]; present && description != nil {
			text, ok := description.(string)
			if !ok {
				canonical, err := appendCanonicalJSON(nil, description)
				if err != nil {
					return nil, err
				}
				text = string(canonical)
			}
			tool.Description = truncateDescription(text)
		}
		if schema, present := definition.fields["inputSchema"]; present {
			canonical, err := appendCanonicalJSON(nil, schema)
			if err != nil {
				return nil, err
			}
			if compact || len(canonical) > maxToolSchemaBytes {
				canonical, err = appendCanonicalJSON(nil, map[string]interface{}{
					"type":        "object",
					"description": fmt.Sprintf("Schema omitted: %d bytes", len(canonical)),
				})
				if err != nil {
					return nil, err
				}
			}
			tool.InputSchema = canonical
		}
		if annotations, present := definition.fields["annotations"]; present {
			canonical, err := appendCanonicalJSON(nil, annotations)
			if err != nil {
				return nil, err
			}
			tool.Annotations = canonical
		}
		tools = append(tools, tool)
	}
	return json.Marshal(tools)
}

// truncateDescription cuts a description longer than the cap at a character
// boundary, keeping the result, "…" included, within the cap.
func truncateDescription(text string) string {
	if len(text) <= maxToolDescriptionBytes {
		return text
	}
	const ellipsis = "…"
	cut := maxToolDescriptionBytes - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + ellipsis
}

// appendCanonicalJSON appends the RFC 8785 (JSON Canonicalization Scheme)
// form of a decoded JSON value.
func appendCanonicalJSON(dst []byte, value interface{}) ([]byte, error) {
	var err error
	switch typed := value.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if typed {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case string:
		return appendCanonicalString(dst, typed), nil
	case float64:
		return appendCanonicalNumber(dst, typed)
	case json.Number:
		number, parseErr := strconv.ParseFloat(string(typed), 64)
		if parseErr != nil {
			return nil, parseErr
		}
		return appendCanonicalNumber(dst, number)
	case []interface{}:
		dst = append(dst, '[')
		for i, item := range typed {
			if i > 0 {
				dst = append(dst, ',')
			}
			if dst, err = appendCanonicalJSON(dst, item); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		dst = append(dst, '{')
		for i, key := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendCanonicalString(dst, key)
			dst = append(dst, ':')
			if dst, err = appendCanonicalJSON(dst, typed[key]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		// Any other Go value is canonicalized through its JSON form.
		raw, marshalErr := json.Marshal(typed)
		if marshalErr != nil {
			return nil, marshalErr
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var decoded interface{}
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		return appendCanonicalJSON(dst, decoded)
	}
}

// appendCanonicalNumber writes a number as ECMAScript's Number#toString does.
func appendCanonicalNumber(dst []byte, number float64) ([]byte, error) {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return nil, fmt.Errorf("unsupported number %v", number)
	}
	if number == 0 {
		return append(dst, '0'), nil // also -0
	}
	format := byte('f')
	if abs := math.Abs(number); abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	dst = strconv.AppendFloat(dst, number, format, -1, 64)
	if format == 'e' {
		// ECMAScript writes 1e-7 where Go writes 1e-07.
		n := len(dst)
		if n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst, nil
}

const lowerHex = "0123456789abcdef"

// appendCanonicalString escapes only what JSON requires, as RFC 8785 does.
func appendCanonicalString(dst []byte, text string) []byte {
	text = strings.ToValidUTF8(text, "�")
	dst = append(dst, '"')
	for i := 0; i < len(text); i++ {
		switch b := text[i]; {
		case b == '"':
			dst = append(dst, '\\', '"')
		case b == '\\':
			dst = append(dst, '\\', '\\')
		case b >= 0x20:
			dst = append(dst, b)
		case b == '\b':
			dst = append(dst, '\\', 'b')
		case b == '\f':
			dst = append(dst, '\\', 'f')
		case b == '\n':
			dst = append(dst, '\\', 'n')
		case b == '\r':
			dst = append(dst, '\\', 'r')
		case b == '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', lowerHex[b>>4], lowerHex[b&0xF])
		}
	}
	return append(dst, '"')
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 sorts
// member names. It equals byte order unless a string holds a character
// outside the Basic Multilingual Plane.
func lessUTF16(a, b string) bool {
	if basicPlaneOnly(a) && basicPlaneOnly(b) {
		return a < b
	}
	left, right := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}

func basicPlaneOnly(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0xF0 {
			return false
		}
	}
	return true
}
