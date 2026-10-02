package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
)

// A server can advertise an ordinary tool, wait until it is trusted, and then
// change the definition. The Gateway records a fingerprint of each definition
// the first time it sees it and reports a later change once.
//
// The record is evidence, not a control: any failure to read or write it
// leaves tool listing and tool calls untouched.

type definitionPin struct {
	SHA256    string `json:"sha256"`
	FirstSeen string `json:"first_seen"`
	ChangedAt string `json:"changed_at,omitempty"`
}

type persistentDefinitionPins struct {
	Version int                                 `json:"version"`
	Servers map[string]map[string]definitionPin `json:"servers"`
}

// maxPinnedDefinitions bounds the record for one server.
const maxPinnedDefinitions = 5000

// maxReportedDefinitionChanges bounds the events one tool list from one
// server can produce. Every change is recorded; the rest are counted.
const maxReportedDefinitionChanges = 25

// definitionPinsMu orders the goroutines of this process. The lock file
// orders the Gateway processes that share the record.
var definitionPinsMu sync.Mutex

// changedToolDefinitions records the definitions one server advertised and
// returns the names of tools whose definition differs from the recorded one,
// at most maxReportedDefinitionChanges of them, and how many more changed.
// A tool seen for the first time is recorded and not returned.
func (p *Proxy) changedToolDefinitions(serverName string, tools []interface{}) (changed []string, suppressed int) {
	path := p.config.DefinitionPinsPath
	if path == "" {
		return nil, 0
	}
	current := definitionFingerprints(tools)
	if len(current) == 0 {
		return nil, 0
	}
	changed, _ = recordDefinitions(path, serverName, current)
	if len(changed) > maxReportedDefinitionChanges {
		suppressed = len(changed) - maxReportedDefinitionChanges
		changed = changed[:maxReportedDefinitionChanges]
	}
	return changed, suppressed
}

// definitionFingerprints returns the fingerprint of each named tool in one
// list. A list longer than maxPinnedDefinitions is cut to its first names in
// sorted order, so the same tools are compared on every list.
func definitionFingerprints(tools []interface{}) map[string]string {
	type namedDefinition struct {
		name string
		tool map[string]interface{}
	}
	definitions := make([]namedDefinition, 0, len(tools))
	for _, value := range tools {
		tool, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := tool["name"].(string); name != "" {
			definitions = append(definitions, namedDefinition{name, tool})
		}
	}
	sort.SliceStable(definitions, func(i, j int) bool { return definitions[i].name < definitions[j].name })

	current := make(map[string]string, min(len(definitions), maxPinnedDefinitions))
	for _, definition := range definitions {
		listed, repeated := current[definition.name]
		if !repeated && len(current) == maxPinnedDefinitions {
			break
		}
		fingerprint := definitionFingerprint(definition.tool)
		if fingerprint == "" {
			continue
		}
		if repeated {
			// A name listed twice is pinned as the pair. Pinned one at a time,
			// each would read as a change to the other on every list.
			sum := sha256.Sum256([]byte(listed + fingerprint))
			fingerprint = hex.EncodeToString(sum[:])
		}
		current[definition.name] = fingerprint
	}
	return current
}

// recordDefinitions makes current the record for one server and returns the
// names whose fingerprint differs from the recorded one, in sorted order.
// recorded is false when the record could not be updated; nothing is reported
// then, because a change that is not recorded would be reported on every list.
func recordDefinitions(path, serverName string, current map[string]string) (changed []string, recorded bool) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false
	}
	definitionPinsMu.Lock()
	defer definitionPinsMu.Unlock()
	// Several Gateway processes share this record, one per routed client. The
	// lock covers the read as well as the write, so no process writes back a
	// record that is missing another's pins. Its wait is bounded: a busy
	// record skips this list rather than holding up the tool list.
	release, err := fslock.Acquire(path + ".lock")
	if err != nil {
		return nil, false
	}
	defer release()

	pins := persistentDefinitionPins{Version: 1, Servers: map[string]map[string]definitionPin{}}
	if data, err := os.ReadFile(path); err == nil {
		var stored persistentDefinitionPins
		if json.Unmarshal(data, &stored) == nil && stored.Servers != nil {
			pins.Servers = stored.Servers
		}
	}
	stored := pins.Servers[serverName]

	// The record for a server mirrors its latest list. Pins for tools that are
	// no longer listed are dropped, or a server that keeps renaming its tools
	// would grow the record without bound.
	now := time.Now().UTC().Format(time.RFC3339)
	latest := make(map[string]definitionPin, len(current))
	dirty := len(stored) != len(current)
	for name, fingerprint := range current {
		pin, seen := stored[name]
		switch {
		case !seen:
			pin = definitionPin{SHA256: fingerprint, FirstSeen: now}
			dirty = true
		case pin.SHA256 != fingerprint:
			pin.SHA256, pin.ChangedAt = fingerprint, now
			changed = append(changed, name)
			dirty = true
		}
		latest[name] = pin
	}
	pins.Servers[serverName] = latest
	if dirty && !writeDefinitionPins(path, pins) {
		return nil, false
	}
	sort.Strings(changed)
	return changed, true
}

// definitionFingerprint hashes a definition in canonical form: encoding/json
// writes object keys in sorted order.
func definitionFingerprint(tool map[string]interface{}) string {
	canonical, err := json.Marshal(tool)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func writeDefinitionPins(path string, pins persistentDefinitionPins) bool {
	data, err := json.Marshal(pins)
	if err != nil {
		return false
	}
	// Several Gateway processes share this record, one per routed client.
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false
	}
	return true
}

func (p *Proxy) logChangedToolDefinitions(serverName string, tools []interface{}) {
	changed, suppressed := p.changedToolDefinitions(serverName, tools)
	if p.config.Logger == nil {
		return
	}
	mode := "observe"
	if p.enforceMode() {
		mode = "enforce"
	}
	for _, name := range changed {
		shown := name
		if len(shown) > 80 {
			shown = shown[:80]
		}
		p.config.Logger.LogDefinitionFinding(serverName, name, detection.Result{
			Verdict:     detection.VerdictWarn,
			PatternName: "tool_definition_changed",
			Severity:    "high",
			Description: "Tool definition changed after it was first recorded; review it before trusting it in tool: " + shown,
			Category:    "tool_poisoning",
		}, mode, true)
	}
	if suppressed > 0 {
		// One event stands for the rest, so a server that changes every
		// definition at once cannot flood the event log. The service drops
		// an event with no tool name, so the count stands in for one.
		p.config.Logger.LogDefinitionFinding(serverName, fmt.Sprintf("%d more tools", suppressed), detection.Result{
			Verdict:     detection.VerdictWarn,
			PatternName: "tool_definition_changed",
			Severity:    "high",
			Description: fmt.Sprintf("%d more tool definitions changed on this server after they were first recorded and are not reported one by one; review the server before trusting its tools", suppressed),
			Category:    "tool_poisoning",
		}, mode, true)
	}
}
