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

var definitionPinsMu sync.Mutex

// changedToolDefinitions records the definitions one server advertised and
// returns the names of tools whose definition differs from the recorded one.
// A tool seen for the first time is recorded and not returned.
func (p *Proxy) changedToolDefinitions(serverName string, tools []interface{}) []string {
	path := p.config.DefinitionPinsPath
	if path == "" || len(tools) == 0 || len(tools) > maxPinnedDefinitions {
		return nil
	}
	definitionPinsMu.Lock()
	defer definitionPinsMu.Unlock()

	pins := persistentDefinitionPins{Version: 1, Servers: map[string]map[string]definitionPin{}}
	if data, err := os.ReadFile(path); err == nil {
		var stored persistentDefinitionPins
		if json.Unmarshal(data, &stored) == nil && stored.Servers != nil {
			pins.Servers = stored.Servers
		}
	}
	recorded := pins.Servers[serverName]
	if recorded == nil {
		recorded = map[string]definitionPin{}
		pins.Servers[serverName] = recorded
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var changed []string
	dirty := false
	for _, value := range tools {
		tool, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		fingerprint := definitionFingerprint(tool)
		if name == "" || fingerprint == "" {
			continue
		}
		pin, seen := recorded[name]
		switch {
		case !seen:
			recorded[name] = definitionPin{SHA256: fingerprint, FirstSeen: now}
			dirty = true
		case pin.SHA256 != fingerprint:
			pin.SHA256, pin.ChangedAt = fingerprint, now
			recorded[name] = pin
			changed = append(changed, name)
			dirty = true
		}
	}
	if dirty && !writeDefinitionPins(path, pins) {
		// A change that cannot be recorded would be reported on every list.
		return nil
	}
	sort.Strings(changed)
	return changed
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
	changed := p.changedToolDefinitions(serverName, tools)
	if p.config.Logger == nil {
		return
	}
	for _, name := range changed {
		shown := name
		if len(shown) > 80 {
			shown = shown[:80]
		}
		mode := "observe"
		if p.enforceMode() {
			mode = "enforce"
		}
		p.config.Logger.LogDefinitionFinding(serverName, name, detection.Result{
			Verdict:     detection.VerdictWarn,
			PatternName: "tool_definition_changed",
			Severity:    "high",
			Description: "Tool definition changed after it was first recorded; review it before trusting it in tool: " + shown,
			Category:    "tool_poisoning",
		}, mode, true)
	}
}
