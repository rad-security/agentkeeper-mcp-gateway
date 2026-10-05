package proxy

import (
	"sort"
	"strings"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// Two routed MCP servers can offer the same tool name, or one server can take a
// name that looks like another's, so a client or agent reaches for the wrong
// one. tools/list reports these — it never hides a tool; the operator decides.

// genericToolNames are names many servers legitimately share. A duplicate of
// one is reported only when the servers look alike or a definition is poisoned.
var genericToolNames = map[string]bool{
	"search": true, "list": true, "get": true, "read": true, "write": true,
	"query": true, "fetch": true, "run": true, "help": true, "status": true,
	"ping": true, "version": true,
}

// lookalikeTokens are words an impostor server name adds to shadow a real one.
var lookalikeTokens = []string{"shadow", "proxy", "mirror", "official", "backup", "alt", "copy", "clone", "fork", "real", "secure", "v2"}

// reportToolShadowing inspects the routed servers' cached tools for duplicate
// tool names across servers and look-alike server names, and logs one finding
// per pair per process. It reads cached state only and never changes the list.
func (p *Proxy) reportToolShadowing() {
	if p.config.Logger == nil {
		return
	}
	servers := p.routedServersWithTools()
	if len(servers) < 2 {
		return
	}
	sort.Strings(servers)

	toolsByServer := make(map[string]map[string]map[string]interface{}, len(servers))
	for _, s := range servers {
		named := make(map[string]map[string]interface{})
		for _, value := range p.cachedTools(s) {
			if tool, ok := value.(map[string]interface{}); ok {
				if name := definitionString(tool["name"]); name != "" {
					named[strings.ToLower(name)] = tool
				}
			}
		}
		toolsByServer[s] = named
	}

	mode := "observe"
	if p.enforceMode() {
		mode = "enforce"
	}

	// Look-alike server names, every unordered pair once.
	lookalikePairs := make(map[string]bool)
	for i := 0; i < len(servers); i++ {
		for j := i + 1; j < len(servers); j++ {
			if serversLookAlike(servers[i], servers[j]) {
				lookalikePairs[servers[i]+"\x00"+servers[j]] = true
				p.emitShadowFinding("la|"+servers[i]+"|"+servers[j], servers[j], "tool_shadowing_lookalike_server",
					"Server "+servers[j]+" looks like "+servers[i]+".", mode)
			}
		}
	}

	// Duplicate tool names across servers, every (tool, server pair) once.
	for i := 0; i < len(servers); i++ {
		for j := i + 1; j < len(servers); j++ {
			a, b := servers[i], servers[j]
			for name, toolA := range toolsByServer[a] {
				toolB, ok := toolsByServer[b][name]
				if !ok {
					continue
				}
				if genericToolNames[name] && !lookalikePairs[a+"\x00"+b] && !p.eitherPoisoned(toolA, toolB) {
					continue
				}
				p.emitShadowFinding("dup|"+name+"|"+a+"|"+b, a, "tool_shadowing_duplicate",
					"Tool "+name+" is offered by both "+a+" and "+b+".", mode)
			}
		}
	}
}

func (p *Proxy) eitherPoisoned(a, b map[string]interface{}) bool {
	if p.config.DetectionEngine == nil {
		return false
	}
	return p.config.DetectionEngine.HasPoisonTrait(toolDescriptionFromMap(a)) ||
		p.config.DetectionEngine.HasPoisonTrait(toolDescriptionFromMap(b))
}

func (p *Proxy) emitShadowFinding(key, serverName, pattern, description, mode string) {
	p.shadowMu.Lock()
	if p.shadowReported[key] {
		p.shadowMu.Unlock()
		return
	}
	p.shadowReported[key] = true
	p.shadowMu.Unlock()
	p.config.Logger.LogDefinitionFinding(serverName, "", detection.Result{
		Verdict:     detection.VerdictWarn,
		PatternName: pattern,
		Severity:    "medium",
		Description: description,
		Category:    "tool_poisoning",
	}, mode, true)
}

func (p *Proxy) routedServersWithTools() []string {
	p.mu.Lock()
	names := make([]string, 0, len(p.toolCache))
	for name, tools := range p.toolCache {
		if len(tools) > 0 {
			names = append(names, name)
		}
	}
	p.mu.Unlock()
	routed := names[:0]
	for _, name := range names {
		if !p.serverBlockedByPolicy(name) {
			routed = append(routed, name)
		}
	}
	return routed
}

// serversLookAlike reports whether two server names are confusable: equal after
// stripping separators, digits and impostor tokens; a short edit distance; or
// equal after folding look-alike letters.
func serversLookAlike(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if normalizeServerName(la) == normalizeServerName(lb) {
		return true
	}
	if detection.FoldConfusables(la) == detection.FoldConfusables(lb) {
		return true
	}
	if len(la) >= 6 && len(lb) >= 6 && damerauLevenshtein(la, lb, 2) <= 2 {
		return true
	}
	return false
}

func normalizeServerName(name string) string {
	for _, token := range lookalikeTokens {
		name = strings.ReplaceAll(name, token, "")
	}
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// damerauLevenshtein returns the optimal-string-alignment distance, capped: any
// value above max is reported as max+1 so callers can threshold cheaply.
func damerauLevenshtein(a, b string, max int) int {
	ra, rb := []rune(a), []rune(b)
	if abs(len(ra)-len(rb)) > max {
		return max + 1
	}
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		best := curr[0]
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < curr[j] {
					curr[j] = t
				}
			}
			if curr[j] < best {
				best = curr[j]
			}
		}
		if best > max {
			return max + 1
		}
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[len(rb)]
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
