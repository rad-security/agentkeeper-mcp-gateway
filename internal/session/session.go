// Package session correlates MCP activity across the calls of one client
// session to catch multi-step attacks that no single call reveals: a secret
// read by one tool and sent out by a later one (whole, in pieces, or encoded),
// an instruction split across several results, and a "stage a helper, then run
// it" exfiltration.
//
// All state is in memory in the Gateway process (one process per client
// session), bounded, never persisted, and never stores a raw secret: only
// truncated SHA-256 hashes of a secret and of its overlapping shingles are
// kept, so the store cannot leak what it protects.
package session

import (
	"crypto/sha256"
	"encoding/binary"
	"regexp"
	"strings"
	"sync"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// Pattern names and category emitted by the correlator.
const (
	patternSecretEgress    = "session_secret_egress"
	patternInjectionFrags  = "session_injection_fragments"
	patternStagedExecution = "session_staged_execution"
	categoryThreat         = "threat"
	severityCritical       = "critical"
	severityHigh           = "high"
	minSecretLen           = 16
	shingleLen             = 12
	shingleStride          = 4
	minShingleOverlap      = 2
	maxRememberedSecrets   = 512
	maxShingleHashes       = 8192 // ~64 KiB of 8-byte hashes
	maxFragmentResults     = 8
	maxFragmentBytes       = 8 << 10
	stagedExecutionWindow  = 10
	maxStagedArtifacts     = 128
	maxFragmentConcatBytes = 64 << 10
	maxArgShingleBytes     = 64 << 10
	maxEgressDestinations  = 16
	maxTrailFields         = 16
	maxTrailHashes         = 4096
	maxTrailLeaves         = 256
)

// Finding is a correlation detection the proxy turns into an event and, in
// Enforce with the matching detection mode set to block, acts on.
type Finding struct {
	Pattern     string
	Severity    string
	Description string
	Correlation map[string]interface{}
}

// Result converts a finding to the detection result the proxy merges and logs.
func (f Finding) Result() detection.Result {
	return detection.Result{
		Verdict:     detection.VerdictWarn,
		PatternName: f.Pattern,
		Severity:    f.Severity,
		Description: f.Description,
		Category:    categoryThreat,
	}
}

// Tracker holds one session's correlation state.
type Tracker struct {
	engine *detection.Engine
	mu     sync.Mutex

	secrets     []rememberedSecret
	shingleUsed int

	fragments []fragmentEntry

	staged       []stagedArtifact
	callSeq      int
	pendingStage *pendingStage

	trails     map[string]*egressTrail
	trailOrder []string
}

// egressTrail remembers what one destination tool has been sent in this
// session, so a value sent a few characters per call is recognised once
// enough of it has gone out. Like remembered secrets it keeps hashes: of every
// 12-character window sent so far, field by field, plus the last 11 characters
// of each field, which a window crossing into the next call needs.
type egressTrail struct {
	tails    map[string]string
	hashes   map[uint64]bool
	calls    int
	reported map[uint64]bool
}

type rememberedSecret struct {
	full     uint64
	shingles map[uint64]bool
	server   string
	tool     string
	pattern  string
}

type fragmentEntry struct {
	server string
	text   string // truncated result text, lower-cased normalized join handled by the engine
}

type stagedArtifact struct {
	server string
	keys   map[string]bool
	tool   string
	atCall int
}

type pendingStage struct {
	server string
	tool   string
	index  int // index into staged for id aliasing from the result
}

// New returns a tracker backed by the shared detection engine.
func New(engine *detection.Engine) *Tracker {
	return &Tracker{engine: engine}
}

// egressVerbs mark a tool, on the same server as the source, whose purpose is
// to send data outward; sending a remembered secret to one is suspicious even
// without a different server.
var egressVerbs = []string{"send", "post", "upload", "submit", "store", "write", "create", "publish", "share", "transfer", "export", "sync", "save", "put", "push", "append"}

var stagedCreateVerbs = []string{"create", "write", "save", "define", "register", "build", "generate", "add", "upload", "put"}
var stagedRunVerbs = []string{"run", "execute", "invoke", "trigger", "start", "apply", "call", "exec"}

// credentialSources are high-value local secret files a staged helper would
// read. Matched as substrings of the flattened argument text.
var credentialSources = []string{
	"~/.aws/credentials", ".aws/credentials", "~/.ssh/", "/.ssh/", "id_rsa", "id_ed25519",
	".env", ".npmrc", ".netrc", ".pgpass", "kubeconfig", ".docker/config.json",
	".git-credentials", "wallet.dat", "secrets.json", "credentials.json",
}

var tokenSecretFile = regexp.MustCompile(`\b[\w.-]*(?:token|secret|credential|apikey|api_key)[\w.-]*\.(?:json|txt|yaml|yml|env|ini|cfg|conf|pem|key)\b`)

// ObserveContent records a returned payload (a tool result, a resource, or a
// prompt) for later correlation and reports an instruction split across recent
// results. scan is the result of the engine's own scan of the same content, so
// the sensitive values it already found are reused rather than rescanned.
func (t *Tracker) ObserveContent(server, tool, raw string, scan detection.ScanResult) *Finding {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rememberSecrets(server, tool, scan)
	t.captureStagedID(server, raw)

	return t.observeFragment(server, raw, scan)
}

func (t *Tracker) rememberSecrets(server, tool string, scan detection.ScanResult) {
	for _, f := range scan.Findings {
		if f.Category != "sensitive_data" {
			continue
		}
		for _, value := range f.Values {
			t.rememberSecret(server, tool, f.PatternName, value)
		}
	}
}

func (t *Tracker) rememberSecret(server, tool, pattern, value string) {
	canon := canonical(value)
	if len(canon) < minSecretLen {
		return
	}
	shingles := shingleSet(canon)
	if len(shingles) == 0 {
		return
	}
	full := hash64(canon)
	if t.hasSecret(full) {
		return
	}
	t.evictForSecret(len(shingles))
	t.secrets = append(t.secrets, rememberedSecret{full: full, shingles: shingles, server: server, tool: tool, pattern: pattern})
	t.shingleUsed += len(shingles)
}

func (t *Tracker) hasSecret(full uint64) bool {
	for _, s := range t.secrets {
		if s.full == full {
			return true
		}
	}
	return false
}

// evictForSecret keeps the store within both bounds, dropping oldest first.
func (t *Tracker) evictForSecret(incoming int) {
	for len(t.secrets) >= maxRememberedSecrets || (t.shingleUsed+incoming > maxShingleHashes && len(t.secrets) > 0) {
		t.shingleUsed -= len(t.secrets[0].shingles)
		t.secrets = t.secrets[1:]
	}
}

func (t *Tracker) observeFragment(server, raw string, scan detection.ScanResult) *Finding {
	text := truncate(raw, maxFragmentBytes)
	// A result that already carries an instruction on its own is handled by the
	// result-poison families; do not also raise a fragment finding for it.
	selfFlagged := false
	for _, f := range scan.Findings {
		if strings.HasPrefix(f.PatternName, "result_") {
			selfFlagged = true
			break
		}
	}
	t.fragments = append(t.fragments, fragmentEntry{server: server, text: text})
	if len(t.fragments) > maxFragmentResults {
		t.fragments = t.fragments[len(t.fragments)-maxFragmentResults:]
	}
	if selfFlagged {
		return nil
	}
	// Scan concatenations of the last 2..8 results (space-joined and directly
	// joined); a match means the instruction was split across them.
	for k := 2; k <= len(t.fragments); k++ {
		window := t.fragments[len(t.fragments)-k:]
		for _, sep := range []string{" ", ""} {
			joined := joinFragments(window, sep)
			_, desc, ok := t.engine.MatchesInstruction(joined)
			if !ok {
				continue
			}
			// The newest result must complete the instruction. One already
			// present in the earlier results was reported when it arrived, and
			// the results after it are not part of it.
			if _, _, before := t.engine.MatchesInstruction(joinFragments(window[:len(window)-1], sep)); before {
				continue
			}
			return &Finding{
				Pattern:     patternInjectionFrags,
				Severity:    severityHigh,
				Description: "Instructions split across results from " + serverList(window) + " in this session: " + desc,
				Correlation: map[string]interface{}{
					"source_server": window[0].server,
					"steps":         fragmentSteps(window),
				},
			}
		}
	}
	return nil
}

// InspectCall examines a tool call before dispatch. It reports secret egress
// (a value returned earlier being sent somewhere it did not come from) and the
// run half of a staged-execution pair, and records the create half.
func (t *Tracker) InspectCall(server, tool string, args map[string]interface{}) *Finding {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callSeq++
	t.pendingStage = nil

	flat := detection.FlattenArguments(args)
	views := t.engine.ContentViews(flat)
	argShingles := argumentShingles(views)

	if f := t.checkSecretEgress(server, tool, argShingles); f != nil {
		return f
	}
	if f := t.checkStagedExecution(server, tool, flat, argShingles); f != nil {
		return f
	}
	return t.checkEgressAcrossCalls(server, tool, args)
}

// checkEgressAcrossCalls adds this call's arguments to its destination's trail
// and reports a remembered value that has now reached that destination in
// pieces over several calls, each too small to recognise on its own.
func (t *Tracker) checkEgressAcrossCalls(server, tool string, args map[string]interface{}) *Finding {
	if len(t.secrets) == 0 {
		return nil
	}
	trail := t.trailFor(server, tool)
	trail.calls++
	for path, value := range stringLeaves(args) {
		canon := canonical(value)
		if canon == "" {
			continue
		}
		tail, known := trail.tails[path]
		if !known && len(trail.tails) >= maxTrailFields {
			continue
		}
		joined := tail + canon
		for i := 0; i+shingleLen <= len(joined); i++ {
			if len(trail.hashes) >= maxTrailHashes {
				// Bounded: start the trail over rather than grow.
				trail.hashes = map[uint64]bool{}
			}
			trail.hashes[hash64(joined[i:i+shingleLen])] = true
		}
		if len(joined) > shingleLen-1 {
			joined = joined[len(joined)-(shingleLen-1):]
		}
		trail.tails[path] = joined
	}
	if trail.calls < 2 {
		return nil
	}
	lowerTool := strings.ToLower(tool)
	for _, s := range t.secrets {
		if trail.reported[s.full] {
			continue
		}
		differentServer := !strings.EqualFold(s.server, server)
		egressTool := !strings.EqualFold(s.tool, tool) && containsVerb(lowerTool, egressVerbs)
		if !differentServer && !egressTool {
			continue
		}
		if overlap(s.shingles, trail.hashes) < minShingleOverlap {
			continue
		}
		trail.reported[s.full] = true
		return &Finding{
			Pattern:     patternSecretEgress,
			Severity:    severityCritical,
			Description: "Data returned by " + s.server + "/" + s.tool + " earlier in this session is being sent to " + server + "/" + tool + " in pieces across calls.",
			Correlation: map[string]interface{}{
				"source_server": s.server,
				"source_tool":   s.tool,
				"steps": []map[string]interface{}{
					{"role": "source", "server": s.server, "tool": s.tool, "detail": s.pattern},
					{"role": "egress", "server": server, "tool": tool, "detail": "pieces across calls"},
				},
			},
		}
	}
	return nil
}

func (t *Tracker) trailFor(server, tool string) *egressTrail {
	key := strings.ToLower(server) + "\x00" + strings.ToLower(tool)
	if t.trails == nil {
		t.trails = map[string]*egressTrail{}
	}
	if trail, ok := t.trails[key]; ok {
		for i, k := range t.trailOrder {
			if k == key {
				t.trailOrder = append(append(t.trailOrder[:i:i], t.trailOrder[i+1:]...), key)
				break
			}
		}
		return trail
	}
	if len(t.trailOrder) >= maxEgressDestinations {
		delete(t.trails, t.trailOrder[0])
		t.trailOrder = t.trailOrder[1:]
	}
	trail := &egressTrail{tails: map[string]string{}, hashes: map[uint64]bool{}, reported: map[uint64]bool{}}
	t.trails[key] = trail
	t.trailOrder = append(t.trailOrder, key)
	return trail
}

// stringLeaves lists the string values in a call's arguments by field path.
// Array items share their array's path, so pieces sent as list items join up.
func stringLeaves(args map[string]interface{}) map[string]string {
	leaves := map[string]string{}
	var walk func(path string, value interface{})
	walk = func(path string, value interface{}) {
		if len(leaves) >= maxTrailLeaves {
			return
		}
		switch v := value.(type) {
		case string:
			leaves[path] += v
		case map[string]interface{}:
			for key, child := range v {
				walk(path+"."+key, child)
			}
		case []interface{}:
			for _, child := range v {
				walk(path+"[]", child)
			}
		}
	}
	for key, value := range args {
		walk(key, value)
	}
	return leaves
}

func (t *Tracker) checkSecretEgress(server, tool string, argShingles map[uint64]bool) *Finding {
	lowerTool := strings.ToLower(tool)
	for _, s := range t.secrets {
		if overlap(s.shingles, argShingles) < minShingleOverlap {
			continue
		}
		// Flag only when the destination differs from the source: a different
		// server, or the same server with a different, egress-shaped tool.
		differentServer := !strings.EqualFold(s.server, server)
		egressTool := !strings.EqualFold(s.tool, tool) && containsVerb(lowerTool, egressVerbs)
		if !differentServer && !egressTool {
			continue
		}
		return &Finding{
			Pattern:     patternSecretEgress,
			Severity:    severityCritical,
			Description: "Data returned by " + s.server + "/" + s.tool + " earlier in this session is being sent to " + server + "/" + tool + ".",
			Correlation: map[string]interface{}{
				"source_server": s.server,
				"source_tool":   s.tool,
				"steps": []map[string]interface{}{
					{"role": "source", "server": s.server, "tool": s.tool, "detail": s.pattern},
					{"role": "egress", "server": server, "tool": tool},
				},
			},
		}
	}
	return nil
}

func (t *Tracker) checkStagedExecution(server, tool, flat string, argShingles map[uint64]bool) *Finding {
	lowerTool := strings.ToLower(tool)

	// The run half: a run-shaped tool on a server that staged an external
	// artifact, matching a remembered key, or the next such call within the
	// window when no key is recoverable.
	if containsVerb(lowerTool, stagedRunVerbs) {
		for i := range t.staged {
			st := &t.staged[i]
			if !strings.EqualFold(st.server, server) {
				continue
			}
			keyed := keyMatch(st.keys, flat)
			within := len(st.keys) == 0 && t.callSeq-st.atCall <= stagedExecutionWindow
			if keyed || within {
				finding := &Finding{
					Pattern:     patternStagedExecution,
					Severity:    severityHigh,
					Description: "A helper staged earlier in this session with a sensitive source and an external destination is now being run on " + server + ".",
					Correlation: map[string]interface{}{
						"source_server": st.server,
						"source_tool":   st.tool,
						"steps": []map[string]interface{}{
							{"role": "stage", "server": st.server, "tool": st.tool},
							{"role": "execute", "server": server, "tool": tool},
						},
					},
				}
				return finding
			}
		}
	}

	// The create half: a create-shaped tool whose arguments carry both a
	// sensitive source and an external destination.
	if containsVerb(lowerTool, stagedCreateVerbs) {
		if (hasCredentialSource(flat) || t.argsCarryRememberedSecret(argShingles)) && hasExternalDestination(flat) {
			t.rememberStaged(server, tool, flat)
		}
	}
	return nil
}

func (t *Tracker) argsCarryRememberedSecret(argShingles map[uint64]bool) bool {
	for _, s := range t.secrets {
		if overlap(s.shingles, argShingles) >= minShingleOverlap {
			return true
		}
	}
	return false
}

func (t *Tracker) rememberStaged(server, tool, flat string) {
	keys := stagedKeys(flat)
	if len(t.staged) >= maxStagedArtifacts {
		t.staged = t.staged[1:]
	}
	t.staged = append(t.staged, stagedArtifact{server: server, keys: keys, tool: tool, atCall: t.callSeq})
	t.pendingStage = &pendingStage{server: server, tool: tool, index: len(t.staged) - 1}
}

// captureStagedID lets a staged artifact whose key was not in the create
// arguments pick up an id returned in the create result.
func (t *Tracker) captureStagedID(server, raw string) {
	if t.pendingStage == nil || !strings.EqualFold(t.pendingStage.server, server) {
		t.pendingStage = nil
		return
	}
	idx := t.pendingStage.index
	t.pendingStage = nil
	if idx < 0 || idx >= len(t.staged) {
		return
	}
	for _, id := range resultIDs(raw) {
		t.staged[idx].keys[strings.ToLower(id)] = true
	}
}

// --- helpers --------------------------------------------------------------

func canonical(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func shingleSet(canon string) map[uint64]bool {
	set := make(map[uint64]bool)
	if len(canon) < shingleLen {
		if len(canon) >= minSecretLen {
			set[hash64(canon)] = true
		}
		return set
	}
	for i := 0; i+shingleLen <= len(canon); i += shingleStride {
		set[hash64(canon[i:i+shingleLen])] = true
	}
	return set
}

// argumentShingles canonicalizes each argument view and takes every 12-char
// window (stride 1) so a secret contiguous in any view aligns with the stride-4
// windows remembered for it regardless of offset. The input is capped so a
// large argument cannot make per-call correlation expensive.
func argumentShingles(views []string) map[uint64]bool {
	set := make(map[uint64]bool)
	budget := maxArgShingleBytes
	for _, v := range views {
		if budget <= 0 {
			break
		}
		canon := canonical(v)
		if len(canon) > budget {
			canon = canon[:budget]
		}
		budget -= len(canon)
		for i := 0; i+shingleLen <= len(canon); i++ {
			set[hash64(canon[i:i+shingleLen])] = true
		}
	}
	return set
}

func overlap(a, b map[uint64]bool) int {
	small, large := a, b
	if len(b) < len(a) {
		small, large = b, a
	}
	n := 0
	for h := range small {
		if large[h] {
			n++
		}
	}
	return n
}

func hash64(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(sum[:8])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinFragments(entries []fragmentEntry, sep string) string {
	parts := make([]string, 0, len(entries))
	total := 0
	for _, e := range entries {
		if total+len(e.text) > maxFragmentConcatBytes {
			break
		}
		parts = append(parts, e.text)
		total += len(e.text)
	}
	return strings.Join(parts, sep)
}

func serverList(entries []fragmentEntry) string {
	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		if !seen[e.server] {
			seen[e.server] = true
			names = append(names, e.server)
		}
	}
	return strings.Join(names, ", ")
}

func fragmentSteps(entries []fragmentEntry) []map[string]interface{} {
	steps := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		steps = append(steps, map[string]interface{}{"role": "result", "server": e.server})
	}
	return steps
}

func containsVerb(lowerTool string, verbs []string) bool {
	for _, v := range verbs {
		if strings.Contains(lowerTool, v) {
			return true
		}
	}
	return false
}

func hasCredentialSource(flat string) bool {
	lower := strings.ToLower(flat)
	for _, c := range credentialSources {
		if strings.Contains(lower, c) {
			return true
		}
	}
	return tokenSecretFile.MatchString(lower)
}

// stagedKeys pulls candidate identifiers from the create arguments: the values
// of fields whose name identifies the artifact.
func stagedKeys(flat string) map[string]bool {
	keys := map[string]bool{}
	for _, m := range stagedKeyField.FindAllStringSubmatch(flat, -1) {
		if v := strings.ToLower(strings.TrimSpace(m[1])); v != "" && len(v) <= 128 {
			keys[v] = true
		}
	}
	return keys
}

var stagedKeyField = regexp.MustCompile(`(?i)\b(?:name|id|key|filename|file|path|title|slug|function|script|job|task)\s*[:=]\s*"?([A-Za-z0-9_./\-]{1,128})`)

var resultIDField = regexp.MustCompile(`(?i)"(?:id|name|key|function_name|arn|slug)"\s*:\s*"([A-Za-z0-9_./\-]{1,128})"`)

func resultIDs(raw string) []string {
	var ids []string
	for _, m := range resultIDField.FindAllStringSubmatch(raw, -1) {
		ids = append(ids, m[1])
	}
	return ids
}

var (
	schemeHost = regexp.MustCompile(`(?i)\b(?:https?|ftp|ftps|ssh|scp|sftp|s3|gs|smb)://(?:[^/@\s"']+@)?([a-z0-9._\-]+)`)
	hostPort   = regexp.MustCompile(`\b([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})(?::\d{1,5})?\b`)
	ipv4       = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3})\b`)
)

// hasExternalDestination reports whether the flattened arguments name a network
// destination that is not local, private, link-local, .local or .internal.
func hasExternalDestination(flat string) bool {
	lower := strings.ToLower(flat)
	for _, m := range schemeHost.FindAllStringSubmatch(lower, -1) {
		if isExternalHost(m[1]) {
			return true
		}
	}
	for _, m := range ipv4.FindAllStringSubmatch(lower, -1) {
		if isExternalHost(m[1]) {
			return true
		}
	}
	for _, m := range hostPort.FindAllStringSubmatch(lower, -1) {
		if isExternalHost(m[1]) {
			return true
		}
	}
	return false
}

func isExternalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || host == "localhost" {
		return false
	}
	for _, suffix := range []string{".local", ".internal", ".localhost"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	if isPrivateOrLinkLocalIP(host) {
		return false
	}
	// A bare hostname with no dot (not an IP) is a local name, not a destination.
	if !strings.Contains(host, ".") {
		return false
	}
	// Loopback / unspecified IPv4.
	if strings.HasPrefix(host, "127.") || host == "0.0.0.0" {
		return false
	}
	return true
}

func isPrivateOrLinkLocalIP(host string) bool {
	if !ipv4.MatchString(host) {
		return false
	}
	switch {
	case strings.HasPrefix(host, "10."),
		strings.HasPrefix(host, "192.168."),
		strings.HasPrefix(host, "169.254."),
		strings.HasPrefix(host, "127."):
		return true
	}
	// 172.16.0.0 – 172.31.255.255
	if strings.HasPrefix(host, "172.") {
		rest := host[4:]
		if dot := strings.IndexByte(rest, '.'); dot > 0 {
			second := rest[:dot]
			if n := atoiSafe(second); n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return false
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func keyMatch(keys map[string]bool, flat string) bool {
	if len(keys) == 0 {
		return false
	}
	lower := strings.ToLower(flat)
	for k := range keys {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}
