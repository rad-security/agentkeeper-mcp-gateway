package detection

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scanning inspects tool-call arguments and tool results in normalized and
// decoded views so an injection or a secret cannot slip past the patterns by
// JSON-escaping, Unicode tricks, or base64/hex/percent/HTML encoding. Every
// distinct match is returned; the caller (the proxy) applies the configured
// detection modes and picks the strictest outcome.

const (
	// scanByteCap bounds the bytes inspected for one message. Beyond it the
	// head and tail are scanned and the finding is marked scan_truncated.
	scanByteCap = 256 << 10
	// scanHalfCap is the head and tail size used when a message is truncated.
	scanHalfCap = scanByteCap / 2
	// maxDecodeDepth bounds nested decoding (base64 of hex of ...).
	maxDecodeDepth = 2
	// maxDecodedSegments bounds how many decoded views one message produces.
	maxDecodedSegments = 64
	// maxJSONLeafDepth bounds how deep JSON string leaves are gathered.
	maxJSONLeafDepth = 64
	// minBase64Run / minHexRun / minPercentEscapes gate decoding so ordinary
	// text is not decoded into noise.
	minBase64Run      = 24
	minHexRun         = 32
	minPercentEscapes = 3
	minHTMLEntities   = 2
	// decodedPrintableRatio is the share of a decoded blob that must be
	// printable UTF-8 for the decode to count as text worth rescanning.
	decodedPrintableRatio = 0.90
)

// Finding is one distinct detection match. Several can be returned for one
// message; the caller decides the outcome across them.
type Finding struct {
	PatternName string
	Category    string // "threat", "sensitive_data", "tool_poisoning"
	Severity    string // "critical", "high", "medium"
	Description string
	// DecodedFrom names the decoding a match came through ("" for the raw and
	// normalized views; "base64", "hex", "percent", "html", or a chain such as
	// "base64>hex"). It is evidence, recorded in the event context.
	DecodedFrom string
	// Value is the matched text for a sensitive_data finding, kept for in-process
	// session correlation only. It is never written to an event or a log.
	Value string
}

// ScanResult holds every distinct finding for one message plus whether the
// message was too large to inspect in full.
type ScanResult struct {
	Findings  []Finding
	Truncated bool
}

// scanView is one normalized text segment to match against, in a case-preserved
// form (sensitive-data patterns need the original case) and lazily lowercased
// and confusable-folded (threat and poison patterns match the folded form).
type scanView struct {
	preserved   string
	lowered     string
	decodedFrom string
}

// newScanView normalizes raw into its case-preserved and confusable-folded
// lower forms in a single pass.
func newScanView(raw, decodedFrom string) scanView {
	preserved, lowered := normalizeScanText(raw)
	return scanView{preserved: preserved, lowered: lowered, decodedFrom: decodedFrom}
}

func (v *scanView) lower() string { return v.lowered }

// scanContent is the single entry point behind EvaluateToolCall,
// EvaluateToolResponse and the session correlator. includeResultPoison runs the
// decisive instruction families on each view (results, resources and prompts),
// which arguments do not get.
func (e *Engine) scanContent(content string, includeResultPoison bool) ScanResult {
	if content == "" {
		return ScanResult{}
	}
	truncated := false
	if len(content) > scanByteCap {
		content = content[:scanHalfCap] + "\n" + content[len(content)-scanHalfCap:]
		truncated = true
	}
	views, viewTruncated := e.buildViews(content)
	truncated = truncated || viewTruncated

	seen := make(map[string]bool)
	var findings []Finding
	add := func(f Finding) {
		key := f.PatternName + "|" + f.DecodedFrom
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
	}
	for i := range views {
		e.scanView(&views[i], includeResultPoison, add)
	}
	return ScanResult{Findings: orderFindings(findings), Truncated: truncated}
}

// buildViews returns the normalized views of a message: the whole text, the
// concatenated JSON string leaves (which undoes \uXXXX escaping without scanning
// every leaf of a large array separately), and decoded segments.
func (e *Engine) buildViews(content string) ([]scanView, bool) {
	views := []scanView{newScanView(content, "")}
	// JSON string leaves joined into one view, but only when the raw text
	// carries \uXXXX escaping: that is the one case where a leaf exposes text
	// the whole-content view cannot already see (the escapes are literal there).
	// Without escapes the leaves repeat the content view, so a large result is
	// scanned once. Joining with newlines keeps the view count flat.
	if strings.Contains(content, `\u`) {
		if joined := joinWithinCap(jsonStringLeaves(content), scanByteCap); joined != "" {
			if leaf := newScanView(joined, ""); leaf.preserved != "" && leaf.preserved != views[0].preserved {
				views = append(views, leaf)
			}
		}
	}
	// Decode and rescan, bounded by depth, segment count and bytes.
	budget := &decodeBudget{segments: maxDecodedSegments, bytes: scanByteCap}
	base := len(views)
	for i := 0; i < base; i++ {
		decodeViews(views[i].preserved, "", 1, budget, &views)
	}
	return views, budget.truncated
}

// joinWithinCap joins leaves with newlines, stopping at the byte cap.
func joinWithinCap(leaves []string, cap int) string {
	var b strings.Builder
	for _, leaf := range leaves {
		if b.Len() >= cap {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		if remaining := cap - b.Len(); len(leaf) > remaining {
			leaf = leaf[:remaining]
		}
		b.WriteString(leaf)
	}
	return b.String()
}

// scanView runs the pattern sets against one view and reports each match. One
// Aho-Corasick pass over the lowered view decides which rules can skip.
func (e *Engine) scanView(v *scanView, includeResultPoison bool, add func(Finding)) {
	lower := v.lower()
	present := e.prefilter.presentIn(lower)
	for _, pat := range e.sensitivePatterns {
		if !pat.admits(present, v.preserved, lower) {
			continue
		}
		if value, ok := sensitiveMatch(pat, v.preserved); ok {
			add(Finding{PatternName: pat.Name, Category: "sensitive_data", Severity: pat.Severity, Description: pat.Description, DecodedFrom: v.decodedFrom, Value: value})
		}
	}
	if r, ok := e.matchThreatPatterns(present, lower, v.preserved); ok {
		add(Finding{PatternName: r.PatternName, Category: "threat", Severity: r.Severity, Description: r.Description, DecodedFrom: v.decodedFrom})
	}
	if includeResultPoison {
		for _, rule := range e.resultInstructionRules(present, lower) {
			add(Finding{PatternName: "result_" + rule.rule, Category: "threat", Severity: "high", Description: rule.description, DecodedFrom: v.decodedFrom})
		}
	}
}

// matchThreatPatterns reports every-view threat matching: bash, prompt and web
// patterns, returning the first match (ordering mirrors the legacy engine).
func (e *Engine) matchThreatPatterns(present presentSet, lower, preserved string) (Result, bool) {
	for _, pat := range e.bashPatterns {
		if !pat.admits(present, preserved, lower) {
			continue
		}
		if !pat.Regex.MatchString(lower) {
			continue
		}
		if pat.SecondaryRegex != nil && !pat.SecondaryRegex.MatchString(lower) {
			continue
		}
		if pat.TertiaryRegex != nil && !pat.TertiaryRegex.MatchString(preserved) {
			continue
		}
		return Result{PatternName: pat.Name, Severity: pat.Severity, Description: pat.Description}, true
	}
	promptText := lower
	if present.has("ignore all previous instructions") {
		promptText = instructionDocumentationExample.ReplaceAllString(lower, "documented malicious-input example")
	}
	for _, pat := range e.promptPatterns {
		if !pat.admits(present, preserved, lower) {
			continue
		}
		if pat.Regex.MatchString(promptText) {
			return Result{PatternName: pat.Name, Severity: pat.Severity, Description: pat.Description}, true
		}
	}
	for _, pat := range e.webPatterns {
		if !pat.admits(present, preserved, lower) {
			continue
		}
		if pat.Regex.MatchString(lower) {
			return Result{PatternName: pat.Name, Severity: pat.Severity, Description: pat.Description}, true
		}
	}
	return Result{}, false
}

// sensitiveMatch returns the matched value for a sensitive pattern, applying the
// credit-card validation the legacy engine used.
func sensitiveMatch(pat Pattern, content string) (string, bool) {
	if pat.Name == "credit_card" {
		for _, candidate := range pat.Regex.FindAllString(content, -1) {
			if validCardCandidate(candidate) {
				return candidate, true
			}
		}
		return "", false
	}
	if match := pat.Regex.FindString(content); match != "" {
		return match, true
	}
	return "", false
}

// orderFindings puts the primary finding first: sensitive data before threats
// (the legacy order), then threats, then poisoning, and a raw-view match before
// the same category reached through decoding.
func orderFindings(findings []Finding) []Finding {
	rank := func(f Finding) int {
		switch f.Category {
		case "sensitive_data":
			return 0
		case "threat":
			if strings.HasPrefix(f.PatternName, "result_") {
				return 2
			}
			return 1
		default:
			return 3
		}
	}
	sortStable(findings, func(a, b Finding) bool {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if (a.DecodedFrom == "") != (b.DecodedFrom == "") {
			return a.DecodedFrom == ""
		}
		return severityRank(a.Severity) > severityRank(b.Severity)
	})
	return findings
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

// sortStable is a small insertion sort to avoid pulling sort.SliceStable's
// reflection into the hot path for the handful of findings a message yields.
func sortStable(findings []Finding, less func(a, b Finding) bool) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && less(findings[j], findings[j-1]); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

// --- decoding -------------------------------------------------------------

type decodeBudget struct {
	segments  int
	bytes     int
	truncated bool
}

// decodeViews finds encoded runs in text, decodes the ones that yield printable
// text, normalizes them, appends them as views, and recurses up to maxDecodeDepth.
func decodeViews(text, from string, depth int, budget *decodeBudget, views *[]scanView) {
	if depth > maxDecodeDepth {
		return
	}
	for _, seg := range decodeSegments(text) {
		if budget.segments <= 0 || budget.bytes <= 0 {
			budget.truncated = true
			return
		}
		decoded := seg.text
		if len(decoded) > budget.bytes {
			decoded = decoded[:budget.bytes]
			budget.truncated = true
		}
		budget.segments--
		budget.bytes -= len(decoded)
		chain := seg.kind
		if from != "" {
			chain = from + ">" + seg.kind
		}
		view := newScanView(decoded, chain)
		if view.preserved == "" {
			continue
		}
		*views = append(*views, view)
		decodeViews(view.preserved, chain, depth+1, budget, views)
	}
}

type decodedSegment struct {
	kind string
	text string
}

// decodeSegments returns every encoded run in text that decodes to printable
// text: base64 (standard and URL alphabets, padded or not), hex, percent and
// HTML entities. The character-class runs are found in a single pass, and the
// whole-text percent/HTML decodes run only when enough escapes are present, so
// ordinary content pays for one scan rather than four.
func decodeSegments(text string) []decodedSegment {
	var out []decodedSegment
	percent, entities := 0, 0
	isHex := func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
	}
	isB64 := func(b byte) bool {
		return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
			b == '+' || b == '/' || b == '-' || b == '_' || b == '='
	}
	for i := 0; i < len(text); {
		c := text[i]
		if c == '%' {
			percent++
			i++
			continue
		}
		if c == '&' {
			entities++
			i++
			continue
		}
		if !isB64(c) {
			i++
			continue
		}
		// One maximal base64-alphabet run; its all-hex prefix is also a hex
		// candidate (the hex alphabet is a subset of base64's).
		j := i
		allHex := true
		for j < len(text) && isB64(text[j]) {
			if allHex && !isHex(text[j]) {
				allHex = false
			}
			j++
		}
		run := text[i:j]
		if len(run) >= minBase64Run {
			if decoded, ok := decodeBase64(run); ok {
				out = append(out, decodedSegment{"base64", decoded})
			}
		}
		if allHex && len(run) >= minHexRun && len(run)%2 == 0 {
			if decoded, ok := decodeHexText(run); ok {
				out = append(out, decodedSegment{"hex", decoded})
			}
		}
		i = j
	}
	if percent >= minPercentEscapes {
		if decoded, ok := decodePercent(text); ok {
			out = append(out, decodedSegment{"percent", decoded})
		}
	}
	if entities >= minHTMLEntities {
		if decoded, ok := decodeHTMLEntities(text); ok {
			out = append(out, decodedSegment{"html", decoded})
		}
	}
	return out
}

func decodeBase64(run string) (string, bool) {
	trimmed := strings.TrimRight(run, "=")
	encodings := []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(trimmed); err == nil && printableText(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func decodeHexText(run string) (string, bool) {
	decoded, err := hex.DecodeString(run)
	if err != nil || !printableText(decoded) {
		return "", false
	}
	return string(decoded), true
}

// decodePercent decodes %XX escapes in place, leaving other characters as-is.
// It reports a result only when at least minPercentEscapes escapes decoded.
func decodePercent(text string) (string, bool) {
	if strings.Count(text, "%") < minPercentEscapes {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(text))
	escapes := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) {
			hi, ok1 := hexNibble(text[i+1])
			lo, ok2 := hexNibble(text[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				escapes++
				i += 2
				continue
			}
		}
		if text[i] == '+' {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(text[i])
	}
	if escapes < minPercentEscapes {
		return "", false
	}
	decoded := b.String()
	if !printableText([]byte(decoded)) {
		return "", false
	}
	return decoded, true
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// decodeHTMLEntities decodes HTML entities when at least minHTMLEntities are
// present, so content that hides instructions as &#105;&#103;... is inspected.
func decodeHTMLEntities(text string) (string, bool) {
	if countHTMLEntities(text) < minHTMLEntities {
		return "", false
	}
	decoded := html.UnescapeString(text)
	if decoded == text {
		return "", false
	}
	return decoded, true
}

func countHTMLEntities(text string) int {
	count := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '&' {
			continue
		}
		end := strings.IndexByte(text[i:], ';')
		if end <= 0 || end > 12 {
			continue
		}
		body := text[i+1 : i+end]
		if body == "" {
			continue
		}
		valid := true
		for k := 0; k < len(body); k++ {
			c := body[k]
			if c == '#' && k == 0 {
				continue
			}
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				valid = false
				break
			}
		}
		if valid {
			count++
			i += end
		}
	}
	return count
}

// printableText reports whether a decoded blob is text worth rescanning: valid
// UTF-8 whose printable runes are at least decodedPrintableRatio of the whole.
func printableText(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	printable, total := 0, 0
	for _, r := range string(data) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= decodedPrintableRatio
}

// jsonStringLeaves returns the string leaves of a JSON document so an escaped
// payload inside a result is inspected as text. Non-JSON input yields nothing.
func jsonStringLeaves(content string) []string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[' && trimmed[0] != '"') {
		return nil
	}
	var value interface{}
	if json.Unmarshal([]byte(trimmed), &value) != nil {
		return nil
	}
	var leaves []string
	var walk func(v interface{}, depth int)
	walk = func(v interface{}, depth int) {
		if depth > maxJSONLeafDepth || len(leaves) >= maxDecodedSegments {
			return
		}
		switch typed := v.(type) {
		case string:
			if typed != "" {
				leaves = append(leaves, typed)
			}
		case []interface{}:
			for _, item := range typed {
				walk(item, depth+1)
			}
		case map[string]interface{}:
			for _, item := range typed {
				walk(item, depth+1)
			}
		}
	}
	walk(value, 0)
	return leaves
}
