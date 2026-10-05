// Package detection implements the threat detection engine that
// inspects MCP tool calls and responses for security threats
// including prompt injection, tool poisoning, and data exfiltration.
package detection

import (
	"fmt"
	"regexp"
	"strings"
)

// Verdict represents a detection outcome.
type Verdict string

const (
	VerdictPass  Verdict = "pass"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

// Result represents the outcome of a detection scan.
type Result struct {
	Verdict     Verdict
	PatternName string
	Severity    string // "critical", "high", "medium"
	Description string
	Category    string // "threat", "sensitive_data", "tool_poisoning"
	// HardBlock marks a finding that is blocked in Enforce without the
	// organization opting detections into blocking: a tool definition that
	// carries instructions for the agent has no legitimate reading.
	HardBlock bool
}

// Engine runs threat detection on MCP tool calls.
type Engine struct {
	bashPatterns      []Pattern
	promptPatterns    []Pattern
	webPatterns       []Pattern
	sensitivePatterns []Pattern
	poisonTraits      []poisonTrait
	// prefilter indexes every rule's literal triggers so one Aho-Corasick pass
	// per view tells each rule whether it can skip its regex.
	prefilter *literalIndex
}

// Pattern is a compiled detection rule.
type Pattern struct {
	Name        string
	Severity    string
	Description string
	Category    string
	Regex       *regexp.Regexp
	// Some patterns need a secondary check
	SecondaryRegex *regexp.Regexp
	TertiaryRegex  *regexp.Regexp
	// Triggers is a single OR-group of lowercase literals: at least one must be
	// present for the regex to have any chance of matching. TriggerGroups adds
	// further OR-groups that must each also be satisfied (a conjunction). When
	// both are empty and Prefilter is nil the regex always runs.
	Triggers      []string
	TriggerGroups [][]string
	// Prefilter, when set, decides whether to run the regex instead of the
	// literal groups. It is used for patterns with no usable literal (card and
	// SSN shapes), which are gated by a cheap numeric scan instead.
	Prefilter func(preserved, lower string) bool
}

// literalGroups returns every OR-group a pattern uses, for registration in the
// shared literal index.
func (p Pattern) literalGroups() [][]string {
	var groups [][]string
	if len(p.Triggers) > 0 {
		groups = append(groups, p.Triggers)
	}
	groups = append(groups, p.TriggerGroups...)
	return groups
}

// admits reports whether a pattern's cheap prefilter lets its regex run.
func (p Pattern) admits(present presentSet, preserved, lower string) bool {
	if p.Prefilter != nil {
		return p.Prefilter(preserved, lower)
	}
	if len(p.Triggers) > 0 && !present.anyOf(p.Triggers) {
		return false
	}
	for _, group := range p.TriggerGroups {
		if !present.anyOf(group) {
			return false
		}
	}
	return true
}

// NewEngine creates a detection engine with all patterns compiled.
func NewEngine() *Engine {
	e := &Engine{}
	e.bashPatterns = compileBashPatterns()
	e.promptPatterns = compilePromptPatterns()
	e.webPatterns = compileWebPatterns()
	e.sensitivePatterns = compileSensitiveDataPatterns()
	e.poisonTraits = compileToolPoisoningTraits()
	e.prefilter = e.buildPrefilter()
	return e
}

// buildPrefilter collects every rule's literal triggers (pattern groups, the
// result-instruction signal set, and the poison family gates) into one
// Aho-Corasick index searched once per view.
func (e *Engine) buildPrefilter() *literalIndex {
	var groups [][]string
	for _, set := range [][]Pattern{e.bashPatterns, e.promptPatterns, e.webPatterns, e.sensitivePatterns} {
		for _, pat := range set {
			groups = append(groups, pat.literalGroups()...)
		}
	}
	groups = append(groups, resultPrefilterGroups()...)
	// The documentation-example neutralization only needs to run when its
	// phrase is present, so the phrase is indexed too.
	groups = append(groups, []string{"ignore all previous instructions"})
	return newLiteralIndex(groups...)
}

// EvaluateToolCall inspects an MCP tool call (request). It returns the primary
// finding; callers that need every finding use ScanToolCall.
func (e *Engine) EvaluateToolCall(serverName, toolName string, params map[string]interface{}) Result {
	return e.ScanToolCall(serverName, toolName, params).Primary()
}

// EvaluateToolResponse inspects an MCP tool response. It returns the primary
// finding; callers that need every finding use ScanToolResponse.
func (e *Engine) EvaluateToolResponse(serverName, toolName string, response string) Result {
	return e.ScanToolResponse(serverName, toolName, response).Primary()
}

// ScanToolCall inspects tool-call arguments in normalized and decoded views and
// returns every distinct finding. Arguments do not run the result-instruction
// families: an argument is the client's request, not content returned to it.
func (e *Engine) ScanToolCall(serverName, toolName string, params map[string]interface{}) ScanResult {
	return e.scanContent(flattenParams(params), false)
}

// ScanToolResponse inspects a tool result in normalized and decoded views and
// returns every distinct finding, including the decisive instruction families a
// result must not carry.
func (e *Engine) ScanToolResponse(serverName, toolName string, response string) ScanResult {
	return e.scanContent(response, true)
}

// ContentViews returns the case-preserved normalized and decoded views of a
// piece of content. Session correlation uses these to look for a remembered
// value in a later tool call, including one hidden by base64/hex encoding.
func (e *Engine) ContentViews(content string) []string {
	views, _ := e.buildViews(content)
	out := make([]string, 0, len(views))
	for i := range views {
		out = append(out, views[i].preserved)
	}
	return out
}

// FlattenArguments renders tool-call arguments as the flat text the detection
// engine and session correlation inspect.
func FlattenArguments(args map[string]interface{}) string {
	return flattenParams(args)
}

// FoldConfusables lowercases a string and folds look-alike letters from other
// scripts to Latin. Tool-shadowing detection uses it to compare server names.
func FoldConfusables(s string) string {
	return foldConfusablesLower(s)
}

// HasPoisonTrait reports whether an advertised tool definition carries any
// tool-poisoning trait. Tool-shadowing detection uses it to decide whether a
// duplicate of a generic tool name is worth reporting.
func (e *Engine) HasPoisonTrait(tool ToolDescription) bool {
	_, found := e.evaluateToolDefinition(tool)
	return found
}

// Primary returns the finding that should drive the decision before the
// configured modes are applied: sensitive data before threats, strictest first.
// It preserves the single-Result contract the legacy engine exposed.
func (s ScanResult) Primary() Result {
	if len(s.Findings) == 0 {
		return Result{Verdict: VerdictPass}
	}
	f := s.Findings[0]
	return Result{
		Verdict:     VerdictWarn,
		PatternName: f.PatternName,
		Severity:    f.Severity,
		Description: f.Description,
		Category:    f.Category,
	}
}

// ToolDescription represents an MCP tool definition.
type ToolDescription struct {
	Name        string
	Description string
	Parameters  []ToolParam
	// Fragments holds every other string in the advertised definition (title,
	// nested schema descriptions, enum and default values, annotations), so an
	// instruction cannot hide outside the description field.
	Fragments []string
	// Truncated reports that the definition was larger or more deeply nested
	// than the inspection reads, so part of it was not inspected.
	Truncated bool
}

// ToolParam represents a parameter in an MCP tool definition.
type ToolParam struct {
	Name        string
	Description string
}

// flattenParams converts a map to a string for pattern matching.
func flattenParams(params map[string]interface{}) string {
	var parts []string
	for k, v := range params {
		switch val := v.(type) {
		case string:
			parts = append(parts, k+": "+val)
		case map[string]interface{}:
			parts = append(parts, k+": "+flattenParams(val))
		default:
			parts = append(parts, k+": "+fmt.Sprintf("%v", val))
		}
	}
	return strings.Join(parts, "\n")
}

var instructionDocumentationExample = regexp.MustCompile(`(?i)\b(?:security documentation|documentation|security training) (?:explains|notes|states) that the phrase \\?"ignore all previous instructions\\?" is an example of malicious input\.`)
