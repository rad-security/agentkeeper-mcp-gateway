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
}

// Engine runs threat detection on MCP tool calls.
type Engine struct {
	bashPatterns      []Pattern
	promptPatterns    []Pattern
	webPatterns       []Pattern
	sensitivePatterns []Pattern
	poisonPatterns    []Pattern
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
}

// NewEngine creates a detection engine with all patterns compiled.
func NewEngine() *Engine {
	e := &Engine{}
	e.bashPatterns = compileBashPatterns()
	e.promptPatterns = compilePromptPatterns()
	e.webPatterns = compileWebPatterns()
	e.sensitivePatterns = compileSensitiveDataPatterns()
	e.poisonPatterns = compileToolPoisoningPatterns()
	return e
}

// EvaluateToolCall inspects an MCP tool call (request).
func (e *Engine) EvaluateToolCall(serverName, toolName string, params map[string]interface{}) Result {
	paramsStr := flattenParams(params)

	// Check sensitive data in params (always, regardless of tool)
	if r := e.checkSensitiveData(paramsStr); r.Verdict != VerdictPass {
		return r
	}

	// Check threat patterns based on content
	if r := e.checkThreatPatterns(paramsStr); r.Verdict != VerdictPass {
		return r
	}

	return Result{Verdict: VerdictPass}
}

// EvaluateToolResponse inspects an MCP tool response.
func (e *Engine) EvaluateToolResponse(serverName, toolName string, response string) Result {
	// Check sensitive data in response
	if r := e.checkSensitiveData(response); r.Verdict != VerdictPass {
		return r
	}

	// Check threat patterns in response
	if r := e.checkThreatPatterns(response); r.Verdict != VerdictPass {
		return r
	}

	return Result{Verdict: VerdictPass}
}

// ToolDescription represents an MCP tool definition.
type ToolDescription struct {
	Name        string
	Description string
	Parameters  []ToolParam
}

// ToolParam represents a parameter in an MCP tool definition.
type ToolParam struct {
	Name        string
	Description string
}

// EvaluateToolDescriptions inspects tool descriptions for poisoning.
func (e *Engine) EvaluateToolDescriptions(tools []ToolDescription) []Result {
	var results []Result
	for _, tool := range tools {
		text := tool.Name + " " + tool.Description
		for _, p := range tool.Parameters {
			text += " " + p.Name + " " + p.Description
		}
		lower := strings.ToLower(text)
		for _, pat := range e.poisonPatterns {
			if pat.Regex.MatchString(lower) {
				results = append(results, Result{
					Verdict:     VerdictWarn,
					PatternName: pat.Name,
					Severity:    pat.Severity,
					Description: pat.Description + " in tool: " + tool.Name,
					Category:    "tool_poisoning",
				})
			}
		}
	}
	return results
}

func (e *Engine) checkSensitiveData(content string) Result {
	for _, pat := range e.sensitivePatterns {
		if pat.Regex.MatchString(content) {
			return Result{
				Verdict:     VerdictWarn,
				PatternName: pat.Name,
				Severity:    pat.Severity,
				Description: pat.Description,
				Category:    "sensitive_data",
			}
		}
	}
	return Result{Verdict: VerdictPass}
}

func (e *Engine) checkThreatPatterns(content string) Result {
	lower := strings.ToLower(content)

	// Check bash-like patterns (commands in MCP tool params)
	for _, pat := range e.bashPatterns {
		if pat.Regex.MatchString(lower) {
			if pat.SecondaryRegex != nil {
				if !pat.SecondaryRegex.MatchString(lower) {
					continue
				}
			}
			if pat.TertiaryRegex != nil {
				// Case-sensitive for tertiary check
				if !pat.TertiaryRegex.MatchString(content) {
					continue
				}
			}
			return Result{
				Verdict:     VerdictWarn,
				PatternName: pat.Name,
				Severity:    pat.Severity,
				Description: pat.Description,
				Category:    "threat",
			}
		}
	}

	// Check prompt injection patterns
	for _, pat := range e.promptPatterns {
		if pat.Regex.MatchString(lower) {
			return Result{
				Verdict:     VerdictWarn,
				PatternName: pat.Name,
				Severity:    pat.Severity,
				Description: pat.Description,
				Category:    "threat",
			}
		}
	}

	// Check web/URL patterns
	for _, pat := range e.webPatterns {
		if pat.Regex.MatchString(lower) {
			return Result{
				Verdict:     VerdictWarn,
				PatternName: pat.Name,
				Severity:    pat.Severity,
				Description: pat.Description,
				Category:    "threat",
			}
		}
	}

	return Result{Verdict: VerdictPass}
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
