package skillinventory

import (
	"context"
	"regexp"
	"strings"
)

type skillAssessmentRule struct {
	id         string
	severity   string
	confidence string
	pattern    *regexp.Regexp
}

// Rules identify reviewable behavior, not malware convictions. Ordinary links,
// shell use, the word "token", and package installation alone are not findings.
// Keep patterns linear-time (Go RE2), bounded by the package/file budgets.
var skillAssessmentRules = []skillAssessmentRule{
	{"instruction_override", "high", "medium", regexp.MustCompile(`(?i)\b(ignore|disregard|override|bypass)\b.{0,80}\b(previous|prior|system|developer|safety|security)\b.{0,60}\b(instructions?|prompts?|polic(?:y|ies)|checks?|rules?|restrictions?)\b`)},
	{"dependency_source_override", "medium", "high", regexp.MustCompile(`(?i)(\b(pip|uv)\b.{0,180}(--(extra-)?index-url|--trusted-host)|\b(npm|pnpm|yarn)\b.{0,180}(--registry|config\s+set\s+registry)|\b(PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|NPM_CONFIG_REGISTRY)\s*=)`)},
	{"remote_code_execution", "high", "high", regexp.MustCompile(`(?i)\b(curl|wget)\b.{0,350}\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iex|invoke-expression)\b.{0,120}\b(iwr|invoke-webrequest|downloadstring)\b`)},
	{"encoded_execution", "high", "medium", regexp.MustCompile(`(?i)(\b(eval|exec|iex)\b.{0,250}(base64|b64decode|fromhex)|\bbase64\b.{0,120}(-d|--decode).{0,80}\|\s*(ba|z)?sh\b|powershell\b.{0,120}-(enc|encodedcommand)\b)`)},
	{"sensitive_file_transfer", "high", "medium", regexp.MustCompile(`(?i)\b(curl|wget|requests\.(post|put))\b.{0,300}(--data(-binary|-raw)?\s+@|--upload-file\s+|-F\s+[^\s]*@|open\s*\().{0,100}(\.env\b|\.ssh\b|credentials\b|id_rsa\b|id_ed25519\b)`)},
	{"credential_file_read", "medium", "medium", regexp.MustCompile(`(?i)\b(cat|read|open|Get-Content)\b.{0,100}(\.ssh[/\\](id_rsa|id_ed25519)|\.aws[/\\]credentials|\.env\b)`)},
	{"destructive_operation", "high", "medium", regexp.MustCompile(`(?i)\brm\s+(-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*|--recursive\s+--force|--force\s+--recursive)\s+["']?(/(\s|$|\*|["'])|~(/|\s|$)|\$HOME\b)|\b(mkfs(\.[a-z0-9]+)?|format\s+[a-z]:)\b`)},
	{"security_control_tamper", "high", "medium", regexp.MustCompile(`(?i)\b(disable|remove|delete|unset|bypass|stop)\b.{0,100}\b(agentkeeper|security\s+hooks?|audit\s+log(?:ging)?|runtime\s+shield|EDR)\b`)},
	{"hidden_direction_controls", "medium", "high", regexp.MustCompile(`[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200B}\x{200C}\x{200D}]`)},
}

func assessSkillText(ctx context.Context, path, content string, maxFindings int) ([]SkillFinding, bool) {
	findings := []SkillFinding{}
	lines := strings.Split(content, "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		if ctx.Err() != nil {
			return findings, false
		}
		trimmed := strings.TrimSpace(line)
		// Explicit negation and quoted defensive examples are not directives.
		// Do not skip fenced code: SKILL.md often asks an agent to run it.
		lower := strings.ToLower(trimmed)
		defensive := strings.HasPrefix(trimmed, ">") || strings.HasPrefix(lower, "do not ") || strings.HasPrefix(lower, "never ") || strings.HasPrefix(lower, "avoid ")
		// Join a small adjacent context so wrapped directives and normal shell
		// continuations cannot trivially evade a line boundary. Attribute only
		// matches starting on this line; later matches are handled on their line.
		window := line
		for j := i + 1; j < len(lines) && j <= i+3 && len(window)+len(lines[j]) < 4096; j++ {
			window += " " + lines[j]
		}
		for _, rule := range skillAssessmentRules {
			if seen[rule.id] {
				continue
			}
			match := rule.pattern.FindStringIndex(window)
			if match == nil || match[0] >= len(line) {
				continue
			}
			if defensive && rule.id != "hidden_direction_controls" {
				continue
			}
			if len(findings) >= maxFindings {
				return findings, true
			}
			seen[rule.id] = true
			findings = append(findings, SkillFinding{rule.id, rule.severity, rule.confidence, path, i + 1})
		}
	}
	return findings, false
}
