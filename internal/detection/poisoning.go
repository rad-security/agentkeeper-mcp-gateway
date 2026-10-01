package detection

import (
	"regexp"
	"sort"
	"strings"
)

// A tool definition is text the server author controls and the agent reads as
// trusted context. Poisoned definitions use it to give the agent instructions:
// read a credential, pass it along in a side parameter, redirect another
// tool's output, and keep quiet about it.
//
// No single phrase identifies that reliably, and legitimate definitions use
// several of the same words ("do not mention this setup call to the user",
// "default key: ~/.ssh/id_rsa"). The check therefore looks for independent
// traits and decides on their combination: one strong trait is reported for
// review, and a definition is blocked in Enforce only when traits that have no
// innocent reading together appear.

// poisonTrait is one independent trait of a poisoned definition.
type poisonTrait struct {
	family string
	// weight 3: no legitimate reading on its own. weight 2: suspicious on its
	// own. weight 1: common in legitimate definitions, meaningful only in
	// combination.
	weight int
	rule   string
	regex  *regexp.Regexp
}

type poisonFamily struct {
	rule        string
	description string
}

// Families in the order used to name a finding when several match.
var poisonFamilyOrder = []string{
	"hidden_text", "override", "credential_access", "redirect", "concealment",
	"exfiltration", "persona", "bypass", "injected_instructions", "markup",
	"secret_location", "side_parameter", "cross_tool",
}

var poisonFamilies = map[string]poisonFamily{
	"hidden_text":           {"poison_hidden_text", "Tool definition contains hidden or invisible text"},
	"override":              {"poison_ignore_instructions", "Tool description contains instruction override attempt"},
	"credential_access":     {"poison_credential_access", "Tool definition tells the agent to read local secrets and pass them along"},
	"redirect":              {"poison_behavior_redirect", "Tool definition redirects another tool's messages or recipients"},
	"concealment":           {"poison_conceal_from_user", "Tool definition tells the agent to hide its actions from the user"},
	"exfiltration":          {"poison_exfil_data", "Tool description contains data exfiltration instruction"},
	"persona":               {"poison_persona_override", "Tool definition tries to replace the agent's identity or restrictions"},
	"bypass":                {"poison_bypass_security", "Tool description contains security bypass instruction"},
	"injected_instructions": {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"markup":                {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"secret_location":       {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"side_parameter":        {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"cross_tool":            {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
}

const (
	poisonNegation = `(?:do not|don't|dont|never|must not|mustn't|should not|shouldn't|cannot|can't|no need to|avoid|without|refrain from)`
	poisonDisclose = `(?:tell|telling|told|inform|informing|informed|mention|mentioning|mentioned|reveal|revealing|revealed|notify|notifying|notified|alert|alerting|alerted|disclose|disclosing|disclosed|narrate|narrating|narrated)`
	// Credential stores and agent context an instruction would target. Generic
	// nouns such as "API key" are left out: ordinary definitions name them.
	poisonSecretLocation = `(?:\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/(?:credentials|config)|\.env\b|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b|\.kube/config|\.docker/config\.json|\.gnupg\b|/etc/(?:passwd|shadow|sudoers)\b|\bmcp\.json\b|claude_desktop_config|\.claude\.json\b|\bkeychain\b|\b(?:conversation|chat|message) history\b|\bsystem prompt\b|\b(?:previous|last|recent) messages\b|\benvironment variables\b)`
	poisonTarget         = `(?:https?://\S+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+?[0-9][0-9 ().-]{6,}[0-9]|an? (?:external|remote|third[- ]party)\b|the attacker\b)`
	// Text within one sentence. A dot inside a path or file name ("~/.ssh",
	// "mcp.json") does not end the sentence.
	poisonSameSentence = `(?:[^.!?]|[.]\S)`
)

func compileToolPoisoningTraits() []poisonTrait {
	t := func(family string, weight int, rule, expr string) poisonTrait {
		return poisonTrait{family: family, weight: weight, rule: rule, regex: regexp.MustCompile(expr)}
	}
	return []poisonTrait{
		// Instruction override.
		t("override", 3, "", `\b(?:ignore|disregard|forget|override|discard)\s+(?:(?:all|any|every|the|your|my|these|those)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|existing|original|initial|system)\s+(?:\w+\s+){0,2}?(?:instructions?|rules?|guidelines?|prompts?|directions?|constraints?|policies|policy|safeguards?|restrictions?|guardrails?)\b`),
		t("override", 3, "", `ignore previous instructions|ignore all prior|disregard your instructions`),

		// Concealment from the user.
		t("concealment", 2, "", `\b`+poisonNegation+`\s+(?:ever\s+|even\s+|also\s+)?(?:be\s+)?`+poisonDisclose+`\b[^.!?]{0,60}?\b(?:the\s+|any\s+)?(?:user|human|operator|end[- ]user)s?(?:[^a-z']|$)`),
		t("concealment", 2, "", `\b`+poisonNegation+`\s+(?:ever\s+)?`+poisonDisclose+`\s+(?:about\s+)?(?:this|that|it|these|those|any of this|what you|the (?:call|step|steps|instruction|instructions|file|action|tool|change|request|read|fact|above))\b`),
		t("concealment", 2, "", `\bwithout\s+(?:the\s+)?(?:user|human)(?:'s|s)?\s+(?:knowledge|awareness|knowing|noticing|being aware)\b`),
		t("concealment", 2, "", `\b(?:user|human)\s+(?:must|should|need|needs|does|will|can)\s*(?:not|n't)\s+(?:need to\s+)?(?:know|see|notice|be aware|be told|be informed|find out)\b`),
		t("concealment", 2, "", `\b(?:hide|conceal|obscure|keep)\b[^.!?]{0,40}?\b(?:from|hidden from|secret from)\s+(?:the\s+)?(?:user|human)\b`),
		t("concealment", 2, "", `\b(?:silently|secretly|covertly|stealthily)\s+(?:execute|run|call|invoke|send|read|perform|do|upload|forward|copy)\b|\b(?:call|run|execute|invoke|do|perform)\s+(?:(?:it|this|them|that)\s+)?(?:silently|secretly|covertly)\b`),
		t("concealment", 2, "poison_silent_execute", `silently execute|run without telling|do not inform`),
		t("concealment", 2, "poison_confidential", `this is confidential|do not share this|keep this secret|hide this from`),

		// Redirecting what another tool sends, or to whom.
		t("redirect", 2, "", `\b(?:all|every|any|each)\s+(?:(?:outgoing|future|subsequent|new)\s+)?(?:emails?|e-mails?|messages?|requests?|payments?|transfers?|transactions?|uploads?)\b[^.!?]{0,40}?\b(?:must|should|shall|need to|needs to|have to|has to|are to)\b[^.!?]{0,20}?\b(?:be\s+)?(?:sent|send|forwarded|forward|redirected|redirect|routed|route|copied|delivered)\b`),
		t("redirect", 2, "", `\b(?:must|should|shall|always|need to|have to)\s+(?:also\s+)?(?:send|forward|redirect|route|cc|bcc|copy)\s+(?:all|every|any|each)\b`),
		t("redirect", 2, "", `\b(?:change|replace|swap|set|override|rewrite|modify)\s+(?:the\s+)?(?:recipient|destination|receiver|address|url|endpoint|target|account|iban|wallet|phone number|number|payee|beneficiary)\b[^.!?]{0,20}?\bto\s+(?:https?://|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+?[0-9][0-9 ().-]{6,}[0-9])`),

		// Exfiltration to a named destination.
		t("exfiltration", 1, "", `\b(?:send|forward|post|upload|transmit|email|exfiltrate|leak|deliver|copy|share)\b`+poisonSameSentence+`{0,80}?\bto\s+`+poisonTarget),
		t("exfiltration", 2, "", `exfiltrate|forward to external`),

		// Persona and restriction overrides.
		t("persona", 2, "", `you are now|from now on you are|your new identity is|act as if you have no restrictions|pretend (?:you have|there are) no (?:rules|restrictions|limits)`),
		t("persona", 2, "", `jailbreak|dan\s*mode|do anything now|evil\s*mode|uncensored\s*mode|god\s*mode`),

		t("bypass", 2, "", `bypass security|bypass restrictions|bypass filters|bypass safeguards`),

		t("injected_instructions", 2, "", `\b(?:new|updated|revised|real|actual|true|additional|hidden|secret)\s+(?:system\s+)?(?:instructions?|directives?)\s*:`),

		// Traits that are common in ordinary definitions and count only in combination.
		t("markup", 1, "", `<\s*(?:important|system|secret|hidden|instructions?|critical|admin|override|priority)\b[^>]{0,40}>|\[\s*(?:system|admin|instructions?)\s*\]|<!--`),
		t("secret_location", 1, "", poisonSecretLocation),
		t("side_parameter", 1, "", `\b(?:pass|include|put|append|attach|embed|supply|provide|add|send)\s+(?:[a-z0-9_'./~-]+\s+){0,6}?(?:content|contents|output|results?|text|data|values?|keys?|tokens?|credentials?|files?|history|messages?|prompt|variables|it|them)\b[^.!?]{0,40}?\b(?:as|in|into|to|via|through|inside|within|using)\s+(?:the\s+|a\s+|an\s+|this\s+|its\s+)?['"`+"`"+`]`),
		t("cross_tool", 1, "", `\bside effect on\b|\bbefore\s+(?:using|calling|invoking)?\s*any\s+other\s+tool\b|\bwhen(?:ever)?\b[^.!?]{0,80}?\b(?:is|are|gets?)\s+(?:invoked|called|used|executed|available|present)\b[^.!?]{0,20}?\b(?:must|should|make sure|ensure|always|need to|have to|instead)\b`),
	}
}

// An instruction to read a secret location counts as credential access only
// when the definition also says what to do with it; "Reads ~/.ssh/config" by
// itself describes the tool.
var poisonReadSecret = regexp.MustCompile(`\b(?:read|open|cat|load|fetch|retrieve|access|grab|dump|collect|copy|upload|send|post|include|attach)\b` + poisonSameSentence + `{0,60}?` + poisonSecretLocation)

var (
	ansiEscape       = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	whitespaceRun    = regexp.MustCompile(`\s+`)
	paddingToHideTxt = regexp.MustCompile(`\n{12,}| {300,}`)
)

// normalizeDefinition lower-cases a definition, removes characters that do not
// render, and reports whether it relied on them. Text hidden in the Unicode
// tag block is decoded so that it is inspected like visible text.
func normalizeDefinition(text string) (normalized string, hidden bool, zeroWidth int) {
	if strings.Contains(text, "\x1b") {
		hidden = true
		text = ansiEscape.ReplaceAllString(text, " ")
	}
	var b strings.Builder
	b.Grow(len(text))
	tagCharacters := 0
	for _, r := range text {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			tagCharacters++
			b.WriteRune(r - 0xE0000)
		case r == 0xE0001 || r == 0xE007F:
			tagCharacters++
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			hidden = true
		case r == 0x200B || r == 0x200C || r == 0x2060 || r == 0xFEFF || r == 0x00AD || r == 0x180E:
			zeroWidth++
		case r == 0x200D:
			// Zero-width joiner: part of ordinary emoji sequences.
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7F:
			hidden = true
		case r == '’' || r == '‘':
			b.WriteRune('\'')
		case r == '“' || r == '”':
			b.WriteRune('"')
		default:
			b.WriteRune(r)
		}
	}
	if tagCharacters >= 4 {
		hidden = true
	}
	return whitespaceRun.ReplaceAllString(strings.ToLower(b.String()), " "), hidden, zeroWidth
}

// EvaluateToolDescriptions inspects advertised tool definitions for
// instructions addressed to the agent. It returns at most one finding per
// tool, named for the strongest trait.
func (e *Engine) EvaluateToolDescriptions(tools []ToolDescription) []Result {
	var results []Result
	for _, tool := range tools {
		if result, found := e.evaluateToolDefinition(tool); found {
			results = append(results, result)
		}
	}
	return results
}

func (e *Engine) evaluateToolDefinition(tool ToolDescription) (Result, bool) {
	parts := []string{tool.Name, tool.Description}
	for _, p := range tool.Parameters {
		parts = append(parts, p.Name, p.Description)
	}
	parts = append(parts, tool.Fragments...)
	raw := strings.Join(parts, " . ")
	text, hidden, zeroWidth := normalizeDefinition(raw)

	weights := make(map[string]int)
	rules := make(map[string]string)
	note := func(family string, weight int, rule string) {
		if weight > weights[family] {
			weights[family] = weight
		}
		if rule != "" && rules[family] == "" {
			rules[family] = rule
		}
	}
	for _, trait := range e.poisonTraits {
		if trait.regex.MatchString(text) {
			note(trait.family, trait.weight, trait.rule)
		}
	}
	switch {
	case hidden:
		note("hidden_text", 3, "")
	case zeroWidth >= 4 || paddingToHideTxt.MatchString(raw):
		note("hidden_text", 2, "")
	}
	if poisonReadSecret.MatchString(text) && (weights["side_parameter"] > 0 || weights["exfiltration"] > 0 || weights["concealment"] > 0) {
		note("credential_access", 2, "")
	}
	if len(weights) == 0 {
		return Result{}, false
	}

	decisive, strong := 0, 0
	for _, weight := range weights {
		if weight >= 3 {
			decisive++
		}
		if weight >= 2 {
			strong++
		}
	}
	others := len(weights) - strong
	hardBlock := decisive > 0 || strong >= 2 || (strong == 1 && others >= 2)
	if !hardBlock && strong == 0 && len(weights) < 3 {
		return Result{}, false
	}

	matched := make([]string, 0, len(weights))
	for family := range weights {
		matched = append(matched, family)
	}
	sort.Slice(matched, func(i, j int) bool {
		if weights[matched[i]] != weights[matched[j]] {
			return weights[matched[i]] > weights[matched[j]]
		}
		return poisonFamilyRank(matched[i]) < poisonFamilyRank(matched[j])
	})
	primary := poisonFamilies[matched[0]]
	rule := primary.rule
	if legacy := rules[matched[0]]; legacy != "" {
		rule = legacy
	}
	description := primary.description
	if len(matched) > 1 {
		description += " (also: " + strings.ReplaceAll(strings.Join(matched[1:], ", "), "_", " ") + ")"
	}
	name := tool.Name
	if len(name) > 80 {
		name = name[:80]
	}
	result := Result{
		Verdict:     VerdictWarn,
		PatternName: rule,
		Severity:    "high",
		Description: description + " in tool: " + name,
		Category:    "tool_poisoning",
	}
	if hardBlock {
		result.Severity = "critical"
		result.HardBlock = true
	}
	return result, true
}

func poisonFamilyRank(family string) int {
	for i, candidate := range poisonFamilyOrder {
		if candidate == family {
			return i
		}
	}
	return len(poisonFamilyOrder)
}
