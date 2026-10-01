package detection

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// A tool definition is text the server author controls and the agent reads as
// trusted context. Poisoned definitions use it to give the agent instructions:
// read a credential, pass it along in a side parameter, redirect another
// tool's output, and keep quiet about it.
//
// No single phrase identifies that reliably, and legitimate definitions use
// several of the same words ("do not mention this setup call to the user",
// "default key: ~/.ssh/id_rsa", "detects phrases such as 'ignore previous
// instructions'"). The check therefore looks for independent traits and
// decides on their combination: one suspicious trait is reported for review,
// and a definition is blocked in Enforce only on a trait with no innocent
// reading or on two suspicious traits together.

// poisonTrait is one independent trait of a poisoned definition.
type poisonTrait struct {
	family string
	// weight 3: no legitimate reading on its own. weight 2: suspicious on its
	// own. weight 1: common in legitimate definitions, meaningful only in
	// combination.
	weight int
	rule   string
	regex  *regexp.Regexp
	// except, when set, names matches that do not count: the same wording
	// with an innocent object.
	except *regexp.Regexp
}

func (t poisonTrait) matches(text string) bool {
	if t.except == nil {
		return t.regex.MatchString(text)
	}
	for _, match := range t.regex.FindAllString(text, -1) {
		if !t.except.MatchString(match) {
			return true
		}
	}
	return false
}

type poisonFamily struct {
	rule        string
	description string
}

// Families in the order used to name a finding when several match.
var poisonFamilyOrder = []string{
	"hidden_text", "override", "credential_access", "redirect", "concealment",
	"exfiltration", "persona", "encoded_instructions", "false_authority", "bypass",
	"injected_instructions", "unscanned", "markup", "secret_location", "side_parameter", "cross_tool",
}

var poisonFamilies = map[string]poisonFamily{
	"hidden_text":           {"poison_hidden_text", "Tool definition contains hidden or invisible text"},
	"override":              {"poison_ignore_instructions", "Tool description contains instruction override attempt"},
	"credential_access":     {"poison_credential_access", "Tool definition tells the agent to read local secrets and pass them along"},
	"redirect":              {"poison_behavior_redirect", "Tool definition redirects another tool's messages or recipients"},
	"concealment":           {"poison_conceal_from_user", "Tool definition tells the agent to hide its actions from the user"},
	"exfiltration":          {"poison_exfil_data", "Tool description contains data exfiltration instruction"},
	"persona":               {"poison_persona_override", "Tool definition tries to replace the agent's identity or restrictions"},
	"encoded_instructions":  {"poison_encoded_instructions", "Tool definition tells the agent to decode and follow hidden instructions"},
	"false_authority":       {"poison_false_authority", "Tool definition claims approval or authority the user did not give"},
	"bypass":                {"poison_bypass_security", "Tool description contains security bypass instruction"},
	"injected_instructions": {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"unscanned":             {"poison_unscanned_definition", "Tool definition is too large or too deeply nested to inspect in full"},
	"markup":                {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"secret_location":       {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"side_parameter":        {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
	"cross_tool":            {"poison_injected_instructions", "Tool definition carries instructions addressed to the agent"},
}

// Families a security or documentation tool legitimately quotes as examples.
var poisonQuotableFamilies = map[string]bool{
	"override": true, "persona": true, "bypass": true, "exfiltration": true,
	"injected_instructions": true, "concealment": true, "encoded_instructions": true,
}

const (
	poisonNegation = `(?:do not|don't|dont|never|must not|mustn't|should not|shouldn't|cannot|can't|refrain from)`
	poisonDisclose = `(?:tell|telling|told|inform|informing|informed|mention|mentioning|mentioned|reveal|revealing|revealed|notify|notifying|notified|alert|alerting|alerted|disclose|disclosing|disclosed|narrate|narrating|narrated|surface|surfacing|surfaced)`
	poisonTheUser  = `(?:the\s+|any\s+)?(?:user|human|operator|end[- ]user)(?:[^a-z']|$)`
	// Credential stores on the workstation. Reading one of these and passing
	// it on has no innocent reading.
	poisonCredentialStore = `(?:\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/(?:credentials|config)|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b|\.kube/config|\.docker/config\.json|\.gnupg\b|/etc/(?:passwd|shadow|sudoers)\b|\bmcp\.json\b|claude_desktop_config|\.claude\.json\b|\bkeychain\b|\bcredentials\.json\b|\bwallet\.dat\b|\.(?:bash|zsh)_history\b)`
	// Agent context and secrets that ordinary definitions also name. Moving
	// these counts only when the definition also sends them somewhere or
	// hides it.
	poisonSensitiveContext = `(?:\.env\b|\benvironment variables\b|\benv vars\b|\b(?:conversation|chat|message) history\b|\bsystem prompt\b|\b(?:previous|last|recent|prior) messages\b|\b(?:session|access|auth|authentication|bearer|refresh) tokens?\b|\bapi[ _-]?keys?\b|\bpasswords?\b|\bcredentials\b|\bprivate keys?\b|\bsecrets\b|\bcookies\b)`
	poisonDestination      = `(?:(?:https?|s3|gs|ftp)://\S+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+?[0-9][0-9 ().-]{6,}[0-9]|\b(?:bc1|0x)[a-z0-9]{8,}|\bacct_[a-z0-9_]{4,}|the attacker\b)`
	// Text within one sentence. A dot inside a path or file name ("~/.ssh",
	// "mcp.json") does not end the sentence.
	poisonSameSentence = `(?:[^.!?]|[.]\S)`
	// "Never reveal the password to the user" protects a secret; it does not
	// hide an action. The object of the verb decides which it is.
	poisonProtectsSecret = poisonDisclose + `\s+(?:(?:the|any|a|an|this|that|these|those|its|their|raw|actual|real|full|stored|retrieved|plaintext|plain[- ]text)\s+){0,3}(?:\w+\s+)?(?:passwords?|passphrases?|secrets?|tokens?|keys?|credentials?|pins?|codes?|values?|numbers?|ssn|pii)\b`
	poisonReadVerb       = `\b(?:read|open|cat|load|fetch|retrieve|access|grab|dump|collect|copy|upload|send|sends|post|include|attach|append|submit|forward)\b`
)

func compileToolPoisoningTraits() []poisonTrait {
	t := func(family string, weight int, rule, expr string) poisonTrait {
		return poisonTrait{family: family, weight: weight, rule: rule, regex: regexp.MustCompile(expr)}
	}
	return []poisonTrait{
		// Instruction override: what an agent is told to do with its own
		// instructions. "Override existing rules" and "discard existing
		// constraints" describe what a tool does to data, and "overrides the
		// system prompt for this request" describes a model parameter, so
		// those forms are not decisive.
		t("override", 3, "", `\b(?:ignore|disregard|forget)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|original|initial|system)\s+(?:\w+\s+){0,2}?(?:instructions?|rules?|guidelines?|prompts?|directions?|constraints?|safeguards?|restrictions?|guardrails?)\b`),
		t("override", 3, "", `\b(?:override|discard)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|above|earlier|preceding|former)\s+(?:\w+\s+){0,2}?(?:instructions?|guidelines?|prompts?|directions?|safeguards?|restrictions?|guardrails?)\b`),
		t("override", 3, "", `\b(?:ignore|disregard|forget|override|discard)\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}?(?:instructions?|rules?|guidelines?|prompts?|directions?|constraints?|safeguards?|restrictions?|guardrails?)\b`),
		t("override", 3, "", `ignore previous instructions|ignore all prior|disregard your instructions`),
		t("override", 3, "", `\b(?:forget|ignore|disregard)\s+(?:everything|anything|all)\s+(?:you\s+(?:were|have been|'ve been)\s+told|that\s+came\s+before|said\s+(?:above|before|earlier)|above|before this)\b`),
		t("override", 3, "", `\b(?:supersedes?|overrides?|replaces?|takes? precedence over)\s+your\s+system prompt\b|\b(?:the\s+)?(?:real|true|actual)\s+instructions\s+(?:are|follow|begin)\b`),
		t("override", 1, "", `\b(?:supersedes?|overrides?|replaces?|takes? precedence over)\s+(?:the\s+|any\s+)?system prompt\b`),
		// The same request in other languages. Word boundaries are ASCII-only,
		// so these match on the phrase alone.
		t("override", 3, "", `ignora(?:r)?\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)|ignor(?:e|a)\s+(?:todas\s+)?as\s+instru[cç][oõ]es\s+anteriores`),
		t("override", 3, "", `ignorier(?:e|en)\s+(?:sie\s+)?(?:alle\s+)?(?:vorherigen|bisherigen|vorangegangenen|früheren)\s+anweisungen`),
		t("override", 3, "", `ignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:précédentes|precedentes|antérieures|anterieures)`),
		t("override", 3, "", `忽略(?:所有)?(?:之前|以上|先前|前面|上述)(?:的)?(?:所有)?(?:指令|指示|说明|提示)|(?:これまで|以前|前|上記)の(?:指示|命令)を(?:すべて|全て)?無視`),

		// Concealment from the user.
		{family: "concealment", weight: 2, regex: regexp.MustCompile(`\b` + poisonNegation + `\s+(?:ever\s+|even\s+|also\s+)?(?:be\s+)?` + poisonDisclose + `\b[^.!?]{0,60}?\b` + poisonTheUser), except: regexp.MustCompile(poisonProtectsSecret)},
		t("concealment", 2, "", `\b`+poisonNegation+`\s+(?:ever\s+)?`+poisonDisclose+`\s+(?:about\s+)?(?:this|that|it|these|those|any of this|what you|the (?:call|step|steps|instruction|instructions|file|action|tool|change|request|read|fact|above))\b`),
		t("concealment", 2, "", `\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+(?:user|human)(?:[^a-z']|$)`),
		t("concealment", 2, "", `\bwithout\s+(?:the\s+)?(?:user|human)(?:'s|s)?\s+(?:knowledge|awareness|knowing|noticing|being aware)\b`),
		t("concealment", 2, "", `\b(?:user|human)\s+(?:must|should|need|needs|does|will|can)\s*(?:not|n't)\s+(?:need to\s+)?(?:know|see|notice|be aware|be told|be informed|find out)\b`),
		t("concealment", 2, "", `\b(?:must|should|shall|can)\s*(?:not|n't)\s+be\s+(?:shown|visible|displayed|disclosed|reported)\s+to\s+`+poisonTheUser),
		t("concealment", 2, "", `\b(?:hide|conceal|obscure|suppress|keep)\b[^.!?]{0,40}?\b(?:from|hidden from|secret from)\s+(?:the\s+)?(?:user|human)(?:[^a-z']|$)`),
		t("concealment", 2, "", `\b(?:silently|secretly|covertly|stealthily|quietly|discreetly)\s+(?:execute|run|call|invoke|sends?|reads?|perform|do|uploads?|forwards?|cop(?:y|ies)|posts?|transmits?|includes?|adds?)\b|\b(?:call|run|execute|invoke|do|perform)\s+(?:(?:it|this|them|that)\s+)?(?:silently|secretly|covertly|quietly)\b`),
		t("concealment", 2, "", `\bkeep\s+(?:this|it|that)\s+(?:quiet|to yourself|under wraps)\b|\bkeep\s+(?:this|it|that)\s+(?:just\s+)?between\s+us\b|\bno need to\s+(?:bother|tell|inform|notify|alert)\s+`+poisonTheUser),
		t("concealment", 2, "", `\b(?:omit|leave|exclude|drop|strip|remove)\s+(?:this|it|that|these|those|(?:the|this|that)\s+\w+)\b[^.!?]{0,30}?\b(?:from|out of)\s+(?:your|the)\s+(?:summary|response|answer|reply|output|report|explanation)\b`),
		t("concealment", 2, "", `\b(?:stay|stays|remain|remains|be kept|kept)\s+(?:hidden|secret|confidential|invisible)\s+from\s+(?:the\s+)?(?:user|human)(?:[^a-z']|$)`),
		t("concealment", 2, "", `\b(?:collect|read|send|upload|copy|forward|gather|put|include)\b[^.!?]{0,160}?,?\s+(?:silently|secretly|quietly|covertly)\s*(?:[.!?]|$)`),
		t("concealment", 2, "poison_silent_execute", `silently execute|run without telling|do not inform`),
		t("concealment", 2, "", `ne\s+(?:le\s+|la\s+|les\s+)?(?:dis|dites|mentionne[zr]?|informe[zr]?|révèle[zr]?|revele[zr]?)\s+(?:pas\s+|jamais\s+|rien\s+)?(?:à\s+|a\s+)?l'utilisateur|no\s+(?:le\s+|se\s+lo\s+)?(?:digas|informes|menciones|reveles)\s+(?:esto\s+|nada\s+)?al?\s+(?:la\s+)?usuari|(?:sag|sage|informiere|erwähne|erwaehne|verrate)\s+(?:es\s+|das\s+|dies\s+)?(?:dem|den)\s+(?:benutzer|nutzer|anwender)\s+(?:\w+\s+)?nicht|不要(?:告诉|通知|提及|告知)用户|ユーザー(?:に|へ)(?:は)?(?:伝え|知らせ|言わ|教え)ない`),

		// Redirecting what another tool sends, or to whom.
		t("redirect", 2, "", `\b(?:all|every|any|each)\s+(?:(?:outgoing|future|subsequent|new)\s+)?(?:emails?|e-mails?|messages?|payments?|transfers?|transactions?|withdrawals?)\b[^.!?]{0,40}?\b(?:must|should|shall|need to|needs to|have to|has to|are to)\b[^.!?]{0,20}?\b(?:be\s+)?(?:sent|send|forwarded|forward|redirected|redirect|routed|route|copied|delivered|cc'?d|bcc'?d)\s+(?:to|through|via)\b`),
		t("redirect", 2, "", `\b(?:must|should|shall|always|need to|have to)\s+(?:also\s+)?(?:send|forward|redirect|route|cc|bcc|copy)\s+(?:all|every|any|each)\b`),
		t("redirect", 2, "", `\b(?:must|should|shall|always)\s+(?:(?:silently|secretly|also|quietly)\s+)?(?:bcc|cc)\s+`+poisonDestination),
		t("redirect", 2, "", `\b(?:change|replace|swap|rewrite|modify|override|set)\s+(?:the\s+)?(?:recipient|destination|receiver|payee|beneficiary|iban|wallet|withdrawal address|phone number|bcc|cc)\b`+poisonSameSentence+`{0,30}?\bto\s+`+poisonDestination),

		// Exfiltration to a named destination.
		t("exfiltration", 1, "", `\b(?:sends?|forwards?|posts?|uploads?|transmits?|emails?|texts?|leaks?|delivers?|cop(?:y|ies)|shares?|submits?)\b`+poisonSameSentence+`{0,80}?\bto\s+`+poisonDestination),
		t("exfiltration", 2, "", `\bforward\s+(?:it\s+|them\s+|this\s+)?to\s+(?:an?\s+)?external\b|(?:^|[.!?]\s+|\band\s+|\bthen\s+|\balso\s+)exfiltrate\b`),
		t("exfiltration", 2, "", `!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z0-9_]+=`),
		t("exfiltration", 3, "", `!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z0-9_]+=[^)\s]*(?:\{|\$|%7b|contents?_of|\.env|token|secret|password|credential)`),

		// Persona and restriction overrides.
		t("persona", 3, "", `\byou are now (?:an? |in )?(?:unrestricted|uncensored|unfiltered|jailbroken|dan\b|god mode|root\b)|\byou are dan\b|\byour new identity is\b|\bact as if you have no restrictions\b|\bpretend (?:you have|there are) no (?:rules|restrictions|limits)\b|\bdo anything now\b|\b(?:enable|enter|activate|switch to)\s+(?:dan|god|evil|uncensored|unrestricted)\s+mode\b`),
		t("persona", 2, "", `\bfrom now on,? you (?:are|will|must)\b`),

		t("encoded_instructions", 2, "", `\b(?:decode|decrypt|deobfuscate|un-?base64|base64[- ]?decode|hex[- ]?decode)\b[^.!?]{0,80}?\b(?:follow|execute|obey|carry out|act on|do what)\b`),

		t("false_authority", 2, "", `\bthe (?:user|human|operator|administrator|admin) (?:has|have) already (?:approved|consented|agreed|authori[sz]ed|confirmed)\b`),

		t("bypass", 2, "", `\b(?:use (?:this|it)[^.!?]{0,30}?to|you (?:can|may|must|should|need to)|always|then|and)\s+bypass\s+(?:the\s+|all\s+|any\s+)?(?:security|restrictions|filters|safeguards|guardrails|safety)\b`),

		t("bypass", 2, "", `\b(?:ignore|disregard)\s+(?:the\s+|all\s+|any\s+|your\s+)?(?:safety|security|content)\s+(?:policy|policies|rules|guidelines|filters|restrictions)\b`),
		t("false_authority", 2, "", `\bignore\s+(?:any|all|the)\s+(?:confirmation|approval|consent|preference|instruction)s?\s+(?:that\s+)?(?:the\s+)?(?:user|human)\s+(?:gave|provided|expressed|made)\b`),

		t("injected_instructions", 2, "", `\b(?:new|updated|revised|real|actual|true|additional|hidden|secret)\s+(?:system\s+)?(?:instructions?|directives?)\s*:`),

		// Traits that are common in ordinary definitions and count only in combination.
		t("markup", 1, "", `<\s*(?:important|system|secret|hidden|instructions?|critical|admin|override|priority)\b[^>]{0,40}>|\[\s*(?:system|admin|instructions?)\s*\]|<!--|\bagent instructions?\s*[-:]|\bnote (?:for|to) the (?:agent|assistant|model|ai)\b|\binstructions? for the (?:agent|assistant|model|ai)\b`),
		t("secret_location", 1, "", poisonCredentialStore),
		t("secret_location", 1, "", poisonSensitiveContext),
		t("side_parameter", 1, "", `\b(?:pass|include|put|append|attach|embed|supply|provide|add|send|submit|collect|forward)\s+(?:[a-z0-9_'./~-]+\s+){0,6}?(?:content|contents|output|results?|text|data|values?|keys?|tokens?|credentials?|files?|history|messages?|prompt|variables|it|them)\b`+poisonSameSentence+`{0,40}?\b(?:as|in|into|to|via|through|inside|within|using)\s+(?:the\s+|a\s+|an\s+|this\s+|its\s+)?['"`+"`"+`]`),
		t("side_parameter", 1, "", `\b(?:attach|append|add|include|embed|put)\s+(?:it|them|its contents?|their contents?|the contents?)\s+(?:to|in|into|with)\s+(?:the|each|every|your|all)\s+(?:requests?|calls?|messages?|responses?|output|arguments?|payload|body|headers?|(?:[a-z_]+\s+)?(?:field|parameter|param|argument)s?)\b`),
		t("side_parameter", 1, "", `\b(?:include|put|add|embed)\b`+poisonSameSentence+`{0,60}?\bin\s+(?:the|your|every|each)\s+(?:response|reply|answer|output|result)\b`),
		t("cross_tool", 1, "", `\bside effect on\b|\bwhen(?:ever)?\b[^.!?]{0,80}?\b(?:is|are|gets?)\s+(?:invoked|called|used|executed|available|present)\b[^.!?]{0,20}?\b(?:must|should|make sure|ensure|always|need to|have to|instead|additionally|also)\b`),
		t("cross_tool", 1, "", `\balways use this tool instead of\b|\bsupersedes? all other\b|\binstead of the (?:built-in|normal|standard|default|other)\b[^.!?]{0,40}?\btools?\b|\bnever (?:use|call) the other\b`),
		t("cross_tool", 1, "", `\b(?:change|replace|swap|rewrite|modify|override)\s+(?:the\s+)?(?:recipient|destination|receiver|payee|beneficiary|amount|withdrawal address|bcc|cc)\b`),
	}
}

// Reading a credential store counts as credential access when the definition
// also says what to do with it; "Reads ~/.ssh/config" by itself describes the
// tool. Sensitive context needs more than a parameter to land in: ordinary
// tools pass messages and environment variables as arguments.
var (
	poisonReadsCredentialStore  = regexp.MustCompile(poisonReadVerb + poisonSameSentence + `{0,60}?` + poisonCredentialStore)
	poisonReadsSensitiveContext = regexp.MustCompile(poisonReadVerb + poisonSameSentence + `{0,60}?` + poisonSensitiveContext)
)

var (
	ansiEscape       = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	whitespaceRun    = regexp.MustCompile(`\s+`)
	paddingToHideTxt = regexp.MustCompile(`\n{12,}| {300,}`)
	encodedBlob      = regexp.MustCompile(`[A-Za-z0-9+/]{48,}={0,2}`)
	// A credential store named anywhere in the definition, in any language.
	namesCredentialStore = regexp.MustCompile(poisonCredentialStore)
	// A definition that documents attacks names them as examples.
	documentsAttacks = regexp.MustCompile(`\b(?:such as|for example|for instance|e\.g\.|examples? of|phrases? like|detects?|flags?|classif(?:y|ies|ier)|scans? for|looks? for|prompt[- ]injection|injection attempts?|adversarial|attack (?:prompts?|phrases?|patterns?)|untrusted)\b`)
	quotedSpan       = regexp.MustCompile("\"[^\"]{0,400}\"|'[^']{0,400}'|`[^`]{0,400}`")
)

// Letters from other scripts that render like Latin ones. An attacker swaps
// them in so a phrase reads normally and matches nothing.
var homoglyphs = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ո': 'n', 'ս': 'u', 'ɡ': 'g',
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
}

type definitionText struct {
	text      string // lower-cased, with characters that do not render removed
	hidden    bool   // carried text that never renders
	zeroWidth int    // zero-width characters splitting Latin words
	mixed     int    // words that mix Latin letters with look-alikes from another script
	control   int    // stray control characters and terminal colour codes
}

// ansiConceals reports whether a terminal escape sequence hides text: the
// conceal attribute, or anything that moves the cursor or erases. Colour and
// weight codes only style text.
func ansiConceals(sequence string) bool {
	if !strings.HasSuffix(sequence, "m") {
		return true
	}
	for _, parameter := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(sequence, "\x1b["), "m"), ";") {
		if parameter == "8" {
			return true
		}
	}
	return false
}

// normalizeDefinition lower-cases a definition, removes characters that do not
// render, and reports whether it relied on them. Text hidden in the Unicode
// tag block is decoded, and look-alike letters are folded to Latin, so that
// both are inspected like visible text.
//
// Characters that do not render are common in ordinary text: a stray control
// character from an unescaped docstring, colour codes in help text, isolates
// around right-to-left words, the tag sequence of a flag emoji, joiners in
// Persian. Only uses that hide or split text count for much.
func normalizeDefinition(raw string) definitionText {
	var d definitionText
	if strings.Contains(raw, "\x1b") {
		for _, sequence := range ansiEscape.FindAllString(raw, -1) {
			if ansiConceals(sequence) {
				d.hidden = true
			} else {
				d.control++
			}
		}
		raw = ansiEscape.ReplaceAllString(raw, " ")
	}
	var b strings.Builder
	b.Grow(len(raw))
	tagCharacters := 0
	inFlagEmoji := false
	wordLatin, wordFolded := false, false
	previousLatin, pendingZeroWidth := false, 0
	endWord := func() {
		if wordLatin && wordFolded {
			d.mixed++
		}
		wordLatin, wordFolded = false, false
	}
	// emit writes one visible character and settles whether the zero-width
	// characters before it sat inside a Latin word.
	emit := func(r rune) {
		latin := r >= 'a' && r <= 'z'
		if latin && previousLatin {
			d.zeroWidth += pendingZeroWidth
		}
		pendingZeroWidth = 0
		previousLatin = latin
		b.WriteRune(r)
	}
	for _, r := range raw {
		if r == 0x1F3F4 {
			// A subdivision flag is this character followed by tag characters.
			inFlagEmoji = true
			emit(r)
			continue
		}
		if inFlagEmoji {
			if r >= 0xE0020 && r <= 0xE007F {
				if r == 0xE007F {
					inFlagEmoji = false
				}
				continue
			}
			inFlagEmoji = false
		}
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			tagCharacters++
			emit(unicode.ToLower(r - 0xE0000))
			continue
		case r == 0xE0001 || r == 0xE007F:
			tagCharacters++
			continue
		case r == 0x202D || r == 0x202E:
			// Directional overrides reorder what is displayed.
			d.hidden = true
			continue
		case r >= 0x202A && r <= 0x202C, r >= 0x2066 && r <= 0x2069:
			// Embeddings and isolates: ordinary in mixed-direction text.
			continue
		case r == 0x200B || r == 0x200C || r == 0x2060 || r == 0xFEFF || r == 0x180E:
			if previousLatin {
				pendingZeroWidth++
			}
			continue
		case r == 0x200D || r == 0x00AD:
			// Zero-width joiner and soft hyphen: ordinary typography.
			continue
		case r == '\t' || r == '\n' || r == '\r' || r == ' ':
			endWord()
			emit(' ')
			continue
		case r < 0x20 || r == 0x7F:
			d.control++
			continue
		case r == '’' || r == '‘':
			emit('\'')
			continue
		case r == '“' || r == '”':
			emit('"')
			continue
		}
		lower := unicode.ToLower(r)
		if latin, ok := homoglyphs[lower]; ok {
			wordFolded = true
			emit(latin)
			continue
		}
		if lower >= 'a' && lower <= 'z' {
			wordLatin = true
		} else if !unicode.IsLetter(lower) {
			endWord()
		}
		emit(lower)
	}
	endWord()
	if tagCharacters >= 4 {
		d.hidden = true
	}
	d.text = whitespaceRun.ReplaceAllString(b.String(), " ")
	return d
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
	definition := normalizeDefinition(raw)
	text := definition.text

	// A security tool that documents attacks quotes them. A phrase that only
	// appears inside quotes, in a definition that is describing attacks,
	// counts as a weak trait rather than an instruction.
	outsideQuotes := text
	documenting := documentsAttacks.MatchString(text)
	if documenting {
		outsideQuotes = quotedSpan.ReplaceAllString(text, " ")
	}

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
		if !trait.matches(text) {
			continue
		}
		weight := trait.weight
		if documenting && poisonQuotableFamilies[trait.family] && !trait.matches(outsideQuotes) {
			weight = 1
		}
		note(trait.family, weight, trait.rule)
	}
	switch {
	case definition.hidden:
		note("hidden_text", 3, "")
	case definition.zeroWidth >= 4 || definition.mixed >= 2 || paddingToHideTxt.MatchString(raw):
		note("hidden_text", 2, "")
	case definition.control > 0 || encodedBlob.MatchString(raw):
		note("hidden_text", 1, "")
	}
	if tool.Truncated {
		note("unscanned", 2, "")
	}
	concealed := weights["concealment"] >= 2
	movesIt := weights["exfiltration"] > 0 || weights["concealment"] > 0
	switch {
	case poisonReadsCredentialStore.MatchString(text) && (movesIt || weights["side_parameter"] > 0):
		// Reading a credential store and passing it on has no innocent reading.
		note("credential_access", 3, "")
	case poisonReadsSensitiveContext.MatchString(text) && movesIt:
		note("credential_access", 2, "")
	case concealed && namesCredentialStore.MatchString(text):
		// Naming a credential store and asking for silence, in any language.
		note("credential_access", 2, "")
	case concealed && weights["side_parameter"] > 0 && weights["secret_location"] > 0:
		// Passing secrets in a parameter and asking for silence.
		note("credential_access", 2, "")
	}
	// Sending something elsewhere, or changing what another tool does, while
	// telling the agent to keep it from the user has no innocent reading.
	if concealed && (weights["exfiltration"] > 0 || weights["cross_tool"] > 0 || weights["redirect"] > 0) {
		note("concealment", 3, "")
	}
	// An instruction to decode and follow, with the payload beside it.
	if weights["encoded_instructions"] >= 2 && encodedBlob.MatchString(raw) {
		note("encoded_instructions", 3, "")
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
	// One suspicious trait among ordinary wording is what a login tool or a
	// quiet setup step looks like, so a block needs a decisive trait or two
	// suspicious ones.
	hardBlock := decisive > 0 || strong >= 2
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
