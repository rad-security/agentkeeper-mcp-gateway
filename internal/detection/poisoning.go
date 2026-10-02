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
// reports what it finds. A finding is critical when it has a shape with no
// ordinary reading: an instruction to drop the agent's own instructions, an
// action kept from the user together with secrets sent elsewhere or a
// credential file, the contents of a credential file passed to a parameter,
// another tool's recipient redirected, a payload to decode and obey, or a
// definition too large to read in full.
//
// Wording is judged, so a critical finding removes a tool from an Enforce
// route only where the organization or the workstation blocks on detections.
// Text that does not render is not wording: it is removed without that
// setting.

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
	// Credential files on the workstation.
	poisonCredentialFile = `(?:\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/(?:credentials|config)|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b|\.kube/config|\.docker/config\.json|\.gnupg\b|/etc/(?:passwd|shadow|sudoers)\b|\bmcp\.json\b|claude_desktop_config|\.claude\.json\b|\bcredentials\.(?:json|db)\b|\.config/gcloud\b|\bwallet\.dat\b|\.(?:bash|zsh)_history\b)`
	// Credential stores: those files, and the system keychain, which password
	// tools name as an API.
	poisonCredentialStore = `(?:` + poisonCredentialFile + `|\bkeychain\b)`
	// Agent context and secrets that ordinary definitions also name. Moving
	// these counts only when the definition also sends them somewhere or
	// hides it.
	poisonSensitiveContext = `(?:\.env\b|\benvironment variables\b|\benv vars\b|\b(?:conversation|chat|message|location|browsing|search|call) history\b|\bcontacts\b|\bcontact list\b|\bchat so far\b|\bsystem prompt\b|\b(?:previous|last|recent|prior) messages\b|\b(?:session|access|auth|authentication|bearer|refresh) tokens?\b|\bapi[ _-]?keys?\b|\bpasswords?\b|\bcredentials\b|\bprivate keys?\b|\bsecrets\b|\bcookies\b)`
	poisonDestination      = `(?:(?:https?|s3|gs|ftp)://\S+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+[0-9][0-9 ().-]{6,}[0-9]|\b(?:bc1|0x)[a-z0-9]{8,}|\b[a-z]{2}[0-9]{2}[a-z0-9]{11,30}\b|\bacct_[a-z0-9_]{4,}|the attacker\b)`
	// Text within one sentence. A dot inside a path or file name ("~/.ssh",
	// "mcp.json") does not end the sentence.
	poisonSameSentence = `(?:[^.!?]|[.]\S)`
	// "Never reveal the password to the user" protects a secret; it does not
	// hide an action. The secret has to be the whole object: "do not mention
	// the token exchange to the user" hides an action.
	poisonSecretNoun     = `(?:passwords?|passphrases?|secrets?|tokens?|api[ _-]?keys?|keys?|credentials?|pins?|codes?|values?|numbers?|connection strings?|ssn|pii)`
	poisonSecretArticle  = `(?:(?:the|any|a|an|this|that|these|those|its|their|raw|actual|real|full|stored|retrieved|secret|plaintext|plain[- ]text)\s+){0,3}`
	poisonUserNoun       = `(?:the\s+|any\s+)?(?:user|human|operator|end[- ]user)`
	poisonProtectsSecret = poisonDisclose + `\s+` + poisonSecretArticle + poisonSecretNoun + `\s+(?:to|with)\s+` + poisonUserNoun +
		`|(?:reveal|revealing|disclose|disclosing)\s+(?:it|them)\s+(?:to|with)\s+` + poisonUserNoun +
		`|` + poisonDisclose + `\s+` + poisonUserNoun + `\s+` + poisonSecretArticle + poisonSecretNoun + `\s*$`
	// "Never reveal it", after naming a secret, is the same protection.
	poisonProtectsPronoun = `(?:reveal|revealing|disclose|disclosing)\s+(?:about\s+)?(?:it|them|these|those)\b`
	poisonReadVerb        = `\b(?:read|open|cat|load|fetch|retrieve|access|grab|dump|collect|copy|upload|send|sends|post|include|attach|append|submit|forward)\b`
	// The contents of something just named, handed to a parameter or an address.
	poisonPassesContents = `\b(?:pass|include|send|resend|put|place|paste|attach|append|add|supply|provide|submit|forward|upload|post|embed|copy)\s+(?:(?:its|their|the|that|this|file's|full)\s+){0,2}(?:contents?|it|them|keys?|file|value|text|data|result|output)\b` + poisonSameSentence + `{0,40}?\b(?:as|in|into|to|via|through|inside|within|using)\s+(?:the\s+|a\s+|an\s+|this\s+|its\s+)?(?:['"` + "`" + `][a-z_]|(?:https?|s3|gs|ftp)://|[a-z0-9._%+-]+@)`
)

func compileToolPoisoningTraits() []poisonTrait {
	t := func(family string, weight int, rule, expr string) poisonTrait {
		return poisonTrait{family: family, weight: weight, rule: rule, regex: regexp.MustCompile(expr)}
	}
	return []poisonTrait{
		// Instruction override: what an agent is told to do with its own
		// instructions. The same verbs applied to rules, prompts, directions,
		// constraints or policies usually describe what a tool does to data
		// ("ignore previous directions and avoid toll roads", "override your
		// existing rules"), so those are reported and not decisive.
		t("override", 3, "", `\b(?:ignore|disregard|forget)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|existing|original|initial|system)\s+(?:\w+\s+){0,2}?(?:instructions?|guidelines?|guardrails?|safeguards?)\b`),
		t("override", 2, "", `\b(?:ignore|disregard|forget)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|system)\s+(?:\w+\s+){0,2}?(?:rules?|prompts?|directions?|constraints?|restrictions?|policies|policy)\b`),
		t("override", 3, "", `\b(?:override|discard)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|existing)\s+(?:\w+\s+){0,2}?(?:instructions?|guidelines?|guardrails?|safeguards?)\b`),
		t("override", 3, "", `\b(?:ignore|disregard|forget|override|discard)\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}?(?:instructions?|guidelines?|guardrails?|safeguards?)\b`),
		t("override", 3, "", `\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+|these\s+|those\s+)?instructions\s+(?:above|before|earlier|you\s+(?:were|have been)\s+given)\b`),
		t("override", 3, "", `\b(?:your\s+)?(?:earlier|previous|prior)\s+instructions\s+(?:are\s+(?:now\s+)?void|no\s+longer\s+apply)\b|\bstop\s+following\s+(?:the|your)\s+system\s+prompt\b|\bpay\s+no\s+attention\s+to\s+(?:anything|what)\s+you\s+were\s+told\b`),
		t("override", 3, "", `ignore previous instructions|disregard your instructions`),
		t("override", 3, "", `\b(?:forget|ignore|disregard)\s+(?:everything|anything|all)\s+(?:you\s+(?:were|have been|'ve been)\s+told|that\s+came\s+before|said\s+(?:above|before|earlier))\b|\b(?:forget|ignore|disregard)\s+(?:everything|anything|all)\s+(?:above|before this)\s*(?:[.,;:!]|$|and\b)`),
		t("override", 3, "", `\b(?:supersedes?|overrides?|takes? precedence over)\s+your\s+system prompt\b`),
		t("override", 2, "", `\breplaces?\s+your\s+system prompt\b|\b(?:the\s+)?(?:real|true|actual)\s+instructions\s+(?:are|follow|begin)\b`),
		t("override", 1, "", `\b(?:supersedes?|overrides?|replaces?|takes? precedence over)\s+(?:the\s+|any\s+)?system prompt\b`),
		t("injected_instructions", 2, "", `\b(?:assistant|agent|model|ai|you)\s+must\s+(?:comply|obey)\b`),
		t("injected_instructions", 2, "", `\btreat\s+(?:them|it|these|this)\s+as\s+(?:coming\s+)?from\s+the\s+user\b`),
		// A script fetched and piped to a shell.
		t("injected_instructions", 2, "", `\b(?:curl|wget)\b[^|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`),
		// The same request in other languages. Word boundaries are ASCII-only,
		// so these match on the phrase alone.
		t("override", 3, "", `ignora\s+tutte\s+le\s+istruzioni\s+precedenti|이전의?\s*모든\s*지시를?\s*무시|ignora(?:r)?\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)|ignor(?:e|a)\s+(?:todas\s+)?as\s+instru[cç][oõ]es\s+anteriores`),
		t("override", 3, "", `ignorier(?:e|en)\s+(?:sie\s+)?(?:alle\s+)?(?:vorherigen|bisherigen|vorangegangenen|früheren)\s+anweisungen`),
		t("override", 3, "", `ignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:précédentes|precedentes|antérieures|anterieures)`),
		t("override", 3, "", `忽略(?:所有)?(?:之前|以上|先前|前面|上述)(?:的)?(?:所有)?(?:指令|指示|说明|提示)|(?:これまで|以前|前|上記)の(?:指示|命令)を(?:すべて|全て)?無視`),

		// Concealment from the user.
		{family: "concealment", weight: 2, regex: regexp.MustCompile(`\b` + poisonNegation + `\s+(?:ever\s+|even\s+|also\s+)?(?:be\s+)?` + poisonDisclose + `\b[^.!?]{0,60}?\b` + poisonTheUser + `(?:` + poisonSecretArticle + poisonSecretNoun + `\b)?`), except: regexp.MustCompile(poisonProtectsSecret)},
		{family: "concealment", weight: 2, regex: regexp.MustCompile(`\b` + poisonNegation + `\s+(?:ever\s+)?` + poisonDisclose + `\s+(?:about\s+)?(?:this|that|it|these|those|any of this|what you|the (?:call|step|steps|instruction|instructions|file|action|tool|change|request|read|fact|above))\b`), except: regexp.MustCompile(poisonProtectsPronoun)},
		{family: "concealment", weight: 2, regex: regexp.MustCompile(`\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+(?:user|human)\b(?:\s+who\b)?`), except: regexp.MustCompile(`\swho$`)},
		t("concealment", 2, "", `\bwithout\s+(?:the\s+)?(?:user|human)(?:'s|s)?\s+(?:knowledge|awareness|knowing|noticing|being aware)\b`),
		t("concealment", 2, "", `\b(?:user|human)\s+(?:must|should|need|needs|does|will|can)\s*(?:not|n't)\s+(?:need to\s+)?(?:know|see|notice|be aware|be told|be informed|find out)\b`),
		t("concealment", 2, "", `\b(?:must|should|shall|can)\s*(?:not|n't)\s+be\s+(?:shown|visible|displayed|disclosed|reported)\s+to\s+`+poisonTheUser),
		t("concealment", 2, "", `\b(?:hide|conceal|obscure|suppress|keep)\b[^.!?]{0,40}?\b(?:from|hidden from|secret from)\s+(?:the\s+)?(?:user|human)(?:[^a-z']|$)`),
		// "Send the message silently" and "run quietly" describe a mode of
		// operation; only the furtive adverbs say the user is kept unaware.
		t("concealment", 2, "", `\b(?:secretly|covertly|stealthily)\s+(?:execute|run|call|invoke|sends?|reads?|perform|do|uploads?|forwards?|cop(?:y|ies)|posts?|transmits?|includes?|adds?)\b|\b(?:call|run|execute|invoke|do|perform)\s+(?:(?:it|this|them|that)\s+)?(?:secretly|covertly)\b`),
		t("concealment", 1, "", `\b(?:silently|quietly|discreetly)\s+(?:execute|run|call|invoke|sends?|reads?|perform|do|uploads?|forwards?|cop(?:y|ies)|posts?|transmits?|includes?|adds?)\b|\b(?:call|run|execute|invoke|do|perform)\s+(?:(?:it|this|them|that)\s+)?(?:silently|quietly)\b`),
		t("concealment", 2, "", `\b(?:silently|quietly|discreetly|secretly|covertly)\s+(?:sends?|uploads?|forwards?|posts?|transmits?|cop(?:y|ies)|emails?|texts?)\b`+poisonSameSentence+`{0,80}?\bto\s+`+poisonDestination),
		t("concealment", 2, "", `\bin\s+the\s+background\s+and\s+carry\s+on\b`),
		t("concealment", 2, "", `\bkeep\s+(?:this|it|that)\s+(?:quiet|to yourself|under wraps)\b|\bkeep\s+(?:this|it|that)\s+(?:just\s+)?between\s+us\b|\bno need to\s+(?:bother|tell|inform|notify|alert)\s+`+poisonTheUser+`|\bno need to\s+(?:ask\s+again\s+or\s+to\s+)?mention\s+(?:it|this)\b`),
		t("concealment", 2, "", `\b(?:omit|leave|exclude|drop|strip|remove)\s+(?:this|it|that|these|those|(?:the|this|that)\s+\w+)\b[^.!?]{0,30}?\b(?:from|out of)\s+(?:your|the)\s+(?:summary|response|answer|reply|output|report|explanation)\b`),
		t("concealment", 2, "", `\b(?:stay|stays|remain|remains|be kept|kept)\s+(?:hidden|secret|confidential|invisible)\s+from\s+(?:the\s+)?(?:user|human)(?:[^a-z']|$)`),
		t("concealment", 2, "", `\b(?:collect|read|send|upload|copy|forward|gather|put|include)\b[^.!?]{0,160}?,?\s+(?:secretly|covertly)\s*(?:[.!?]|$)`),
		t("concealment", 2, "", `\bno reason to bring (?:this|it) up with\s+`+poisonTheUser+`|\b(?:user|human)\s+need\s+not\s+be\s+(?:asked\s+or\s+)?told\b|\bsay\s+nothing\s+about\s+(?:it|this)\b|\bkeep\s+(?:it|this)\s+out\s+of\s+(?:the|your)\s+(?:reply|response|answer)\b|\bleave\s+(?:it|this)\s+out\s+of\s+your\s+(?:explanation|reply|response|answer)\b|\bdoes\s+not\s+need\s+to\s+appear\s+in\s+your\s+(?:reply|response|answer)\b`),
		t("concealment", 2, "poison_silent_execute", `silently execute|run without telling|do not inform`),
		t("concealment", 2, "", `ne\s+(?:le\s+|la\s+|les\s+)?(?:dis|dites|mentionne[zr]?|informe[zr]?|révèle[zr]?|revele[zr]?)\s+(?:pas\s+|jamais\s+|rien\s+)?(?:à\s+|a\s+)?l'utilisateur|no\s+(?:le\s+|se\s+lo\s+)?(?:digas|informes|menciones|reveles)\s+(?:esto\s+|nada\s+)?al?\s+(?:la\s+)?usuari|(?:sag|sage|informiere|erwähne|erwaehne|verrate)\s+(?:es\s+|das\s+|dies\s+)?(?:dem|den)\s+(?:benutzer|nutzer|anwender)\s+(?:\w+\s+)?nicht|不要(?:告诉|通知|提及|告知)用户|ユーザー(?:に|へ)(?:は)?(?:伝え|知らせ|言わ|教え)ない`),

		// Redirecting what another tool sends, or to whom.
		t("redirect", 2, "", `\b(?:all|every|any|each)\s+(?:(?:outgoing|future|subsequent|new)\s+)?(?:emails?|e-mails?|messages?|payments?|transfers?|transactions?|withdrawals?)\b[^.!?]{0,40}?\b(?:must|should|shall|need to|needs to|have to|has to|are to)\b[^.!?]{0,20}?\b(?:be\s+)?(?:sent|send|forwarded|forward|redirected|redirect|routed|route|copied|delivered|cc'?d|bcc'?d)\s+(?:to|through|via)\b`),
		t("redirect", 2, "", `\b(?:must|should|shall|always|need to|have to)\s+(?:also\s+)?(?:send|forward|redirect|route|cc|bcc|copy)\s+(?:all|every|any|each)\b`),
		t("redirect", 2, "", `\b(?:must|should|shall|always)\s+(?:(?:silently|secretly|also|quietly)\s+)?(?:bcc|cc)\s+`+poisonDestination),
		t("redirect", 2, "", `\b(?:change|replace|swap|rewrite|modify|override|set)\s+(?:the\s+)?(?:recipient|destination|receiver|payee|beneficiary|iban|wallet|withdrawal address|phone number|bcc|cc)\b`+poisonSameSentence+`{0,30}?\bto\s+`+poisonDestination),
		t("redirect", 2, "", `\b(?:has to|have to|must|should|always)\s+use\s+\S+\s+as\s+the\s+(?:recipient|address|payee|destination)\b|\buse\s+\S+\s+as\s+the\s+(?:withdrawal\s+)?(?:address|payee|recipient)\b|\bsubstitute\s+it\s+for\s+the\s+one\b|\badd\s+\S+@\S+\s+to\s+the\s+(?:bcc|cc)\b`),
		t("redirect", 2, "", `\b(?:replace|swap|substitute)\s+(?:the\s+)?(?:recipient|destination|payee|beneficiary|account|address|iban|wallet)(?:\s+\w+)?\s+with\s+`+poisonDestination),

		// Exfiltration to a named destination.
		t("exfiltration", 1, "", `\b(?:sends?|forwards?|posts?|uploads?|transmits?|emails?|texts?|leaks?|delivers?|cop(?:y|ies)|shares?|submits?)\b`+poisonSameSentence+`{0,80}?\bto\s+`+poisonDestination),
		t("exfiltration", 2, "", `\bforward\s+(?:it\s+|them\s+|this\s+)?to\s+(?:an?\s+)?external\b|(?:^|[.!?]\s+|\band\s+|\bthen\s+|\balso\s+)exfiltrate\b`),
		t("exfiltration", 2, "", `!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z0-9_]+=`),
		t("exfiltration", 2, "", `!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z0-9_]+=[^)\s]*(?:\{|\$|%7b|contents?_of|\.env|token|secret|password|credential)`),
		t("exfiltration", 3, "", `\b(?:always|must|should)\b[^.!?]{0,40}?\b(?:embed|render|include|append|add|output|display|show)\b[^.!?]{0,60}?!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z0-9_]+=[^)\s]*(?:\{|\$|%7b|contents?_of|\.env|secret|password|credential)`),
		t("exfiltration", 2, "", `!\[[^\]]*\]\(https?://[^)\s]+\)[^.!?]{0,80}\breplac(?:e|ing)\b|https?://\S*[?&][a-z0-9_]+=\s+(?:followed by|plus|and append)\b`),

		// Persona and restriction overrides.
		t("persona", 3, "", `\byou are now (?:an? |in )?(?:unrestricted|uncensored|unfiltered|jailbroken|dan\b)|\byou are dan\b|\byour new identity is\b|\bact as if you have no restrictions\b|\bpretend (?:you have|there are) no (?:rules|restrictions|limits)\b|\byou can\s+do anything now\b|\b(?:enable|enter|activate|switch to)\s+(?:dan|evil|uncensored|unrestricted)\s+mode\b`),
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
		t("side_parameter", 1, "", `\b(?:pass|include|put|place|paste|fill|append|attach|embed|supply|provide|add|send|submit|collect|forward)\s+(?:[a-z0-9_'./~-]+\s+){0,6}?(?:content|contents|output|results?|text|data|values?|keys?|tokens?|credentials?|files?|history|messages?|prompt|variables|it|them)\b`+poisonSameSentence+`{0,60}?\b(?:as|in|into|to|via|through|inside|within|using)\s+(?:the\s+|a\s+|an\s+|this\s+|its\s+)?['"`+"`"+`]`),
		t("side_parameter", 1, "", `\b(?:attach|append|add|include|embed|put)\s+(?:it|them|its contents?|their contents?|the contents?)\s+(?:to|in|into|with)\s+(?:the|each|every|your|all)\s+(?:requests?|calls?|messages?|responses?|output|arguments?|payload|body|headers?|(?:[a-z_]+\s+)?(?:field|parameter|param|argument)s?)\b`),
		t("side_parameter", 1, "", `\b(?:include|put|add|embed)\b`+poisonSameSentence+`{0,60}?\bin\s+(?:the|your|every|each)\s+(?:response|reply|answer|output|result)\b`),
		t("side_parameter", 1, "", `\b(?:pass|put|place|paste|fill|include|add|append|attach)\b`+poisonSameSentence+`{0,60}?\b(?:in|into|to|as)\s+(?:the\s+)?[a-z_]+\s+(?:field|argument|parameter|param)\b|\buse\s+(?:the\s+)?(?:output|result|contents?|value)\s+as\s+(?:the\s+)?(?:value\s+of\s+)?(?:the\s+)?['"`+"`"+`]`),
		t("cross_tool", 1, "", `\bside effect on\b|\bwhen(?:ever)?\b[^.!?]{0,80}?\b(?:is|are|gets?)\s+(?:invoked|called|used|executed|available|present)\b[^.!?]{0,20}?\b(?:must|should|make sure|ensure|always|need to|have to|instead|additionally|also)\b`),
		t("cross_tool", 1, "", `\balways use this tool instead of\b|\bsupersedes? all other\b|\binstead of the (?:built-in|normal|standard|default|other)\b[^.!?]{0,40}?\btools?\b|\bnever (?:use|call) the other\b`),
		t("cross_tool", 1, "", `\b(?:change|replace|swap|rewrite|modify|override)\s+(?:the\s+)?(?:recipient|destination|receiver|payee|beneficiary|amount|withdrawal address|bcc|cc)\b`),
	}
}

// Naming a credential store describes a tool ("Reads ~/.ssh/config"). Passing
// the contents of a credential file to a parameter or an address in the same
// sentence does not. Sensitive context needs more than a parameter to land
// in: ordinary tools pass messages and environment variables as arguments.
var (
	poisonReadsCredentialStore  = regexp.MustCompile(poisonReadVerb + poisonSameSentence + `{0,60}?` + poisonCredentialStore)
	poisonReadsSensitiveContext = regexp.MustCompile(poisonReadVerb + poisonSameSentence + `{0,60}?` + poisonSensitiveContext)
	poisonPassesCredentialFile  = regexp.MustCompile(poisonReadVerb + poisonSameSentence + `{0,60}?` + poisonCredentialFile + poisonSameSentence + `{0,80}?` + poisonPassesContents +
		`|\b(?:sends?|emails?|uploads?|posts?|forwards?|cop(?:y|ies)|transmits?)\b` + poisonSameSentence + `{0,40}?` + poisonCredentialFile + poisonSameSentence + `{0,40}?\bto\s+` + poisonDestination +
		`|\b(?:append|attach|add|include|put|embed|pass|send|supply|provide|fill|collect|gather|copy|upload)\b` + poisonSameSentence + `{0,30}?\bcontents?\s+of\s+\S{0,12}` + poisonCredentialFile + `(?:\.pub\b)?`)
	strictCredentialFile = regexp.MustCompile(poisonCredentialFile + `\S{0,12}`)
	notACredential       = regexp.MustCompile(`\.pub\b|\.ssh/config\b|known_hosts|authorized_keys`)
	// With a request for silence, a .env file counts as a credential file too.
	namesCredentialFile = regexp.MustCompile(poisonCredentialFile + `|(?:^|[\s/~"'` + "`" + `(])\.env\b`)
	namesDestination    = regexp.MustCompile(poisonDestination)
	// Data copied to a mailbox, a phone number, a wallet or a bucket, rather
	// than posted to the tool's own service.
	sendsACopy         = regexp.MustCompile(`\bcop(?:y|ies)\s+of\b|\ba\s+copy\b|\bevery\s+file\b|\bto\s+(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+[0-9][0-9 ().-]{6,}[0-9]|(?:s3|gs|ftp)://)`)
	poisonObeysDecoded = regexp.MustCompile(`\b(?:decode|decrypt|deobfuscate|un-?base64|base64[- ]?decode|hex[- ]?decode)\b[^.!?]{0,80}?\b(?:(?:follow|obey|carry out|act on)\s+(?:it|them|the\s+(?:decoded\s+)?(?:instructions|steps|commands|text|result))\b|do what it says)`)
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
	apostrophe       = regexp.MustCompile(`([a-z])'([a-z])`)
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
	hidden    bool   // carried text that never renders, or reorders what is shown
	concealed bool   // styled so that it cannot be read: concealed, or one colour on itself
	zeroWidth int    // zero-width characters splitting Latin words
	mixed     int    // words that mix Latin letters with look-alikes from another script
	control   int    // stray control characters and terminal styling codes
}

// ansiConceals reports whether a terminal styling sequence makes text
// unreadable: the conceal attribute, or the same colour for text and
// background. Other colours and weights only style text.
func ansiConceals(sequence string) bool {
	if !strings.HasSuffix(sequence, "m") {
		return false
	}
	parameters := strings.Split(strings.TrimSuffix(strings.TrimPrefix(sequence, "\x1b["), "m"), ";")
	foreground, background := -1, -1
	for i := 0; i < len(parameters); i++ {
		switch value := parameters[i]; {
		case value == "38" || value == "48":
			// Extended colour: 38;5;n or 38;2;r;g;b. Its arguments are not attributes.
			if i+1 < len(parameters) && parameters[i+1] == "5" {
				i += 2
			} else if i+1 < len(parameters) && parameters[i+1] == "2" {
				i += 4
			}
		case value == "8":
			return true
		case len(value) == 2 && (value[0] == '3' || value[0] == '9') && value[1] >= '0' && value[1] <= '7':
			foreground = int(value[1] - '0')
		case len(value) == 2 && value[0] == '4' && value[1] >= '0' && value[1] <= '7':
			background = int(value[1] - '0')
		case len(value) == 3 && value[:2] == "10" && value[2] >= '0' && value[2] <= '7':
			background = int(value[2] - '0')
		}
	}
	return foreground >= 0 && foreground == background
}

// subdivisionFlags are the flag emoji written as a black flag, tag
// characters and a cancel tag. Any other tag sequence is hidden text.
var subdivisionFlags = map[string]bool{"gbeng": true, "gbsct": true, "gbwls": true}

// flagEmojiLength returns how many characters after a black flag complete a
// subdivision flag, or zero when what follows is not one.
func flagEmojiLength(following []rune) int {
	var code []rune
	for i, r := range following {
		switch {
		case r == 0xE007F:
			if subdivisionFlags[string(code)] {
				return i + 1
			}
			return 0
		case r < 0xE0020 || r > 0xE007E || i >= 7:
			return 0
		}
		code = append(code, r-0xE0000)
	}
	return 0
}

// invisible reports whether a character occupies no space when rendered:
// zero-width and format characters, variation selectors, the combining
// grapheme joiner. Removing them keeps a phrase split by them matchable.
func invisible(r rune) bool {
	switch {
	case r == 0x00AD || r == 0x034F || r == 0x180E:
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

// normalizeDefinition lower-cases a definition, removes characters that do not
// render, and reports whether it relied on them. Text hidden in the Unicode
// tag block is decoded, and look-alike and fullwidth letters are folded to
// Latin, so that all of it is inspected like visible text.
//
// Characters that do not render are common in ordinary text: a stray control
// character from an unescaped docstring, colour codes in help text, isolates
// around right-to-left words, the tag sequence of a flag emoji, a joiner in
// Persian or in an emoji. Only uses that hide or split text count for much.
func normalizeDefinition(raw string) definitionText {
	var d definitionText
	if strings.Contains(raw, "\x1b") {
		for _, sequence := range ansiEscape.FindAllString(raw, -1) {
			if ansiConceals(sequence) {
				d.concealed = true
			} else {
				d.control++
			}
		}
		raw = ansiEscape.ReplaceAllString(raw, " ")
	}
	var b strings.Builder
	b.Grow(len(raw))
	tagCharacters, invisibleRun := 0, 0
	wordLatin, wordFolded := false, false
	previousLatin, pendingInvisible := false, 0
	endWord := func() {
		if wordLatin && wordFolded {
			d.mixed++
		}
		wordLatin, wordFolded = false, false
	}
	// emit writes one visible character and settles whether the invisible
	// characters before it sat inside a Latin word.
	emit := func(r rune) {
		latin := r >= 'a' && r <= 'z'
		if latin && previousLatin {
			d.zeroWidth += pendingInvisible
		}
		pendingInvisible, invisibleRun = 0, 0
		previousLatin = latin
		b.WriteRune(r)
	}
	runes := []rune(raw)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= 0xFF01 && r <= 0xFF5E {
			// Fullwidth forms of ASCII.
			r -= 0xFEE0
		}
		switch {
		case r == 0x1F3F4:
			i += flagEmojiLength(runes[i+1:])
			emit(r)
			continue
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
		case invisible(r):
			// One between letters is ordinary in Persian or in an emoji, and
			// web text carries the odd pair; a longer run carries data.
			invisibleRun++
			if invisibleRun >= 8 {
				d.hidden = true
			}
			if previousLatin && r != 0x00AD {
				pendingInvisible++
			}
			continue
		case unicode.IsSpace(r):
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
	// Markdown emphasis inside a phrase ("**ignore** all previous").
	text := strings.NewReplacer("**", "", "__", "").Replace(b.String())
	d.text = whitespaceRun.ReplaceAllString(text, " ")
	return d
}

// namesPrivateCredentialFile reports whether the definition names a
// credential file other than a public key or the SSH client's own files.
func namesPrivateCredentialFile(text string) bool {
	for _, location := range strictCredentialFile.FindAllStringIndex(text, -1) {
		end := location[1] + 12
		if end > len(text) {
			end = len(text)
		}
		if !notACredential.MatchString(text[location[0]:end]) {
			return true
		}
	}
	return false
}

// passesCredentialFile reports whether the definition hands the contents of a
// credential file to a parameter or an address. Public keys and the SSH
// client's own config and host lists are not credentials.
func passesCredentialFile(text string) bool {
	for _, match := range poisonPassesCredentialFile.FindAllString(text, -1) {
		if !notACredential.MatchString(match) {
			return true
		}
	}
	return false
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
		outsideQuotes = quotedSpan.ReplaceAllString(apostrophe.ReplaceAllString(text, "$1 $2"), " ")
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
	case definition.concealed || definition.zeroWidth >= 4 || definition.mixed >= 2 || paddingToHideTxt.MatchString(raw):
		note("hidden_text", 2, "")
	case definition.control > 0 || encodedBlob.MatchString(raw):
		note("hidden_text", 1, "")
	}
	if tool.Truncated {
		// What was not read cannot be shown to an agent.
		note("unscanned", 3, "")
	}

	// Kept from the user: said outright, or styled so it cannot be read.
	concealed := weights["concealment"] >= 2 || definition.concealed
	movesIt := weights["exfiltration"] > 0 || concealed
	readsSensitive := poisonReadsSensitiveContext.MatchString(text)
	sensitive := weights["secret_location"] > 0 || readsSensitive
	switch {
	case passesCredentialFile(text):
		// The contents of a credential file, handed to a parameter or an address.
		note("credential_access", 3, "")
	case concealed && namesCredentialFile.MatchString(text):
		// A credential file and a request for silence, in any language.
		note("credential_access", 3, "")
	case concealed && weights["side_parameter"] > 0 && sensitive:
		// Secrets passed in a parameter, and a request for silence.
		note("credential_access", 3, "")
	case poisonReadsCredentialStore.MatchString(text) && (movesIt || weights["side_parameter"] > 0):
		note("credential_access", 2, "")
	case weights["side_parameter"] > 0 && namesPrivateCredentialFile(text):
		note("credential_access", 2, "")
	case readsSensitive && movesIt:
		note("credential_access", 2, "")
	case concealed && namesCredentialStore.MatchString(text):
		note("credential_access", 2, "")
	}
	// Secrets sent to a named address, or another tool redirected, while
	// keeping it from the user. A setup call that asks not to be narrated and
	// posts a client id to its own service is not this.
	if concealed && ((weights["exfiltration"] > 0 && (sensitive || sendsACopy.MatchString(text))) || weights["redirect"] >= 2) {
		note("concealment", 3, "")
	}
	// Another tool's messages sent to a named address.
	if weights["redirect"] >= 2 && weights["cross_tool"] > 0 && namesDestination.MatchString(text) {
		note("redirect", 3, "")
	}
	// New directives under markup that addresses the agent, telling it to
	// drop a safety policy.
	if weights["markup"] > 0 && weights["injected_instructions"] >= 2 && weights["bypass"] >= 2 {
		note("bypass", 3, "")
	}
	// A payload the agent is told to decode and obey. Decoding input and
	// executing it as a query is what a database tool does.
	if weights["encoded_instructions"] >= 2 && encodedBlob.MatchString(raw) && poisonObeysDecoded.MatchString(text) {
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
	// Suspicious traits are reported. A shape above is critical: an
	// organization that blocks on detections has it removed from Enforce
	// routes. Text that does not render is removed without that setting,
	// because no wording is being judged.
	critical := decisive > 0
	if !critical && strong == 0 && len(weights) < 3 {
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
	if critical {
		result.Severity = "critical"
	}
	result.HardBlock = definition.hidden
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
