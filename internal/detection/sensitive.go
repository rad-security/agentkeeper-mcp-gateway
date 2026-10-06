package detection

import (
	"regexp"
	"strings"
)

// compileSensitiveDataPatterns returns compiled patterns for detecting
// PII, secrets, and other sensitive data in MCP tool call content.
func compileSensitiveDataPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "api_key_stripe",
			Severity:    "critical",
			Description: "Stripe live API key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
			Triggers:    []string{"sk_live_"},
		},
		{
			Name:        "api_key_aws",
			Severity:    "critical",
			Description: "AWS access key ID detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Triggers:    []string{"akia"},
		},
		{
			Name:        "api_key_github",
			Severity:    "critical",
			Description: "GitHub personal access token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{50,}`),
			Triggers:    []string{"ghp_", "gho_", "ghs_", "ghr_", "ghu_", "github_pat_"},
		},
		{
			Name:        "api_key_anthropic",
			Severity:    "critical",
			Description: "Anthropic API key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{32,}`),
			Triggers:    []string{"sk-ant-"},
		},
		{
			Name:        "api_key_openai",
			Severity:    "critical",
			Description: "OpenAI API key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}`),
			Triggers:    []string{"sk-"},
		},
		{
			Name:        "api_key_google",
			Severity:    "critical",
			Description: "Google API key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`),
			Triggers:    []string{"aiza"},
		},
		{
			Name:        "api_key_aws_secret",
			Severity:    "critical",
			Description: "AWS secret access key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})`),
			Triggers:    []string{"aws_secret_access_key"},
			// The value alone, as the generic assignment rule keeps it, so the
			// two remember one secret.
			Extract: firstGroup,
		},
		{
			Name:        "api_key_npm",
			Severity:    "high",
			Description: "npm access token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
			Triggers:    []string{"npm_"},
		},
		{
			Name:        "api_key_slack",
			Severity:    "high",
			Description: "Slack API token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`xox[bporas]-[A-Za-z0-9-]+`),
			Triggers:    []string{"xox"},
		},
		{
			Name:        "private_key_pem",
			Severity:    "critical",
			Description: "PEM-encoded private key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----`),
			Triggers:    []string{"-----begin"},
		},
		{
			Name:        "credit_card",
			Severity:    "critical",
			Description: "Possible credit card number detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\b[0-9](?:[- ]?[0-9]){12,18}\b`),
			Prefilter:   hasCardShape,
			Extract: func(content string, match []int) (string, bool) {
				candidate := content[match[0]:match[1]]
				return candidate, validCardCandidate(candidate)
			},
		},
		{
			Name:        "ssn",
			Severity:    "critical",
			Description: "Possible US Social Security Number detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
			Prefilter:   hasSSNShape,
		},
		{
			Name:        "database_uri",
			Severity:    "critical",
			Description: "Database connection URI with credentials detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`(postgresql|mongodb|mysql|redis)://[^\s]+:[^\s]+@`),
			Triggers:    []string{"postgresql://", "mongodb://", "mysql://", "redis://"},
		},
		{
			Name:        "jwt_token",
			Severity:    "high",
			Description: "JWT token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Triggers:    []string{"eyj"},
		},
		// Last, so a provider pattern matching the same text is the primary
		// finding. The id is the cloud evaluator's, which flags the same
		// assignments in arguments.
		{
			Name:        "leaked_secret_generic_assignment",
			Severity:    "high",
			Description: "Secret, token, password, or API key assignment detected",
			Category:    "sensitive_data",
			Triggers:    []string{"token", "secret", "api_key", "api-key", "apikey", "password", "passwd", "private_key", "private-key", "privatekey"},
			Find:        genericSecretAssignments,
			Extract:     genericSecretValue,
		},
	}
}

func firstGroup(content string, match []int) (string, bool) {
	return content[match[2]:match[3]], true
}

// genericSecretAssignments finds values assigned to secret-named keys, as in
// API_TOKEN=..., "client_secret": "...", X-Api-Key: ... or a JSON-escaped
// \"password\":\"...\": a key (letters, digits, _ and -) containing token,
// secret, api_key, password, passwd or private_key in any case; then an
// optional backslash and quote, spaces, ":", "=" or ":=", spaces, an optional
// backslash and quote; then a value of at least 12 characters from
// [A-Za-z0-9._~+/@=-]. These are the cloud evaluator's key words, value
// characters and minimum length. Each match is reported as submatch indexes:
// the assignment, the key, the value.
//
// It is a single pass over the content rather than a regular expression,
// which on a large result that mentions tokens throughout costs many times the
// scan budget.
func genericSecretAssignments(content string) [][]int {
	var matches [][]int
	covered := 0
	for i := 0; i < len(content); i++ {
		if i < covered || !secretKeyWordAt(content, i) {
			continue
		}
		start := i
		for start > covered && isKeyByte(content[start-1]) {
			start--
		}
		keyEnd := i
		for keyEnd < len(content) && isKeyByte(content[keyEnd]) {
			keyEnd++
		}
		// Any other key word in this key gives the same assignment.
		covered = keyEnd
		valueStart, ok := assignedValueStart(content, keyEnd)
		if !ok {
			continue
		}
		valueEnd := valueStart
		for valueEnd < len(content) && isSecretValueByte(content[valueEnd]) {
			valueEnd++
		}
		if valueEnd-valueStart < genericSecretMinLen {
			continue
		}
		matches = append(matches, []int{start, valueEnd, start, keyEnd, valueStart, valueEnd})
		covered = valueEnd
	}
	return matches
}

// assignedValueStart reads the separator after a key and returns where the
// value starts.
func assignedValueStart(content string, i int) (int, bool) {
	i = skipSpaces(content, skipQuote(content, i))
	switch {
	case strings.HasPrefix(content[i:], ":="):
		i += 2
	case i < len(content) && (content[i] == ':' || content[i] == '='):
		i++
	default:
		return 0, false
	}
	return skipQuote(content, skipSpaces(content, i)), true
}

func skipQuote(content string, i int) int {
	if i < len(content) && content[i] == '\\' {
		i++
	}
	if i < len(content) && (content[i] == '"' || content[i] == '\'') {
		i++
	}
	return i
}

func skipSpaces(content string, i int) int {
	for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r' || content[i] == '\f') {
		i++
	}
	return i
}

// secretKeyWordAt reports whether a secret key word starts at content[i],
// ignoring case.
func secretKeyWordAt(content string, i int) bool {
	rest := content[i:]
	switch lowerASCII(content[i]) {
	case 't':
		return hasPrefixFold(rest, "token")
	case 's':
		return hasPrefixFold(rest, "secret")
	case 'a':
		return hasPrefixFold(rest, "apikey") || hasPrefixFold(rest, "api_key") || hasPrefixFold(rest, "api-key")
	case 'p':
		return hasPrefixFold(rest, "password") || hasPrefixFold(rest, "passwd") ||
			hasPrefixFold(rest, "privatekey") || hasPrefixFold(rest, "private_key") || hasPrefixFold(rest, "private-key")
	}
	return false
}

func hasPrefixFold(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for j := 0; j < len(lowerPrefix); j++ {
		if lowerASCII(s[j]) != lowerPrefix[j] {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isSecretValueByte(c byte) bool {
	switch c {
	case '.', '_', '~', '+', '/', '@', '=', '-':
		return true
	}
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

const genericSecretMinLen = 12

// nonSecretKeyWords mark a key that holds something about a secret rather
// than the secret: a page or sync cursor (nextPageToken, NextToken), an id, a
// name or type, or where the secret is kept.
var nonSecretKeyWords = map[string]bool{
	"page": true, "cursor": true, "next": true, "continuation": true, "sync": true, "resume": true,
	"csrf": true, "xsrf": true, "id": true, "name": true, "type": true,
	"path": true, "file": true, "dir": true, "url": true, "uri": true, "endpoint": true,
}

// placeholderMarkers stand in for a value in documentation and templates.
var placeholderMarkers = []string{"your", "placeholder", "changeme", "change_me", "change-me", "replace", "redacted", "xxxxxx", "insert"}

// secretPathMarkers name a secret's location (projects/1/secrets/db,
// /var/run/secrets/token) rather than its value.
var secretPathMarkers = []string{"/secret", "secret/", "secrets/", "/token", "token/", "tokens/"}

// genericSecretValue reports the value of a generic assignment, or rejects an
// assignment that does not hold a secret: a reference to one in code
// (settings.API_KEY, os.environ.get(...)), a placeholder, a word, name or path,
// a count, or a timestamp.
func genericSecretValue(content string, match []int) (string, bool) {
	if nonSecretKey(content[match[2]:match[3]]) {
		return "", false
	}
	if match[5] < len(content) && content[match[5]] == '(' {
		// A call: token = fetch_token(...).
		return "", false
	}
	value := strings.TrimRight(content[match[4]:match[5]], ".")
	if len(value) < genericSecretMinLen || !secretShapedValue(value) {
		return "", false
	}
	return value, true
}

func nonSecretKey(key string) bool {
	for _, word := range keyWords(key) {
		if nonSecretKeyWords[word] {
			return true
		}
	}
	return false
}

// keyWords splits a key into lowercase words: NEXT_PAGE_TOKEN,
// next-page-token and nextPageToken all give next, page, token.
func keyWords(key string) []string {
	var words []string
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(key[start:end]))
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '_' || c == '-':
			flush(i)
			start = i + 1
		case c >= 'A' && c <= 'Z' && i > start && key[i-1] >= 'a' && key[i-1] <= 'z':
			flush(i)
			start = i
		}
	}
	flush(len(key))
	return words
}

func secretShapedValue(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, marker := range secretPathMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	digits, upper, lowerCase := 0, 0, 0
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lowerCase++
		}
	}
	switch {
	case digits == len(value):
		// A count, an id or an epoch time.
		return false
	case digits == 0 && (upper == 0 || lowerCase == 0):
		// A word, name or path: secretName: tls-secret-production.
		return false
	case digits == 0 && strings.Contains(value, "."):
		// A reference in code: settings.API_KEY, process.env.API_TOKEN.
		return false
	case isISODate(value):
		// A timestamp: PasswordLastUsed: 2026-01-02T03:04:05Z.
		return false
	}
	return true
}

func isISODate(value string) bool {
	return len(value) >= 10 && isASCIIDigits(value[0:4]) && value[4] == '-' &&
		isASCIIDigits(value[5:7]) && value[7] == '-' && isASCIIDigits(value[8:10])
}

// hasCardShape reports whether a run of digits long enough to be a card number
// (13+ digits, single spaces or dashes allowed between them) is present. The
// credit-card regex and its Luhn/issuer validation run only then.
func hasCardShape(_, lower string) bool {
	digits := 0
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			if digits >= 13 {
				return true
			}
		case (c == ' ' || c == '-') && i > 0 && i+1 < len(lower) &&
			isASCIIDigit(lower[i-1]) && isASCIIDigit(lower[i+1]):
			// A single separator between digits keeps the run going.
		default:
			digits = 0
		}
	}
	return false
}

// hasSSNShape reports whether a ddd-dd-dddd token is present, gating the SSN
// regex.
func hasSSNShape(_, lower string) bool {
	for i := 0; i+11 <= len(lower); i++ {
		if isASCIIDigits(lower[i:i+3]) && lower[i+3] == '-' &&
			isASCIIDigits(lower[i+4:i+6]) && lower[i+6] == '-' &&
			isASCIIDigits(lower[i+7:i+11]) {
			return true
		}
	}
	return false
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isASCIIDigit(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

// validCardNumber rejects numeric identifiers that merely have a card-like
// length. A candidate must carry an issuer prefix with a length that issuer
// uses, and pass the checksum: timestamps and database ids pass the checksum
// alone one time in ten.
func validCardNumber(candidate string) bool {
	digits := make([]byte, 0, len(candidate))
	for i := 0; i < len(candidate); i++ {
		if c := candidate[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	return luhnValid(candidate) && cardIssuerLength(string(digits))
}

// cardIssuerLength reports whether the digits start with a card network's
// prefix and have a length that network issues.
func cardIssuerLength(digits string) bool {
	n := len(digits)
	prefix := func(length int) int {
		value := 0
		for i := 0; i < length && i < n; i++ {
			value = value*10 + int(digits[i]-'0')
		}
		return value
	}
	p1, p2, p3, p4 := prefix(1), prefix(2), prefix(3), prefix(4)
	switch {
	case p1 == 4: // Visa
		return n == 13 || n == 16 || n == 19
	case (p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720): // Mastercard
		return n == 16
	case p2 == 34 || p2 == 37: // American Express
		return n == 15
	case p4 == 6011 || p2 == 65 || (p3 >= 644 && p3 <= 649): // Discover
		return n >= 16 && n <= 19
	case p4 >= 3528 && p4 <= 3589: // JCB
		return n >= 16 && n <= 19
	case (p3 >= 300 && p3 <= 305) || p2 == 36 || p2 == 38 || p2 == 39: // Diners Club
		return n >= 14 && n <= 19
	case p2 == 62: // UnionPay
		return n >= 16 && n <= 19
	}
	return false
}

// luhnValid is validation of a candidate, not proof that a card is issued or active.
func luhnValid(candidate string) bool {
	var digits []int
	nonzero := false
	for _, c := range candidate {
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits = append(digits, int(c-'0'))
		nonzero = nonzero || c != '0'
	}
	if len(digits) < 13 || len(digits) > 19 || !nonzero {
		return false
	}
	sum := 0
	for i, doubled := len(digits)-1, false; i >= 0; i, doubled = i-1, !doubled {
		n := digits[i]
		if doubled {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// A greedy candidate can include a following CVV separated by whitespace.
// Consider complete delimited PANs as well, without truncating a contiguous
// longer numeric identifier into a shorter, accidentally valid number.
func validCardCandidate(candidate string) bool {
	if validCardNumber(candidate) {
		return true
	}
	for i, c := range candidate {
		if (c == ' ' || c == '-') && validCardNumber(candidate[:i]) {
			return true
		}
	}
	return false
}
