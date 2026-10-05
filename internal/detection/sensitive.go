package detection

import "regexp"

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
			Regex:       regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}`),
			Triggers:    []string{"aws_secret_access_key"},
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
	}
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
