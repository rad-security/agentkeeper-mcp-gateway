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
		},
		{
			Name:        "api_key_aws",
			Severity:    "critical",
			Description: "AWS access key ID detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		},
		{
			Name:        "api_key_github",
			Severity:    "critical",
			Description: "GitHub personal access token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`(ghp|gho|ghs|ghr)_[A-Za-z0-9_]{36,}`),
		},
		{
			Name:        "api_key_slack",
			Severity:    "high",
			Description: "Slack API token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`xox[bporas]-[A-Za-z0-9-]+`),
		},
		{
			Name:        "private_key_pem",
			Severity:    "critical",
			Description: "PEM-encoded private key detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`),
		},
		{
			Name:        "credit_card",
			Severity:    "critical",
			Description: "Possible credit card number detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\b[0-9](?:[- ]?[0-9]){12,18}\b`),
		},
		{
			Name:        "ssn",
			Severity:    "critical",
			Description: "Possible US Social Security Number detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
		},
		{
			Name:        "database_uri",
			Severity:    "critical",
			Description: "Database connection URI with credentials detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`(postgresql|mongodb|mysql|redis)://[^\s]+:[^\s]+@`),
		},
		{
			Name:        "jwt_token",
			Severity:    "high",
			Description: "JWT token detected",
			Category:    "sensitive_data",
			Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		},
	}
}

// validCardNumber rejects numeric identifiers that merely have a card-like length.
// Luhn is validation of a candidate, not proof that a card is issued or active.
func validCardNumber(candidate string) bool {
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
