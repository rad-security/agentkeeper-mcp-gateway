package session

import "strings"

// Contact details (email addresses and phone numbers) a tool returned are
// remembered so that sending them on to another tool is recognised. Only a
// contact record is remembered, a result that carries both an email address
// and a phone number: a list of addresses alone (a channel's members, an
// inbox) is ordinary input to the next tool. A call is reported when it
// carries at least two of the remembered details to a destination they did
// not come from. Like secrets, only hashes are kept.

// phoneNumbers returns the digits of each phone number in text, up to limit.
// A number has 7 to 15 digits in at most five groups, at least one of three
// or more digits, and is written with separators or a leading +, so a bare
// id, a date or an address is not read as one. It is a single pass: results
// are scanned on every call, and a regular expression over a large one costs
// tens of milliseconds.
func phoneNumbers(text string, limit int) []string {
	var out []string
	for i := 0; i < len(text) && len(out) < limit; i++ {
		c := text[i]
		if !isDigit(c) && c != '+' && c != '(' {
			continue
		}
		// A number starts at a boundary, not inside a word or a longer number.
		if i > 0 && (isDigit(text[i-1]) || isLetter(text[i-1])) {
			continue
		}
		end, lastDigit := i, -1
		for end < len(text) && end-i < 24 && (isDigit(text[end]) || strings.IndexByte(" ().-+", text[end]) >= 0) {
			if text[end] == '+' && end != i {
				break
			}
			if isDigit(text[end]) {
				lastDigit = end
			}
			end++
		}
		if lastDigit < 0 {
			continue
		}
		candidate := text[i : lastDigit+1]
		i = lastDigit
		if digits, ok := phoneDigits(candidate); ok {
			out = append(out, digits)
		}
	}
	return out
}

func phoneDigits(candidate string) (string, bool) {
	if isISODateShape(candidate) || isIPv4Shape(candidate) {
		return "", false
	}
	groups := strings.FieldsFunc(candidate, func(r rune) bool { return r < '0' || r > '9' })
	digits := strings.Join(groups, "")
	if len(digits) < 7 || len(digits) > 15 || len(groups) > 5 {
		return "", false
	}
	if len(groups) < 2 && !strings.HasPrefix(candidate, "+") {
		return "", false
	}
	longest := 0
	for _, group := range groups {
		if len(group) > longest {
			longest = len(group)
		}
	}
	return digits, longest >= 3
}

func isISODateShape(s string) bool {
	return len(s) >= 10 && isDigits(s[0:4]) && s[4] == '-' && isDigits(s[5:7]) && s[7] == '-' && isDigits(s[8:10])
}

func isIPv4Shape(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 || !isDigits(part) {
			return false
		}
	}
	return true
}

// emailAddresses returns the lower-cased email addresses in text, up to
// limit, found from each @ in a single pass.
func emailAddresses(text string, limit int) []string {
	var out []string
	for at := strings.IndexByte(text, '@'); at >= 0 && len(out) < limit; {
		start := at
		for start > 0 && at-start < 64 && isEmailLocalByte(text[start-1]) {
			start--
		}
		end := at + 1
		for end < len(text) && end-at < 254 && (isLetter(text[end]) || isDigit(text[end]) || text[end] == '.' || text[end] == '-') {
			end++
		}
		domain := strings.TrimRight(text[at+1:end], ".-")
		dot := strings.LastIndexByte(domain, '.')
		if start < at && dot > 0 && len(domain)-dot-1 >= 2 && isLetters(domain[dot+1:]) {
			out = append(out, strings.ToLower(text[start:at+1]+domain))
		}
		next := strings.IndexByte(text[at+1:], '@')
		if next < 0 {
			break
		}
		at += 1 + next
	}
	return out
}

func isEmailLocalByte(c byte) bool {
	return isLetter(c) || isDigit(c) || strings.IndexByte("._%+-", c) >= 0
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

func isLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isLetter(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

// rememberContacts keeps the email addresses and phone numbers of a result
// that reads as a contact record.
func (t *Tracker) rememberContacts(server, tool, raw string) {
	text := truncate(raw, maxContactScanBytes)
	emails := emailAddresses(text, maxContactsPerResult)
	if len(emails) == 0 {
		return
	}
	phones := phoneNumbers(text, maxContactsPerResult)
	if len(phones) == 0 {
		return
	}
	for _, value := range append(emails, phones...) {
		hash := hash64("contact:" + value)
		known := false
		for _, c := range t.contacts {
			if c.hash == hash {
				known = true
				break
			}
		}
		if known {
			continue
		}
		if len(t.contacts) >= maxRememberedContacts {
			t.contacts = t.contacts[1:]
		}
		t.contacts = append(t.contacts, rememberedContact{hash: hash, server: server, tool: tool})
	}
}

// checkContactEgress reports a call that carries at least two remembered
// contact details to a destination they did not come from: a different
// server, or the same server's egress-shaped tool. views are the call's
// normalized and decoded argument texts.
func (t *Tracker) checkContactEgress(server, tool string, views []string) *Finding {
	if len(t.contacts) == 0 {
		return nil
	}
	sent := map[uint64]bool{}
	for _, view := range views {
		for _, value := range append(emailAddresses(view, maxContactsPerResult), phoneNumbers(view, maxContactsPerResult)...) {
			sent[hash64("contact:"+value)] = true
		}
	}
	lowerTool := strings.ToLower(tool)
	matched := 0
	var source rememberedContact
	counted := map[uint64]bool{}
	for _, c := range t.contacts {
		if !sent[c.hash] || counted[c.hash] {
			continue
		}
		differentServer := !strings.EqualFold(c.server, server)
		egressTool := !strings.EqualFold(c.tool, tool) && containsVerb(lowerTool, egressVerbs)
		if !differentServer && !egressTool {
			continue
		}
		counted[c.hash] = true
		if matched == 0 {
			source = c
		}
		matched++
	}
	if matched < minContactsSent {
		return nil
	}
	return &Finding{
		Pattern:     patternContactEgress,
		Severity:    severityHigh,
		Category:    categorySensitiveData,
		Description: "Contact details returned by " + source.server + "/" + source.tool + " earlier in this session are being sent to " + server + "/" + tool + ".",
		Correlation: map[string]interface{}{
			"source_server": source.server,
			"source_tool":   source.tool,
			"steps": []map[string]interface{}{
				{"role": "source", "server": source.server, "tool": source.tool, "detail": "contact details"},
				{"role": "egress", "server": server, "tool": tool},
			},
		},
	}
}
