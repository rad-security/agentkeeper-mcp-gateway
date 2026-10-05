package detection

import (
	"strings"
	"unicode"
)

// normalizeScanText returns two views of a piece of content in a single pass:
// a case-preserved form (preserved) and a lowercased, confusable-folded form
// (lower). Both have the characters that do not render removed, fullwidth forms
// folded to ASCII, ANSI styling stripped, and whitespace collapsed. It is the
// argument- and result-scanning counterpart of normalizeDefinition, which
// carries the extra structural signals a tool definition needs. Case is
// preserved in the first form because sensitive-data patterns (AKIA…,
// sk_live_…) are case-sensitive; threat and poison matching uses the folded
// lower form, where a Cyrillic "о" or a Greek "ο" reads as its ASCII twin.
func normalizeScanText(raw string) (preserved, lower string) {
	if raw == "" {
		return "", ""
	}
	if p, l, ok := normalizeASCIIFast(raw); ok {
		return p, l
	}
	if strings.Contains(raw, "\x1b") {
		raw = ansiEscape.ReplaceAllString(raw, " ")
	}
	var pb, lb strings.Builder
	pb.Grow(len(raw))
	lb.Grow(len(raw))
	emit := func(r rune) {
		pb.WriteRune(r)
		lr := unicode.ToLower(r)
		if latin, ok := homoglyphs[lr]; ok {
			lr = latin
		}
		lb.WriteRune(lr)
	}
	runes := []rune(raw)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= 0xFF01 && r <= 0xFF5E {
			// Fullwidth forms of ASCII fold to their ASCII code point.
			r -= 0xFEE0
		}
		switch {
		case r == 0x1F3F4:
			// A black flag starts a subdivision-flag tag sequence; skip the tags
			// that complete it so a flag emoji is not read as hidden text.
			i += flagEmojiLength(runes[i+1:])
			continue
		case r >= 0xE0020 && r <= 0xE007E:
			// Tag block: decoded to the ASCII it mirrors, so hidden text shows.
			emit(r - 0xE0000)
			continue
		case r == 0xE0001 || r == 0xE007F:
			continue
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			// Bidi embeddings, overrides and isolates: dropped.
			continue
		case invisible(r):
			continue
		case unicode.IsSpace(r):
			pb.WriteByte(' ')
			lb.WriteByte(' ')
			continue
		case r < 0x20 || r == 0x7F:
			pb.WriteByte(' ')
			lb.WriteByte(' ')
			continue
		case r == '’' || r == '‘':
			pb.WriteByte('\'')
			lb.WriteByte('\'')
			continue
		case r == '“' || r == '”':
			pb.WriteByte('"')
			lb.WriteByte('"')
			continue
		}
		emit(r)
	}
	replacer := strings.NewReplacer("**", "", "__", "")
	preserved = strings.TrimSpace(whitespaceRun.ReplaceAllString(replacer.Replace(pb.String()), " "))
	lower = strings.TrimSpace(whitespaceRun.ReplaceAllString(replacer.Replace(lb.String()), " "))
	return preserved, lower
}

// normalizeASCIIFast handles the overwhelmingly common case — content that is
// plain ASCII with no ESC byte and no markdown-emphasis runs — with a single
// byte pass instead of decoding the whole message into runes, producing the
// case-preserved and lowercased forms together. Control bytes become spaces and
// whitespace runs collapse. It reports ok=false for anything that needs the
// full rune-aware path (non-ASCII, an ESC byte, or ** / __).
func normalizeASCIIFast(raw string) (preserved, lower string, ok bool) {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 0x80 || c == 0x1b {
			return "", "", false
		}
		if c == '*' && i+1 < len(raw) && raw[i+1] == '*' {
			return "", "", false
		}
		if c == '_' && i+1 < len(raw) && raw[i+1] == '_' {
			return "", "", false
		}
	}
	var pb, lb strings.Builder
	pb.Grow(len(raw))
	lb.Grow(len(raw))
	pendingSpace := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c <= ' ' || c == 0x7F {
			pendingSpace = pb.Len() > 0
			continue
		}
		if pendingSpace {
			pb.WriteByte(' ')
			lb.WriteByte(' ')
			pendingSpace = false
		}
		pb.WriteByte(c)
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lb.WriteByte(c)
	}
	return pb.String(), lb.String(), true
}

// foldConfusablesLower lowercases a normalized view and folds look-alike letters
// from other scripts to Latin. It is used where only the lower form is needed
// (for example re-folding a value for session correlation); the normalization
// path produces both forms together.
func foldConfusablesLower(text string) string {
	ascii := true
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		var b strings.Builder
		b.Grow(len(text))
		for i := 0; i < len(text); i++ {
			c := text[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
		}
		return b.String()
	}
	lower := strings.ToLower(text)
	var b strings.Builder
	b.Grow(len(lower))
	for _, r := range lower {
		if latin, ok := homoglyphs[r]; ok {
			b.WriteRune(latin)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
