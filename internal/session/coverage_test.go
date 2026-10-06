package session

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

func reversedOf(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func rot13Of(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// A secret sent on reversed or ROT13-encoded is recognised like one sent as
// it was returned, whole or in segments.
func TestTransformedSecretEgress(t *testing.T) {
	cases := map[string]func(secret string) map[string]interface{}{
		"reversed": func(s string) map[string]interface{} { return map[string]interface{}{"payload": reversedOf(s)} },
		"rot13":    func(s string) map[string]interface{} { return map[string]interface{}{"payload": rot13Of(s)} },
		"reversed in segments": func(s string) map[string]interface{} {
			r := reversedOf(s)
			return map[string]interface{}{"a": r[:20], "b": r[18:]}
		},
		"base64 of reversed": func(s string) map[string]interface{} {
			return map[string]interface{}{"payload": base64.StdEncoding.EncodeToString([]byte(reversedOf(s)))}
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			tr, e := newTracker()
			secret := rememberServiceSecret(t, tr, e)
			if f := tr.InspectCall("sink", "submit", args(secret)); f == nil || f.Pattern != patternSecretEgress {
				t.Fatalf("transformed egress not flagged: %+v", f)
			}
		})
	}
}

func rememberShortSecret(t *testing.T, tr *Tracker, e *detection.Engine, value string) {
	t.Helper()
	result := "pin settings:\nLAB_PIN_TOKEN=" + value + "\n"
	tr.ObserveContent("config", "read_settings", result, e.ScanToolResponse("config", "read_settings", result))
}

// A secret of 12 to 15 characters is recognised when it is sent on whole, in
// one call or a few characters per call, but not from part of it.
func TestShortSecretEgress(t *testing.T) {
	for _, value := range []string{"Lab2026Secret", "Pin2026xyzQ"[:11] + "9"} {
		tr, e := newTracker()
		rememberShortSecret(t, tr, e, value)
		if f := tr.InspectCall("sink", "submit", map[string]interface{}{"handoff": value}); f == nil {
			t.Fatalf("%q sent whole was not flagged", value)
		}
	}
	tr, e := newTracker()
	rememberShortSecret(t, tr, e, "Lab2026Secret")
	if f := tr.InspectCall("sink", "submit", map[string]interface{}{"note": "Lab2026"}); f != nil {
		t.Fatalf("part of a short secret was flagged: %+v", f)
	}
	tr, e = newTracker()
	rememberShortSecret(t, tr, e, "Lab2026Secret")
	if at, flags := sendValueInPieces(tr, "Lab2026Secret", "archive", "store_pair", 3); at < 0 || flags != 1 {
		t.Fatalf("short secret three characters per call: first flag at %d, %d flags", at, flags)
	}
}

const contactRecord = `{"content":[{"type":"text","text":"name: Alex Example\nemail: alex@example.test\nphone: +1-555-0100\nteam: platform"}]}`

func rememberContact(t *testing.T, tr *Tracker, e *detection.Engine) {
	t.Helper()
	if f := tr.ObserveContent("crm", "get_contact", contactRecord, e.ScanToolResponse("crm", "get_contact", contactRecord)); f != nil {
		t.Fatalf("reading a contact should not itself flag: %+v", f)
	}
}

// Contact details one tool returned, sent on to another, are reported as
// sensitive data.
func TestContactDetailsSentOn(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"as written":               {"diagnostics": "Contact: Alex Example, alex@example.test, +1-555-0100"},
		"reformatted":              {"email": "ALEX@example.test", "phone": "+1 (555) 0100"},
		"base64":                   {"blob": base64.StdEncoding.EncodeToString([]byte("alex@example.test / +1-555-0100"))},
		"same server, egress tool": {"to": "alex@example.test", "sms": "+1 555 0100"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			tr, e := newTracker()
			rememberContact(t, tr, e)
			server, tool := "sink", "submit_diagnostics"
			if name == "same server, egress tool" {
				server, tool = "crm", "send_message"
			}
			f := tr.InspectCall(server, tool, args)
			if f == nil || f.Pattern != patternContactEgress {
				t.Fatalf("contact egress not flagged: %+v", f)
			}
			if r := f.Result(); r.Category != categorySensitiveData || r.Severity != severityHigh {
				t.Fatalf("result = %+v, want sensitive_data, high", r)
			}
			if f.Correlation["source_tool"] != "get_contact" {
				t.Fatalf("correlation missing source: %+v", f.Correlation)
			}
		})
	}
}

func TestContactDetailsNotReported(t *testing.T) {
	// One detail alone, or details going back to where they came from.
	tr, e := newTracker()
	rememberContact(t, tr, e)
	if f := tr.InspectCall("calendar", "create_event", map[string]interface{}{"attendee": "alex@example.test"}); f != nil {
		t.Fatalf("a single email address was flagged: %+v", f)
	}
	if f := tr.InspectCall("crm", "update_contact", map[string]interface{}{"email": "alex@example.test", "phone": "+1-555-0100"}); f != nil {
		t.Fatalf("details sent back to their own server's non-egress tool were flagged: %+v", f)
	}
	// A list of addresses with no phone number is not a contact record.
	tr, e = newTracker()
	members := `{"members": ["alex@example.test", "sam@example.test", "kim@example.test"]}`
	tr.ObserveContent("chat", "list_members", members, e.ScanToolResponse("chat", "list_members", members))
	if f := tr.InspectCall("calendar", "create_event", map[string]interface{}{"attendees": "alex@example.test, sam@example.test, kim@example.test"}); f != nil {
		t.Fatalf("addresses from a member list were flagged: %+v", f)
	}
}

func TestPhoneNumberShapes(t *testing.T) {
	for _, text := range []string{"+1-555-0100", "(555) 555-0100", "+44 20 7946 0958", "555.555.0100", "+15550100"} {
		if got := phoneNumbers("call "+text+" today", 4); len(got) != 1 {
			t.Errorf("%q: phone numbers %q, want one", text, got)
		}
	}
	for _, text := range []string{"2026-10-05", "192.168.1.10", "1234567890", "10 20 30 40 50", "12345", "v1.2.3"} {
		if got := phoneNumbers("value "+text+" here", 4); len(got) != 0 {
			t.Errorf("%q read as a phone number: %q", text, got)
		}
	}
}

func TestContactStoreStaysBounded(t *testing.T) {
	tr, _ := newTracker()
	for i := 0; i < 3*maxRememberedContacts; i++ {
		record := "email: user" + itoaTest(i) + "@example.test phone: +1-555-" + pad4(i)
		tr.rememberContacts("crm", "get_contact", record)
	}
	if len(tr.contacts) > maxRememberedContacts {
		t.Fatalf("contact store grew to %d, cap %d", len(tr.contacts), maxRememberedContacts)
	}
}

func itoaTest(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}

func pad4(i int) string {
	s := itoaTest(i % 10000)
	return strings.Repeat("0", 4-len(s)) + s
}
