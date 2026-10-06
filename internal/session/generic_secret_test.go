package session

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// A synthetic secret with no provider format, built from parts so the
// repository holds no token-shaped literal.
func serviceSecret() string {
	return "svc_" + "7d3f9a1c" + "e5b2084f" + "6a1d3c9e" + "b7f20d4a" + "93c51e08"
}

// observe a config read whose secret is only recognisable by its key name.
func rememberServiceSecret(t *testing.T, tr *Tracker, e *detection.Engine) string {
	t.Helper()
	secret := serviceSecret()
	result := `{"content":[{"type":"text","text":"# service settings\nSERVICE_URL=https://api.example.test\nSERVICE_API_TOKEN=` + secret + `\nLOG_LEVEL=debug\n"}]}`
	scan := e.ScanToolResponse("config", "read_settings", result)
	if f := tr.ObserveContent("config", "read_settings", result, scan); f != nil {
		t.Fatalf("observing the read should not itself flag: %+v", f)
	}
	return secret
}

// Every way of sending on a provider key is recognised for a secret held under
// a generic name too, whether or not the name goes with it.
func TestGenericSecretEgress(t *testing.T) {
	cases := map[string]func(tr *Tracker, secret string) *Finding{
		"whole value to another server": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("sink", "submit", map[string]interface{}{"data": secret})
		},
		"assignment to another server": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("sink", "submit", map[string]interface{}{"data": "SERVICE_API_TOKEN=" + secret})
		},
		"segments in one call": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("archive", "store_segments", map[string]interface{}{
				"segment_1": secret[:20], "segment_2": secret[18:34], "segment_3": secret[32:],
			})
		},
		"base64": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("sink", "submit", map[string]interface{}{"blob": base64.StdEncoding.EncodeToString([]byte(secret))})
		},
		"hex": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("sink", "submit", map[string]interface{}{"blob": hex.EncodeToString([]byte(secret))})
		},
		"same server egress tool": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("config", "export_settings", map[string]interface{}{"payload": secret})
		},
		"handed to a second agent": func(tr *Tracker, secret string) *Finding {
			return tr.InspectCall("tasks", "create_task", map[string]interface{}{"instructions": "Use this credential for the deploy: " + secret})
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			tr, e := newTracker()
			secret := rememberServiceSecret(t, tr, e)
			f := send(tr, secret)
			if f == nil || f.Pattern != patternSecretEgress {
				t.Fatalf("egress not flagged: %+v", f)
			}
			if f.Correlation["source_tool"] != "read_settings" {
				t.Fatalf("correlation missing the source: %+v", f.Correlation)
			}
		})
	}
}

func TestGenericSecretSentAFewCharactersPerCall(t *testing.T) {
	for _, size := range []int{2, 6} {
		tr, e := newTracker()
		secret := rememberServiceSecret(t, tr, e)
		if at, flags := sendValueInPieces(tr, secret, "archive", "store_pair", size); at < 0 || flags != 1 {
			t.Fatalf("%d characters per call: first flag at %d, %d flags; want one report", size, at, flags)
		}
	}
}

// The second secret in a result is remembered as well as the first.
func TestLaterSecretInAResultIsRemembered(t *testing.T) {
	tr, e := newTracker()
	second := "Pw" + "4f8e2b6d" + "1c9a7e3f" + "5b0d2a8c"
	result := "SERVICE_API_TOKEN=" + serviceSecret() + "\nDB_PASSWORD=" + second
	tr.ObserveContent("config", "read_settings", result, e.ScanToolResponse("config", "read_settings", result))
	if f := tr.InspectCall("sink", "submit", map[string]interface{}{"data": second}); f == nil {
		t.Fatal("egress of the second secret in a result was not flagged")
	}
}

// Code that reads a secret is not a secret: sending that code on is not egress.
func TestCodeReferenceIsNotRemembered(t *testing.T) {
	tr, e := newTracker()
	source := "import os\napi_key = settings.SERVICE_API_KEY\ntoken = os.environ.get(\"SERVICE_TOKEN\")\n"
	tr.ObserveContent("files", "read_file", source, e.ScanToolResponse("files", "read_file", source))
	if f := tr.InspectCall("repo", "create_file", map[string]interface{}{"content": source}); f != nil {
		t.Fatalf("sending code that reads a secret was flagged: %+v", f)
	}
}
