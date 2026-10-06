package detection

import (
	"encoding/base64"
	"testing"
)

const genericRule = "leaked_secret_generic_assignment"

// A synthetic secret with no provider format, built from parts so the
// repository holds no token-shaped literal.
func serviceSecret() string {
	return "svc_" + "7d3f9a1c" + "e5b2084f" + "6a1d3c9e" + "b7f20d4a" + "93c51e08"
}

// A value assigned to a secret-named key is reported, in arguments and in
// results, with the value alone: session correlation then recognises the
// value wherever it is sent, with or without its name.
func TestGenericSecretAssignmentsAreDetected(t *testing.T) {
	secret := serviceSecret()
	cases := map[string]string{
		"env assignment":         "SERVICE_API_TOKEN=" + secret,
		"shell export":           `export DB_PASSWORD="` + secret + `"`,
		"json":                   `{"client_secret": "` + secret + `"}`,
		"json inside a string":   `{"text":"{\"api_key\":\"` + secret + `\"}"}`,
		"yaml":                   "auth:\n  private_key: '" + secret + "'",
		"http header":            "X-Api-Key: " + secret,
		"go assignment":          `apiToken := "` + secret + `"`,
		"query string":           "https://api.example.test/v1/items?access_token=" + secret + "&page=2",
		"camel case":             "accessToken: " + secret,
		"end of a sentence":      "The service is configured with password=" + secret + ".",
		"lowercase passwd":       "passwd: " + secret,
		"secret key under a key": "SECRET_KEY = '" + secret + "'",
	}
	e := NewEngine()
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			scans := map[string]ScanResult{
				"call":   e.ScanToolCall("synthetic", "lookup", map[string]interface{}{"text": text}),
				"result": e.ScanToolResponse("synthetic", "lookup", text),
			}
			for label, res := range scans {
				f, ok := findingByName(res, genericRule)
				if !ok {
					t.Fatalf("%s: not detected: %v", label, findingNames(res))
				}
				if len(f.Values) != 1 || f.Values[0] != secret || f.Category != "sensitive_data" || f.Severity != "high" {
					t.Fatalf("%s: values %q, category %s, severity %s; want the value alone, sensitive_data, high", label, f.Values, f.Category, f.Severity)
				}
			}
		})
	}
}

// Assignments that hold something other than a secret are not reported: code
// that reads a secret, placeholders, names and paths, cursors and ids, counts
// and timestamps.
func TestNonSecretAssignmentsAreNotReported(t *testing.T) {
	cases := []string{
		`token = os.environ.get("SERVICE_TOKEN")`,
		`api_key = settings.SERVICE_API_KEY`,
		`const apiKey = process.env.SERVICE_API_KEY;`,
		`password = load_password_from_vault(path)`,
		`token = fetchServiceToken2(scope)`,
		"SERVICE_API_KEY=your_api_key_here",
		"ADMIN_PASSWORD=changeme-before-deploy-1",
		"API_TOKEN=REPLACE_WITH_TOKEN_2",
		"secretName: tls-secret-production",
		"existingSecret: release-postgresql",
		`{"nextPageToken": "CgwIgICAgICA` + `gICAgA9yZWxlYXNlLTIwMjYtMDE"}`,
		`{"NextToken": "AbC123dEf456GhI789jKl"}`,
		`{"syncToken": "CPDAlvWDx70CEPDAlvWDx70CGAU"}`,
		`{"PasswordLastUsed": "2026-01-02T03:04:05Z"}`,
		`{"usage": {"total_tokens": 123456789012}}`,
		"secret_version: projects/123456/secrets/service-db/versions/1",
		"TOKEN_FILE=/run/secrets/service-token-2",
		"client_secret_id: 6f1c2a4e-1b2c-4d3e-8f9a-0b1c2d3e4f5a",
		"tokenizer: ./models/tokenizer.json",
		"token_type: bearer, expires_in: 3600",
		"The password must be at least 12 characters long.",
	}
	e := NewEngine()
	for _, text := range cases {
		if res := e.ScanToolResponse("synthetic", "lookup", text); hasFinding(res, genericRule) {
			f, _ := findingByName(res, genericRule)
			t.Errorf("%q was reported as a secret (values %q)", text, f.Values)
		}
	}
}

// Every secret in a result is kept for session correlation, not only the first.
func TestEverySecretInAnEnvFileIsKept(t *testing.T) {
	first, second := serviceSecret(), "Pw"+"4f8e2b6d"+"1c9a7e3f"+"5b0d2a8c"
	env := "# service settings\nSERVICE_API_TOKEN=" + first + "\nLOG_LEVEL=debug\nDB_PASSWORD=" + second + "\n"
	res := NewEngine().ScanToolResponse("files", "read_file", env)
	f, ok := findingByName(res, genericRule)
	if !ok {
		t.Fatalf("not detected: %v", findingNames(res))
	}
	if len(f.Values) != 2 || f.Values[0] != first || f.Values[1] != second {
		t.Fatalf("values %q; want both secrets in order", f.Values)
	}
}

// A secret assignment hidden in an encoded blob is found in the decoded view.
func TestEncodedGenericSecretIsDetected(t *testing.T) {
	secret := serviceSecret()
	encoded := base64.StdEncoding.EncodeToString([]byte("SERVICE_API_TOKEN=" + secret))
	res := NewEngine().ScanToolResponse("synthetic", "fetch", "settings "+encoded)
	f, ok := findingByName(res, genericRule)
	if !ok || f.DecodedFrom != "base64" || len(f.Values) != 1 || f.Values[0] != secret {
		t.Fatalf("finding %+v (found %v); want the value through base64", f, ok)
	}
}

// A provider pattern stays the primary finding when the generic rule also
// matches the same assignment.
func TestProviderPatternStaysPrimary(t *testing.T) {
	res := NewEngine().ScanToolResponse("synthetic", "fetch", "npm_token="+"npm_"+serviceSecret()[4:40])
	if got := res.Primary().PatternName; got != "api_key_npm" {
		t.Fatalf("primary = %q, want api_key_npm (findings %v)", got, findingNames(res))
	}
}
