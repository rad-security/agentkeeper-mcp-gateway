package coworkposture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func macClaudeDir(home string) string {
	return filepath.Join(home, "Library", "Application Support", "Claude")
}

func checkByName(payload ScanPayload, name string) (ScanCheck, bool) {
	for _, check := range payload.Checks {
		if check.CheckName == name {
			return check, true
		}
	}
	return ScanCheck{}, false
}

func TestScan_RiskyMacCoworkPosture(t *testing.T) {
	home := t.TempDir()
	appDir := macClaudeDir(home)
	writeFixture(t, filepath.Join(appDir, "claude_desktop_config.json"), `{
		"preferences": {
			"coworkWebSearchEnabled": true,
			"allowAllBrowserActions": true
		},
		"mcpServers": {
			"github": {
				"command": "/usr/local/bin/node",
				"args": ["server.js", "--token", "sk-should-not-appear"],
				"env": {"GITHUB_TOKEN": "super-secret-token"}
			}
		}
	}`)
	writeFixture(t, filepath.Join(appDir, "local-agent-mode-sessions", "org-1", "user-1", "local_abc.json"), `{
		"egressAllowedDomains": ["*"],
		"hostLoopMode": true,
		"enabledPlugins": {"gmail": true},
		"extraKnownMarketplaces": ["https://market.example"],
		"connectors": {"google_drive": {"connected": true}},
		"hooks": {"PreToolUse": [{"command": "bash -lc 'curl https://example.com'"}]},
		"scheduledTasks": [{
			"name": "nightly-sensitive",
			"cron": "0 * * * *",
			"prompt": "Use WebFetch and write_file to process reports"
		}]
	}`)
	writeFixture(t, filepath.Join(appDir, "extensions-installations.json"), `{
		"extensions": [{
			"id": "dev-extension",
			"name": "Developer Helper",
			"signatureInfo": {"status": "unsigned"},
			"tools": [{"name": "run_command"}, {"name": "read_file"}]
		}]
	}`)
	writeFixture(t, filepath.Join(appDir, "Cookies"), "cookie-secret-token")

	payload, err := Scan(ScanOptions{
		Home: home,
		OS:   "darwin",
		Now:  time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !payload.Detected() {
		t.Fatal("expected Claude Desktop data to be detected")
	}
	if payload.Source != Source {
		t.Fatalf("source = %q, want %q", payload.Source, Source)
	}

	cases := map[string]struct {
		status   string
		severity string
	}{
		"Cowork Egress Policy":              {StatusFail, SeverityCritical},
		"Cowork Active Dispatch":            {StatusFail, SeverityHigh},
		"Cowork Browser Actions":            {StatusFail, SeverityHigh},
		"Cowork Plugin Hooks":               {StatusFail, SeverityHigh},
		"Cowork Scheduled Task Definitions": {StatusFail, SeverityHigh},
		"DXT Extension Governance":          {StatusFail, SeverityHigh},
		"Cowork MCP Sensitive Environment":  {StatusFail, SeverityMedium},
		"Claude Cookies Present":            {StatusFail, SeverityLow},
	}
	for name, want := range cases {
		check, ok := checkByName(payload, name)
		if !ok {
			t.Fatalf("missing check %q; checks=%+v", name, payload.Checks)
		}
		if check.Status != want.status || check.Severity != want.severity {
			t.Errorf("%s = status %s severity %s, want %s/%s", name, check.Status, check.Severity, want.status, want.severity)
		}
	}

	if payload.Score != 5 || payload.Grade != "F" {
		t.Fatalf("score/grade = %d/%s, want 5/F", payload.Score, payload.Grade)
	}
	if payload.Failed == 0 || payload.Passed == 0 {
		t.Fatalf("expected mixed pass/fail checks, got passed=%d failed=%d", payload.Passed, payload.Failed)
	}
}

func TestScan_RedactsSecretsAndCookieContents(t *testing.T) {
	home := t.TempDir()
	appDir := macClaudeDir(home)
	writeFixture(t, filepath.Join(appDir, "claude_desktop_config.json"), `{
		"mcpServers": {
			"secret-server": {
				"command": "/opt/bin/server",
				"args": ["--api-key", "sk-live-abc123"],
				"env": {"API_TOKEN": "super-secret-value", "PLAIN_NAME": "safe"}
			}
		}
	}`)
	writeFixture(t, filepath.Join(appDir, "Cookies"), "cookie-secret-token")

	payload, err := Scan(ScanOptions{Home: home, OS: "darwin"})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	output := string(body)
	for _, forbidden := range []string{"super-secret-value", "sk-live-abc123", "cookie-secret-token"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("payload leaked %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "API_TOKEN") {
		t.Fatalf("expected env var names to be retained: %s", output)
	}
}

func TestScan_WindowsAppDataLayout(t *testing.T) {
	home := t.TempDir()
	appDir := filepath.Join(home, "AppData", "Roaming", "Claude")
	writeFixture(t, filepath.Join(appDir, "claude_desktop_config.json"), `{"preferences":{"allowAllBrowserActions":false}}`)

	payload, err := Scan(ScanOptions{Home: home, OS: "windows"})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !payload.Detected() {
		t.Fatal("expected Windows Claude app-data to be detected")
	}
	if payload.Platform != "windows" || payload.RawReport.AppDataKind != "windows_current_user" {
		t.Fatalf("wrong platform metadata: platform=%q appDataKind=%q", payload.Platform, payload.RawReport.AppDataKind)
	}
	check, ok := checkByName(payload, "Cowork Browser Actions")
	if !ok {
		t.Fatalf("missing browser check")
	}
	if check.Status != StatusPass {
		t.Fatalf("browser check status = %s, want PASS", check.Status)
	}
}

func TestSend_PostsScanUploadPayload(t *testing.T) {
	var gotPath, gotAuth, gotMachineID string
	var gotPayload ScanPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotMachineID = r.Header.Get("X-Machine-Id")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	payload := ScanPayload{
		Source:   Source,
		Hostname: "host",
		Platform: "darwin",
		Score:    100,
		Grade:    "A",
	}
	resp, err := Send(server.URL, "test-key", "machine-1", payload)
	if err != nil {
		t.Fatalf("send error: %v", err)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("response = %s", resp)
	}
	if gotPath != "/api/v1/scans" {
		t.Fatalf("path = %q, want /api/v1/scans", gotPath)
	}
	if gotAuth != "Bearer test-key" || gotMachineID != "machine-1" {
		t.Fatalf("headers auth=%q machine=%q", gotAuth, gotMachineID)
	}
	if gotPayload.MachineID != "machine-1" {
		t.Fatalf("machine_id = %q, want machine-1", gotPayload.MachineID)
	}
}
