package cmd_test

import (
	"strings"
	"testing"
	"time"
)

// G2: a local `"mode": "enforce"` must not be reported, applied or persisted
// over the route's verified Observe assignment, and must not block the
// Gateway from acknowledging that assignment so the dashboard can promote it.
func TestLocalEnforceRequestReportsAndAcknowledgesAuthoritativeObserveAssignment(t *testing.T) {
	api := newEvidenceAPI(t, 0, false)
	api.assign("observe", 1)
	home := t.TempDir()
	routeEnv := []string{
		"AGENTKEEPER_MCP_CLIENT=codex",
		"AGENTKEEPER_MCP_CONFIG_SOURCE_HASH=sha256:codex-e2e-source",
		"AGENTKEEPER_MCP_ROUTE_REVISION=route-e2e-1",
	}
	launch := func(localMode string) (*gatewayProcess, string) {
		t.Helper()
		cfg := evidenceGatewayConfig(home, api.URL)
		cfg["mode"] = localMode
		gw := startGatewayProcess(t, home, cfg, routeEnv...)
		gw.handshake(t)
		response := gw.request(t, 100, "tools/call", map[string]interface{}{"name": "native_matrix__echo", "arguments": map[string]interface{}{}})
		if !strings.Contains(response, "FIXTURE_ECHO_OK") {
			t.Fatalf("call was not forwarded: %s", response)
		}
		gw.closeStdinAndWait(t, 10*time.Second)
		return gw, gw.stderrText()
	}
	lastReceiptMode := func() string {
		receipts, _ := api.snapshot()
		for i := len(receipts) - 1; i >= 0; i-- {
			if receipts[i]["tool_name"] == "echo" {
				mode, _ := receipts[i]["effective_mode"].(string)
				return mode
			}
		}
		t.Fatal("no echo receipt uploaded")
		return ""
	}
	lastRegistration := func() (string, float64) {
		registrations := api.registrationSnapshot()
		if len(registrations) == 0 {
			t.Fatal("no registration")
		}
		last := registrations[len(registrations)-1]
		mode, _ := last["effective_mode"].(string)
		revision, _ := last["effective_assignment_revision"].(float64)
		return mode, revision
	}

	// First launch of the brand-new route applies the server's Observe r1.
	launch("enforce")
	// Relaunch with the same local enforce request (the observed failure).
	_, stderr := launch("enforce")
	if strings.Contains(stderr, "refusing stale/conflicting") || strings.Contains(stderr, "could not persist assigned Gateway state") {
		t.Fatalf("local enforce request conflicted with verified authority:\n%s", stderr)
	}
	if !strings.Contains(stderr, "starting in observe mode; local config requests enforce but this route's assignment is observe r1") {
		t.Fatalf("banner did not report the authoritative mode and the unapplied local request:\n%s", stderr)
	}
	if mode, revision := lastRegistration(); mode != "observe" || revision != 1 {
		t.Fatalf("registration reported %s@%v; dashboard cannot acknowledge observe@1", mode, revision)
	}
	if mode := lastReceiptMode(); mode != "observe" {
		t.Fatalf("receipt effective_mode=%s, want observe", mode)
	}

	// Dashboard promotion to Enforce r2 applies even with local "audit".
	api.assign("enforce", 2)
	_, stderr = launch("audit")
	if !strings.Contains(stderr, "starting in enforce mode\n") {
		t.Fatalf("promoted route banner:\n%s", stderr)
	}
	if mode := lastReceiptMode(); mode != "enforce" {
		t.Fatalf("promoted receipt effective_mode=%s, want enforce", mode)
	}
	// The promotion is acknowledged by the next registration (heartbeat or
	// relaunch), and neither local mode weakens the established Enforce r2.
	for _, localMode := range []string{"audit", "enforce"} {
		_, stderr = launch(localMode)
		if !strings.Contains(stderr, "starting in enforce mode\n") {
			t.Fatalf("established Enforce with local %s:\n%s", localMode, stderr)
		}
		if mode, revision := lastRegistration(); mode != "enforce" || revision != 2 {
			t.Fatalf("registration with local %s reported %s@%v, want enforce@2", localMode, mode, revision)
		}
	}
}
