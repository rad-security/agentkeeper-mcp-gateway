package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

// routeAuthorityBackend serves a mutable per-route assignment and records the
// effective mode/revision each registration reports (the dashboard's ACK input).
type routeAuthorityBackend struct {
	mu         sync.Mutex
	mode       string
	revision   int64
	registered []map[string]interface{}
	*httptest.Server
}

func newRouteAuthorityBackend(t *testing.T, mode string, revision int64) *routeAuthorityBackend {
	t.Helper()
	b := &routeAuthorityBackend{mode: mode, revision: revision}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/mcp/gateways/register":
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			b.mu.Lock()
			b.registered = append(b.registered, payload)
			mode, revision := b.mode, b.revision
			b.mu.Unlock()
			fmt.Fprintf(w, `{"ok":true,"gateway_id":"gw-local-request","route_assignment":{"desired_mode":%q,"desired_revision":%d}}`, mode, revision)
		case "/api/v1/mcp/sync":
			_, _ = w.Write([]byte(`{"ok":true,"gateway_id":"gw-local-request","policy":{"mode":"audit"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *routeAuthorityBackend) assign(mode string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode, b.revision = mode, revision
}

func (b *routeAuthorityBackend) lastRegistration(t *testing.T) (string, int64) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.registered) == 0 {
		t.Fatal("no registration was sent")
	}
	last := b.registered[len(b.registered)-1]
	mode, _ := last["effective_mode"].(string)
	revision, _ := last["effective_assignment_revision"].(float64)
	return mode, int64(revision)
}

// A local `"mode": "enforce"` request (or --enforce) must not override a
// verified, revisioned control-plane assignment: the Gateway reports and
// applies the authoritative mode and acknowledges the assignment revision so
// the dashboard can promote the route.
func TestLocalEnforceRequestDoesNotOverrideVerifiedObserveAssignment(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-local-enforce-request")
	root := t.TempDir()
	cachePath := filepath.Join(root, "policy-cache-v1.json")
	backend := newRouteAuthorityBackend(t, "observe", 1)
	launch := func(localMode string) (*Client, error) {
		store, err := receipt.NewStore(filepath.Join(root, "receipts-v2"), "0.2.0-test")
		if err != nil {
			t.Fatal(err)
		}
		client := NewClient(backend.URL, "test-key", nil)
		client.SetMode(localMode)
		client.SetRouteContext("codex", "sha256:codex-source", "route:codex")
		client.SetReceiptStore(store)
		return client, client.SetPolicyCache(cachePath)
	}

	// First launch of a brand-new route: the server assigns Observe r1.
	first, err := launch("enforce")
	if err != nil {
		t.Fatalf("first launch: %v", err)
	}
	first.sync()
	if mode, revision := first.EffectiveMode(); mode != "observe" || revision != 1 {
		t.Fatalf("first launch applied %s@%d, want observe@1", mode, revision)
	}

	// Relaunch with the same local enforce request.
	second, err := launch("enforce")
	if err != nil {
		t.Fatalf("relaunch with a local enforce request failed to restore verified authority: %v", err)
	}
	if mode, revision := second.EffectiveMode(); mode != "observe" || revision != 1 {
		t.Fatalf("relaunch restored %s@%d, want the verified observe@1 assignment", mode, revision)
	}
	if err := second.persistPolicyState(); err != nil {
		t.Fatalf("restored state conflicts with verified authority: %v", err)
	}
	second.sync()
	if mode, revision := backend.lastRegistration(t); mode != "observe" || revision != 1 {
		t.Fatalf("registration reported %s@%d; the dashboard needs observe@1 to acknowledge the assignment", mode, revision)
	}

	// Dashboard promotion is applied live and persisted.
	backend.assign("enforce", 2)
	second.sync()
	if mode, revision := second.EffectiveMode(); mode != "enforce" || revision != 2 {
		t.Fatalf("promotion applied %s@%d, want enforce@2", mode, revision)
	}
	if mode, revision := backend.lastRegistration(t); mode != "observe" || revision != 1 {
		t.Fatalf("pre-promotion registration reported %s@%d", mode, revision)
	}
	second.sync()
	if mode, revision := backend.lastRegistration(t); mode != "enforce" || revision != 2 {
		t.Fatalf("post-promotion registration reported %s@%d, want enforce@2", mode, revision)
	}

	// An established Enforce assignment is never weakened by local config.
	for _, localMode := range []string{"audit", "enforce"} {
		restarted, err := launch(localMode)
		if err != nil {
			t.Fatalf("restart with local %s: %v", localMode, err)
		}
		if mode, revision := restarted.EffectiveMode(); mode != "enforce" || revision != 2 {
			t.Fatalf("restart with local %s restored %s@%d, want enforce@2", localMode, mode, revision)
		}
	}
}

// Without any revisioned assignment the local enforce request still applies:
// first boot and offline starts must not silently weaken to Observe.
func TestLocalEnforceRequestStillAppliesBeforeAnyAssignment(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-local-enforce-first-boot")
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts-v2"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient("http://127.0.0.1:1", "test-key", nil)
	client.SetMode("enforce")
	client.SetReceiptStore(store)
	if err := client.SetPolicyCache(filepath.Join(root, "policy-cache-v1.json")); err != nil {
		t.Fatal(err)
	}
	if mode, revision := client.EffectiveMode(); mode != "enforce" || revision != 0 {
		t.Fatalf("first boot with local enforce = %s@%d, want enforce@0", mode, revision)
	}
}

// A legacy policy cache written before the independent assignment state
// existed can carry a revisioned Observe assignment. The local enforce request
// must not fabricate an Enforce authority at that server revision.
func TestLocalEnforceRequestDoesNotFabricateAuthorityFromLegacyObserveCache(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "machine-local-enforce-legacy-cache")
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts-v2"), "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(root, "policy-cache-v1.json")
	seed := NewClient("http://127.0.0.1:1", "test-key", nil)
	seed.SetReceiptStore(store)
	seed.policyCachePath = cachePath
	seed.policyValid = true
	seed.policySyncedAt = seed.now().UTC()
	seed.policyExpiresAt = seed.policySyncedAt.Add(seed.policyCacheTTL)
	seed.mode, seed.modeRevision = "audit", 4
	if err := seed.persistPolicyCache(); err != nil {
		t.Fatal(err)
	}

	client := NewClient("http://127.0.0.1:1", "test-key", nil)
	client.SetMode("enforce")
	client.SetReceiptStore(store)
	if err := client.SetPolicyCache(cachePath); err != nil {
		t.Fatalf("legacy observe cache with local enforce request: %v", err)
	}
	if mode, revision := client.EffectiveMode(); mode != "observe" || revision != 4 {
		t.Fatalf("restored %s@%d, want the cached observe@4 assignment", mode, revision)
	}
	authority, err := client.verifiedAuthority(client.policyStatePath + ".authority")
	if err != nil {
		t.Fatal(err)
	}
	if authority.EffectiveMode != "observe" || authority.EffectiveAssignmentRevision != 4 {
		t.Fatalf("persisted authority %s@%d, want observe@4", authority.EffectiveMode, authority.EffectiveAssignmentRevision)
	}
}

func TestLocalModeRequestNote(t *testing.T) {
	cases := []struct {
		requested, effective string
		revision             int64
		want                 string
	}{
		{"enforce", "observe", 1, "local config requests enforce but this route's assignment is observe r1 — promote the route in the AgentKeeper dashboard to enforce"},
		{"enforce", "observe", 0, ""},
		{"enforce", "enforce", 2, ""},
		{"audit", "enforce", 2, ""},
		{"audit", "observe", 1, ""},
	}
	for _, tc := range cases {
		if got := LocalModeRequestNote(tc.requested, tc.effective, tc.revision); got != tc.want {
			t.Errorf("LocalModeRequestNote(%q, %q, %d) = %q, want %q", tc.requested, tc.effective, tc.revision, got, tc.want)
		}
	}
}
