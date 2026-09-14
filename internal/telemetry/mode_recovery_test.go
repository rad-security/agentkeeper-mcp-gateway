package telemetry

import (
	"errors"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserveCacheDamageNeverPromotes(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "synthetic-mode-recovery")
	for _, assigned := range []bool{false, true} {
		t.Run(map[bool]string{false: "first_boot", true: "acknowledged_observe"}[assigned], func(t *testing.T) {
			root := t.TempDir()
			store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "policy.json")
			first := NewClient("http://127.0.0.1:9", "synthetic", nil)
			first.SetMode("audit")
			first.SetReceiptStore(store)
			if assigned {
				if err := first.SetPolicyCache(path); err != nil {
					t.Fatal(err)
				}
				first.applyAssignedMode("observe", 7)
				if err := first.persistPolicyState(); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			after := NewClient("http://127.0.0.1:9", "synthetic", nil)
			after.SetMode("audit")
			after.SetReceiptStore(store)
			if err := after.SetPolicyCache(path); err == nil {
				t.Fatal("corruption not surfaced")
			}
			if mode, _ := after.EffectiveMode(); mode != "observe" || !after.ModeAuthorityReady() {
				t.Fatalf("damaged cache changed mode: %s ready=%v", mode, after.ModeAuthorityReady())
			}
			if _, err := os.Stat(path + ".state.authority"); err != nil {
				t.Fatal("initial/assigned authority missing", err)
			}
		})
	}
}
func TestIndependentModeAuthoritySurvivesBothReplaceableFilesDamaged(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "synthetic-mode-authority")
	for _, mode := range []string{"observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "policy.json")
			first := NewClient("http://127.0.0.1:9", "synthetic", nil)
			first.SetReceiptStore(store)
			if err := first.SetPolicyCache(path); err != nil {
				t.Fatal(err)
			}
			first.applyAssignedMode(mode, 9)
			if err := first.persistPolicyState(); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{path, path + ".state"} {
				if err := os.WriteFile(file, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			after := NewClient("http://127.0.0.1:9", "synthetic", nil)
			after.SetMode("audit")
			after.SetReceiptStore(store)
			_ = after.SetPolicyCache(path)
			if got, revision := after.EffectiveMode(); got != mode || revision != 9 || !after.ModeAuthorityReady() {
				t.Fatalf("mode=%s revision=%d ready=%v", got, revision, after.ModeAuthorityReady())
			}
			if mode == "enforce" {
				if got := after.Policy().BlockedServers; len(got) != 1 || got[0] != "*" {
					t.Fatal("Enforce did not fail closed", got)
				}
			}
		})
	}
}
func TestAmbiguousLegacyModeRefusesGuessUntilAcknowledged(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "policy.json")
	for _, file := range []string{path, path + ".state"} {
		if err := os.WriteFile(file, []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.SetMode("audit")
	c.SetReceiptStore(store)
	if err := c.SetPolicyCache(path); !errors.Is(err, ErrModeAuthorityUnavailable) {
		t.Fatalf("want diagnostic, got %v", err)
	}
	if mode, _ := c.EffectiveMode(); mode != "observe" || c.ModeAuthorityReady() {
		t.Fatalf("guessed mode=%s ready=%v", mode, c.ModeAuthorityReady())
	}
	c.applyAssignedMode("observe", 10)
	if !c.ModeAuthorityReady() {
		t.Fatal("authenticated assignment failed to recover")
	}
}
func TestExplicitEnforceAndValidLegacyCacheArePreserved(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "policy.json")
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.SetMode("enforce")
	c.SetReceiptStore(store)
	_ = c.SetPolicyCache(path)
	c.policyValid = true
	c.policySyncedAt = time.Now()
	c.policyExpiresAt = time.Now().Add(time.Hour)
	if err := c.persistPolicyCache(); err != nil {
		t.Fatal(err)
	}
	after := NewClient("http://127.0.0.1:9", "synthetic", nil)
	after.SetMode("audit")
	after.SetReceiptStore(store)
	if err := after.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	if mode, _ := after.EffectiveMode(); mode != "enforce" {
		t.Fatalf("established signed Enforce weakened: %s", mode)
	}
}

func TestAuthorityWriteFailureDoesNotApplyOrAcknowledgeNewMode(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.SetReceiptStore(store)
	path := filepath.Join(root, "policy.json")
	if err := c.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	c.applyAssignedMode("enforce", 5)
	authority := path + ".state.authority"
	if err := os.Remove(authority); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	c.applyAssignedMode("observe", 6)
	if mode, rev := c.EffectiveMode(); mode != "enforce" || rev != 5 {
		t.Fatalf("unpersisted assignment applied: %s/%d", mode, rev)
	}
	if err := os.Remove(authority); err != nil {
		t.Fatal(err)
	}
	c.applyAssignedMode("observe", 6)
	if mode, rev := c.EffectiveMode(); mode != "observe" || rev != 6 {
		t.Fatalf("retry failed: %s/%d", mode, rev)
	}
}
func TestInitialAuthorityPersistenceFailurePreventsServingGuessedMode(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(root, "occupied")
	if err := os.WriteFile(occupied, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.SetReceiptStore(store)
	if err := c.SetPolicyCache(filepath.Join(occupied, "policy.json")); err == nil || c.ModeAuthorityReady() {
		t.Fatalf("unpersisted startup considered ready: %v", err)
	}
}

func TestParallelClientCannotOverwriteNewerModeAuthority(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "policy.json")
	newClient := func() *Client {
		c := NewClient("http://127.0.0.1:9", "synthetic", nil)
		c.SetReceiptStore(store)
		_ = c.SetPolicyCache(path)
		return c
	}
	first, second := newClient(), newClient()
	first.applyAssignedMode("enforce", 10)
	second.applyAssignedMode("observe", 9)
	after := newClient()
	if mode, rev := after.EffectiveMode(); mode != "enforce" || rev != 10 {
		t.Fatalf("older process rolled back durable authority: %s/%d", mode, rev)
	}
	// Simulate a second first-boot writer finishing after the assignment write.
	if err := second.persistInitialObserveAuthority(path + ".state.authority"); err != nil {
		t.Fatal(err)
	}
	after = newClient()
	if mode, rev := after.EffectiveMode(); mode != "enforce" || rev != 10 {
		t.Fatalf("late initial Observe rolled back authority: %s/%d", mode, rev)
	}
}

func TestMissingSignerCannotGuessModeOrAcknowledgeUnpersistedAssignment(t *testing.T) {
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.SetMode("audit")
	if err := c.SetPolicyCache(filepath.Join(t.TempDir(), "policy.json")); !errors.Is(err, ErrModeAuthorityUnavailable) {
		t.Fatalf("missing signer ignored: %v", err)
	}
	c.applyAssignedMode("observe", 12)
	if c.ModeAuthorityReady() {
		t.Fatal("unpersisted assignment made ambiguous route ready")
	}
	if _, rev := c.EffectiveMode(); rev != 0 {
		t.Fatalf("unpersisted revision acknowledged: %d", rev)
	}
}
