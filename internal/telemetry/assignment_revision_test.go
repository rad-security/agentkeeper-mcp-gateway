package telemetry

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func TestAssignmentRevisionCannotRollbackOrChangeModeInPlace(t *testing.T) {
	c := NewClient("http://127.0.0.1:9", "synthetic-test-key", nil)
	c.applyAssignedMode("observe", 20)
	for _, revision := range []int64{1, 19, 20, 0, -1} {
		c.applyAssignedMode("enforce", revision)
		if mode, current := c.EffectiveMode(); mode != "observe" || current != 20 {
			t.Fatalf("assignment enforce@%d changed observe@20 to %s@%d", revision, mode, current)
		}
	}
	c.applyAssignedMode("enforce", 21)
	if mode, revision := c.EffectiveMode(); mode != "enforce" || revision != 21 {
		t.Fatalf("explicit newer assignment was not applied: %s@%d", mode, revision)
	}
	c.applyAssignedMode("observe", 22)
	if mode, revision := c.EffectiveMode(); mode != "observe" || revision != 22 {
		t.Fatalf("explicit newer demotion was not applied: %s@%d", mode, revision)
	}
}

func TestNewerSignedObserveStateSurvivesStaleEnforceCache(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "synthetic-assignment-revision")
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test-version")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "policy-cache-v1.json")
	c := NewClient("http://127.0.0.1:9", "synthetic-test-key", nil)
	c.SetReceiptStore(store)
	if err := c.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	c.policyValid = true
	c.policySyncedAt = time.Now().UTC()
	c.policyExpiresAt = c.policySyncedAt.Add(time.Hour)
	c.cachedPolicy = SyncPolicy{BlockedServers: []string{"marker"}}
	c.applyAssignedMode("enforce", 7)
	if err := c.persistPolicyCache(); err != nil {
		t.Fatal(err)
	}
	c.applyAssignedMode("observe", 8)
	if err := c.persistPolicyState(); err != nil {
		t.Fatal(err)
	}
	// Model termination between assignment-state and policy-cache writes.
	restarted := NewClient("http://127.0.0.1:9", "synthetic-test-key", nil)
	restarted.SetReceiptStore(store)
	if err := restarted.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	if mode, revision := restarted.EffectiveMode(); mode != "observe" || revision != 8 {
		t.Fatalf("newer signed Observe state lost to old cache: %s@%d", mode, revision)
	}
}
