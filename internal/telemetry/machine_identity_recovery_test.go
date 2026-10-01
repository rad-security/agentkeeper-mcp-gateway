package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

func authorityClientOnMachine(t *testing.T, store *receipt.Store, machineID, localMode string) *Client {
	t.Helper()
	c := NewClient("http://127.0.0.1:9", "synthetic", nil)
	c.machineID = machineID
	c.SetMode(localMode)
	c.SetReceiptStore(store)
	return c
}

func newAuthorityStore(t *testing.T) (*receipt.Store, string) {
	t.Helper()
	root := t.TempDir()
	store, err := receipt.NewStore(filepath.Join(root, "receipts"), "test")
	if err != nil {
		t.Fatal(err)
	}
	return store, filepath.Join(root, "policy.json")
}

func TestObserveAuthorityFromAnotherMachineIdentityIsReestablished(t *testing.T) {
	for _, assigned := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial_observe", true: "acknowledged_observe"}[assigned], func(t *testing.T) {
			store, path := newAuthorityStore(t)
			previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
			if err := previous.SetPolicyCache(path); err != nil {
				t.Fatal(err)
			}
			if assigned {
				previous.applyAssignedMode("observe", 7)
				if err := previous.persistPolicyState(); err != nil {
					t.Fatal(err)
				}
			}
			for _, launch := range []string{"first launch", "next launch"} {
				replacement := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "audit")
				if err := replacement.SetPolicyCache(path); err != nil {
					t.Fatalf("%s on the replacement machine: %v", launch, err)
				}
				if mode, revision := replacement.EffectiveMode(); mode != "observe" || revision != 0 || !replacement.ModeAuthorityReady() {
					t.Fatalf("%s: mode=%s revision=%d ready=%v", launch, mode, revision, replacement.ModeAuthorityReady())
				}
			}
		})
	}
}

func TestEnforceAuthorityFromAnotherMachineIdentityStillRefusesGuess(t *testing.T) {
	store, path := newAuthorityStore(t)
	previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
	if err := previous.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	previous.applyAssignedMode("enforce", 5)
	if err := previous.persistPolicyState(); err != nil {
		t.Fatal(err)
	}
	replacement := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "audit")
	if err := replacement.SetPolicyCache(path); err == nil {
		t.Fatal("foreign Enforce authority was accepted without a diagnostic")
	}
	if replacement.ModeAuthorityReady() {
		t.Fatal("established Enforce from another machine was downgraded to a guessed Observe")
	}
	replacement.applyAssignedMode("enforce", 6)
	if mode, _ := replacement.EffectiveMode(); mode != "enforce" || !replacement.ModeAuthorityReady() {
		t.Fatalf("authenticated assignment failed to recover: mode=%s ready=%v", mode, replacement.ModeAuthorityReady())
	}
}

// Machine identity detection can return nothing (a Linux image without
// /etc/machine-id, a failed ioreg). The Gateway must be able to read back the
// Observe authority it wrote itself.
func TestUnavailableMachineIdentityDoesNotLockOutObserve(t *testing.T) {
	store, path := newAuthorityStore(t)
	for _, launch := range []string{"first launch", "next launch", "third launch"} {
		c := authorityClientOnMachine(t, store, "", "audit")
		if err := c.SetPolicyCache(path); err != nil {
			t.Fatalf("%s: %v", launch, err)
		}
		if mode, _ := c.EffectiveMode(); mode != "observe" || !c.ModeAuthorityReady() {
			t.Fatalf("%s: mode=%s ready=%v", launch, mode, c.ModeAuthorityReady())
		}
	}
}

// A local enforce request (--enforce or config "mode": "enforce") on a route
// that only ever recorded its initial Observe has no control-plane policy to
// lose. It must behave as it does on a fresh install, not deny every server
// because an earlier Observe run happened to leave a state file behind.
func TestLocalEnforceRequestAfterObserveRunDoesNotFailClosed(t *testing.T) {
	store, path := newAuthorityStore(t)
	observe := authorityClientOnMachine(t, store, "synthetic-local-enforce", "audit")
	if err := observe.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	enforce := authorityClientOnMachine(t, store, "synthetic-local-enforce", "enforce")
	if err := enforce.SetPolicyCache(path); err != nil {
		t.Fatalf("local enforce request after an Observe run: %v", err)
	}
	if mode, _ := enforce.EffectiveMode(); mode != "enforce" || !enforce.ModeAuthorityReady() {
		t.Fatalf("mode=%s ready=%v", mode, enforce.ModeAuthorityReady())
	}
	if blocked := enforce.Policy().BlockedServers; len(blocked) != 0 {
		t.Fatalf("local enforce request denied every server: %v", blocked)
	}
}

// The control plane's Enforce assignment is different: losing its policy
// snapshot must still deny everything until a fresh policy arrives.
func TestAssignedEnforceStillFailsClosedWithoutPolicy(t *testing.T) {
	store, path := newAuthorityStore(t)
	assigned := authorityClientOnMachine(t, store, "synthetic-assigned-enforce", "audit")
	if err := assigned.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	assigned.applyAssignedMode("enforce", 3)
	if err := assigned.persistPolicyState(); err != nil {
		t.Fatal(err)
	}
	restarted := authorityClientOnMachine(t, store, "synthetic-assigned-enforce", "audit")
	_ = restarted.SetPolicyCache(path)
	if blocked := restarted.Policy().BlockedServers; len(blocked) != 1 || blocked[0] != "*" {
		t.Fatalf("assigned Enforce without a policy snapshot did not fail closed: %v", blocked)
	}
}

// A local enforce request on a replacement machine starts from the previous
// machine's initial Observe record. It must recover exactly as Observe does,
// then apply the local request, instead of denying every server for good.
func TestLocalEnforceRequestOnReplacementMachineDoesNotFailClosed(t *testing.T) {
	store, path := newAuthorityStore(t)
	previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
	if err := previous.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	for _, launch := range []string{"first launch", "next launch"} {
		replacement := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "enforce")
		if err := replacement.SetPolicyCache(path); err != nil {
			t.Fatalf("%s: %v", launch, err)
		}
		if mode, _ := replacement.EffectiveMode(); mode != "enforce" || !replacement.ModeAuthorityReady() {
			t.Fatalf("%s: mode=%s ready=%v", launch, mode, replacement.ModeAuthorityReady())
		}
		if blocked := replacement.Policy().BlockedServers; len(blocked) != 0 {
			t.Fatalf("%s: local enforce request denied every server: %v", launch, blocked)
		}
	}
}

// Recovery must look at every persisted record. An Observe authority beside
// an Enforce state (a restore that mixed two points in time) is not evidence
// that the route was only ever in Observe.
func TestForeignObserveAuthorityBesideEnforceStateIsNotRecovered(t *testing.T) {
	store, path := newAuthorityStore(t)
	previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
	if err := previous.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	statePath := previous.policyStatePath
	observeAuthority, err := os.ReadFile(statePath + ".authority")
	if err != nil {
		t.Fatal(err)
	}
	previous.applyAssignedMode("enforce", 5)
	if err := previous.persistPolicyState(); err != nil {
		t.Fatal(err)
	}
	// The authority file is rolled back to initial Observe; the state file
	// still records Enforce revision 5.
	if err := os.WriteFile(statePath+".authority", observeAuthority, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "audit")
	if err := replacement.SetPolicyCache(path); err == nil {
		t.Fatal("mixed Observe/Enforce records were accepted without a diagnostic")
	}
	if replacement.ModeAuthorityReady() {
		t.Fatal("an Enforce record from another machine was discarded in favour of Observe")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("the Enforce state record was deleted: %v", err)
	}
}

// Two client processes can start on the replacement machine together. The one
// that finds the route already recovered must end in the same state as the
// one that recovered it.
func TestSecondProcessFindingRouteAlreadyRecoveredDoesNotFailClosed(t *testing.T) {
	store, path := newAuthorityStore(t)
	previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
	if err := previous.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	first := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "enforce")
	if err := first.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	// The second process read the foreign records before the first recovered.
	second := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "enforce")
	second.policyCachePath = first.policyCachePath
	second.policyStatePath = first.policyStatePath
	second.policyCacheBad = true
	if err := second.reestablishObserveForThisMachine(second.policyStatePath+".authority", true); err != nil {
		t.Fatal(err)
	}
	if blocked := second.Policy().BlockedServers; len(blocked) != 0 {
		t.Fatalf("second process denied every server: %v", blocked)
	}
}

// A policy snapshot recording Enforce is evidence too. Recovery must not
// delete it to come up in Observe.
func TestForeignObserveAuthorityBesideEnforcePolicySnapshotIsNotRecovered(t *testing.T) {
	store, path := newAuthorityStore(t)
	previous := authorityClientOnMachine(t, store, "synthetic-previous-laptop", "audit")
	if err := previous.SetPolicyCache(path); err != nil {
		t.Fatal(err)
	}
	statePath, cachePath := previous.policyStatePath, previous.policyCachePath
	observeAuthority, err := os.ReadFile(statePath + ".authority")
	if err != nil {
		t.Fatal(err)
	}
	previous.applyAssignedMode("enforce", 5)
	if err := previous.persistPolicyState(); err != nil {
		t.Fatal(err)
	}
	previous.policyValid = true
	previous.policySyncedAt = time.Now()
	previous.policyExpiresAt = time.Now().Add(time.Hour)
	if err := previous.persistPolicyCache(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath+".authority", observeAuthority, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := authorityClientOnMachine(t, store, "synthetic-replacement-laptop", "audit")
	_ = replacement.SetPolicyCache(path)
	if replacement.ModeAuthorityReady() {
		t.Fatal("an Enforce policy snapshot from another machine was discarded in favour of Observe")
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("the Enforce policy snapshot was deleted: %v", err)
	}
}
