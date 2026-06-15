package cmd

import (
	"testing"
	"time"
)

func TestCoworkAutoGuardIntervalDefaultAndMinimum(t *testing.T) {
	t.Setenv("AGENTKEEPER_COWORK_GUARD_INTERVAL", "")
	t.Setenv("AGENTKEEPER_COWORK_GUARD_INTERVAL_MS", "")
	if got := coworkAutoGuardInterval(); got != 60*time.Second {
		t.Fatalf("default guard interval = %s, want 60s", got)
	}

	t.Setenv("AGENTKEEPER_COWORK_GUARD_INTERVAL", "250ms")
	if got := coworkAutoGuardInterval(); got != 30*time.Second {
		t.Fatalf("duration env guard interval = %s, want 30s minimum", got)
	}

	t.Setenv("AGENTKEEPER_COWORK_GUARD_INTERVAL", "")
	t.Setenv("AGENTKEEPER_COWORK_GUARD_INTERVAL_MS", "250")
	if got := coworkAutoGuardInterval(); got != 30*time.Second {
		t.Fatalf("millisecond env guard interval = %s, want 30s minimum", got)
	}
}

func TestCoworkGuardLockIsExclusive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	unlock, acquired, err := acquireCoworkGuardLock()
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("first lock acquisition should succeed")
	}

	_, acquired, err = acquireCoworkGuardLock()
	if err != nil {
		t.Fatal(err)
	}
	if acquired {
		t.Fatal("second lock acquisition should be skipped while first lock is held")
	}

	unlock()
	unlock, acquired, err = acquireCoworkGuardLock()
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("lock should be acquirable after unlock")
	}
	unlock()
}
