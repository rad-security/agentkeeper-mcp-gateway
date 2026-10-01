//go:build darwin || linux || windows

package fslock

import (
	"path/filepath"
	"testing"
	"time"
)

// Each routed client runs its own Gateway. A second process must wait for a
// lock the first holds briefly, not fail and drop the evidence it was writing.
func TestAcquireWaitsForABrieflyHeldLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.lock")
	release, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		release()
	}()
	started := time.Now()
	second, err := Acquire(path)
	if err != nil {
		t.Fatalf("second holder gave up after %v: %v", time.Since(started), err)
	}
	second()
	if waited := time.Since(started); waited < 400*time.Millisecond {
		t.Fatalf("second holder acquired after %v while the lock was still held", waited)
	}
}

func TestAcquireGivesUpOnALockThatIsNeverReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.lock")
	release, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	started := time.Now()
	if second, err := Acquire(path); err == nil {
		second()
		t.Fatal("acquired a lock that is held")
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Fatalf("gave up only after %v", waited)
	}
}
