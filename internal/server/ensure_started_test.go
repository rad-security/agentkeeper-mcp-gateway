package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exitOnDieScript is a stdio backend that records each start and exits when
// it receives any line containing "die".
func exitOnDieScript(t *testing.T) (script, starts string) {
	t.Helper()
	dir := t.TempDir()
	starts = filepath.Join(dir, "starts")
	script = filepath.Join(dir, "backend.sh")
	body := "#!/bin/sh\necho started >> \"$1\"\nwhile IFS= read -r line; do case \"$line\" in *die*) exit 0 ;; esac; done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, starts
}

func TestEnsureStartedReplacesExitedBackendWithoutWaitingForBackoff(t *testing.T) {
	script, starts := exitOnDieScript(t)
	mgr := NewManager([]ServerConfig{{Name: "fixture", Command: script, Args: []string{starts}}})
	if err := mgr.StartAll(); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()
	first := mgr.Get("fixture")
	if first == nil {
		t.Fatal("backend did not start")
	}
	first.Notify("die", nil)
	select {
	case <-first.Stopped():
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not exit")
	}
	if err := mgr.EnsureStarted("fixture"); err != nil {
		t.Fatal(err)
	}
	// Synchronous: no dependence on the background restart timer.
	replacement := mgr.Get("fixture")
	if replacement == nil || replacement == first || replacement.stoppedNow() {
		t.Fatalf("EnsureStarted did not install a live replacement: %p (old %p)", replacement, first)
	}
	if err := mgr.EnsureStarted("fixture"); err != nil {
		t.Fatalf("EnsureStarted on a live backend: %v", err)
	}
	if mgr.Get("fixture") != replacement {
		t.Fatal("EnsureStarted replaced a live backend")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(starts)
		if strings.Count(string(data), "started") >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let the pending background restart fire; it must not start a third copy.
	time.Sleep(300 * time.Millisecond)
	data, _ := os.ReadFile(starts)
	if got := strings.Count(string(data), "started"); got != 2 {
		t.Fatalf("backend starts=%d, want exactly 2", got)
	}
	if mgr.Get("fixture") != replacement {
		t.Fatal("background restart replaced the on-demand backend")
	}
}

func TestEnsureStartedHonorsCrashLoopBudgetAndShutdown(t *testing.T) {
	script, starts := exitOnDieScript(t)
	mgr := NewManager([]ServerConfig{{Name: "fixture", Command: script, Args: []string{starts}}})
	mgr.mu.Lock()
	mgr.restartAttempts["fixture"] = maxRestartAttempts + 1
	mgr.mu.Unlock()
	if err := mgr.EnsureStarted("fixture"); !errors.Is(err, ErrRestartLimit) {
		t.Fatalf("exhausted budget: err=%v, want ErrRestartLimit", err)
	}
	if mgr.Get("fixture") != nil {
		t.Fatal("backend spawned beyond the crash-loop budget")
	}
	if err := mgr.EnsureStarted("unconfigured"); err == nil {
		t.Fatal("unconfigured backend was started")
	}
	mgr.MarkHealthy("fixture")
	mgr.StopAll()
	if err := mgr.EnsureStarted("fixture"); err == nil || mgr.Get("fixture") != nil {
		t.Fatalf("backend started during shutdown: err=%v", err)
	}
	if _, err := os.Stat(starts); !os.IsNotExist(err) {
		t.Fatalf("backend process was spawned: %v", err)
	}
}
