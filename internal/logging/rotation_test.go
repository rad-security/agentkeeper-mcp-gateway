package logging

import (
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDiagnosticLogsRotateWithBoundedPrivateRetention(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "events.jsonl")
	one, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	one.logMaxBytes = 1024
	two.logMaxBytes = 1024
	var wait sync.WaitGroup
	for _, logger := range []*Logger{one, two} {
		wait.Add(1)
		go func(l *Logger) {
			defer wait.Done()
			for i := 0; i < 20; i++ {
				l.LogToolCall("fixture", "record", nil, detection.Result{Verdict: detection.VerdictPass})
			}
		}(logger)
	}
	wait.Wait()
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	logs := 0
	for _, file := range files {
		if filepath.Ext(file) == ".lock" {
			continue
		}
		logs++
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 1024 || info.Mode().Perm() != 0600 {
			t.Fatalf("unbounded or public log: %s size=%d perms=%o", file, info.Size(), info.Mode().Perm())
		}
	}
	if logs > 4 || logs < 2 {
		t.Fatalf("retained logs=%d", logs)
	}
	queued, _, err := one.PendingEvents(100)
	if err != nil || len(queued) != 40 {
		t.Fatalf("rotation lost durable events: %d %v", len(queued), err)
	}
}

func TestDiagnosticLogRecoversAfterExternalRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	l, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	l.LogToolCall("fixture", "record", nil, detection.Result{Verdict: detection.VerdictPass})
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("diagnostic did not recover: %v", err)
	}
}
