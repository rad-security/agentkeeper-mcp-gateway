package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLastLinesReadsTheTailWithoutAnExternalProgram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	cases := []struct {
		name, content string
		lines         int
		want          string
	}{
		{"fewer lines than asked", "a\nb\n", 5, "a\nb\n"},
		{"exact tail", "a\nb\nc\nd\n", 2, "c\nd\n"},
		{"no trailing newline", "a\nb\nc", 2, "b\nc"},
		{"empty file", "", 3, ""},
		{"zero lines", "a\nb\n", 0, ""},
		{"long lines across read chunks", string(make([]byte, 0)), 1, ""},
	}
	big := make([]byte, 200_000)
	for i := range big {
		big[i] = 'x'
	}
	cases[len(cases)-1].content = "first\n" + string(big) + "\nlast-" + string(big[:70_000]) + "\n"
	cases[len(cases)-1].want = "last-" + string(big[:70_000]) + "\n"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _, err := lastLines(path, tc.lines)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("lastLines(%d) = %q, want %q", tc.lines, truncateForTest(string(got)), truncateForTest(tc.want))
			}
		})
	}
	if _, _, err := lastLines(filepath.Join(t.TempDir(), "missing.jsonl"), 3); err == nil {
		t.Fatal("a missing log must be an error")
	}
}

func truncateForTest(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// Without SIGPIPE (Windows) a closed pipe only shows as a failed write, so
// that is what must end `logs -f | head -1`.
func TestFollowLogReturnsWhenAWriteFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	closed := errors.New("pipe closed")
	stop := make(chan os.Signal)
	done := make(chan error, 1)
	go func() { done <- followLog(path, 0, failingWriter{closed}, stop) }()
	select {
	case err := <-done:
		if !errors.Is(err, closed) {
			t.Fatalf("followLog returned %v, want the write error", err)
		}
	case <-time.After(5 * time.Second):
		close(stop)
		<-done
		t.Fatal("followLog kept running after a failed write")
	}
}

// syncBuffer lets a test read what followLog has written so far.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func waitForFollowed(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for out.String() != want {
		if time.Now().After(deadline) {
			t.Fatalf("followed output = %q, want %q", out.String(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A replaced log that has already grown past the old offset is still a new
// file: it must be followed from its first byte, not from mid-line.
func TestFollowLogRestartsWhenTheFileIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	old := "old-1\nold-2\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	stop := make(chan os.Signal)
	done := make(chan error, 1)
	go func() { done <- followLog(path, int64(len(old)), out, stop) }()
	defer func() {
		close(stop)
		<-done
	}()

	// Once an append is copied, followLog has polled the original file.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("old-3\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	waitForFollowed(t, out, "old-3\n")

	// Rotate by rename, with the new file already longer than the old one.
	replacement := "replacement-line-1\nreplacement-line-2\n"
	next := filepath.Join(dir, "events.jsonl.next")
	if err := os.WriteFile(next, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	waitForFollowed(t, out, "old-3\n"+replacement)
}
