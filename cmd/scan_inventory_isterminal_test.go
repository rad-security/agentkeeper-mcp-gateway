package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isTerminal classifies readers. Covers the classifier exhaustively so that
// the TTY-hang regression cannot sneak back in via a refactor that changes
// which paths skip the stdin ReadAll.
func TestIsTerminal(t *testing.T) {
	t.Run("bytes.Buffer is not a terminal", func(t *testing.T) {
		if isTerminal(bytes.NewBufferString("hello")) {
			t.Error("bytes.Buffer should not be classified as terminal")
		}
	})

	t.Run("nil-like reader is not a terminal", func(t *testing.T) {
		if isTerminal(io.LimitReader(bytes.NewReader(nil), 0)) {
			t.Error("LimitReader should not be classified as terminal")
		}
	})

	t.Run("regular file is not a terminal", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "foo")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if isTerminal(f) {
			t.Error("regular file should not be classified as terminal")
		}
	})

	t.Run("pipe read end is not a terminal", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		if isTerminal(r) {
			t.Error("pipe read end should not be classified as terminal")
		}
	})

	t.Run("/dev/null is a char device (classified as terminal → skip read)", func(t *testing.T) {
		// /dev/null is a character device on Unix, so the classifier
		// correctly returns true — which causes readHookEnvelope to skip
		// the read. That's fine: /dev/null returns EOF immediately anyway,
		// so skipping vs. reading both produce empty results.
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Skipf("cannot open %s on this platform: %v", os.DevNull, err)
		}
		defer f.Close()
		if !isTerminal(f) {
			t.Error("/dev/null is a character device; classifier should return true")
		}
	})
}

// readHookEnvelope with a pipe that has piped JSON + a close (Claude Code's
// invocation pattern) should extract the cwd/version even though isTerminal
// returns false for pipes.
func TestReadHookEnvelope_PipedJSONStillReads(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	envelope := `{"cwd":"/some/dir","claude_version":"0.2.76"}`
	go func() {
		_, _ = w.Write([]byte(envelope))
		_ = w.Close()
	}()

	cwd, ver := readHookEnvelope(r)
	if cwd != "/some/dir" {
		t.Errorf("cwd: want /some/dir, got %q", cwd)
	}
	if ver != "0.2.76" {
		t.Errorf("claude_version: want 0.2.76, got %q", ver)
	}
}

// When stdin IS a character device (terminal-like), readHookEnvelope must
// return immediately without blocking on ReadAll. This is the regression
// test for the customer-reported TTY hang.
func TestReadHookEnvelope_TerminalLikeDoesNotBlock(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	done := make(chan struct{})
	go func() {
		cwd, ver := readHookEnvelope(f)
		if cwd != "" || ver != "" {
			t.Errorf("terminal-like stdin should return empty; got cwd=%q ver=%q", cwd, ver)
		}
		close(done)
	}()

	// Any blocking read on /dev/null or a TTY would stall here; give it a
	// generous margin and still expect prompt return.
	select {
	case <-done:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("readHookEnvelope blocked on terminal-like stdin (>500ms)")
	}
}
