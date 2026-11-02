package cmd_test

import (
	"strings"
	"testing"
)

func TestNoticesPrintsEmbeddedThirdPartyNotices(t *testing.T) {
	stdout, stderr, code := run(t, t.TempDir(), "notices")
	if code != 0 {
		t.Fatalf("notices exited %d: %s", code, stderr)
	}
	for _, want := range []string{"Third-party software notices", "Go standard library and runtime", "github.com/spf13/cobra"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("notices output lacks %q", want)
		}
	}
	if stderr != "" {
		t.Fatalf("notices wrote to stderr: %s", stderr)
	}
}
