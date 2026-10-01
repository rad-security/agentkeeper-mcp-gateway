package cmd

import (
	"os"
	"path/filepath"
	"testing"
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
