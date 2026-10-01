package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// None of add's own flags has a short form today. If one gains it, the short
// form after a stdio command must be caught like the long one.
func TestMisplacedAddFlagCoversShortForms(t *testing.T) {
	command := &cobra.Command{Use: "add"}
	command.Flags().StringP("env", "e", "", "")
	command.Flags().StringArray("header", nil, "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"short form", []string{"server.py", "-e", `{"K":"V"}`}, "-e"},
		{"short form with value attached", []string{"server.py", `-e={"K":"V"}`}, "-e"},
		{"long form", []string{"server.py", "--env", `{"K":"V"}`}, "--env"},
		{"flag without a short form", []string{"server.py", "--header=A:B"}, "--header"},
		{"other short flag", []string{"server.py", "-y", "-v"}, ""},
		{"long flag sharing the letter", []string{"server.py", "--extra"}, ""},
		{"after a separator", []string{"server.py", "--", "-e", "--env"}, ""},
		{"no arguments", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := misplacedAddFlag(command, tc.args); got != tc.want {
				t.Fatalf("misplacedAddFlag(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
