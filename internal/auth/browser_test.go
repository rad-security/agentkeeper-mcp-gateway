package auth

import (
	"reflect"
	"testing"
)

func TestBrowserCommand(t *testing.T) {
	const url = "https://www.agentkeeper.dev/device?code=ABCD-1234&source=gateway"
	has := func(names ...string) func(string) bool {
		return func(name string) bool {
			for _, n := range names {
				if n == name {
					return true
				}
			}
			return false
		}
	}

	tests := []struct {
		name      string
		goos      string
		available func(string) bool
		wantName  string
		wantArgs  []string
		wantOK    bool
	}{
		{
			// The URL goes to the shell's URL handler as one argument, so the
			// "&" in the query string is not read as a command separator.
			name:      "windows uses the URL protocol handler",
			goos:      "windows",
			available: has(),
			wantName:  "rundll32",
			wantArgs:  []string{"url.dll,FileProtocolHandler", url},
			wantOK:    true,
		},
		{
			name:      "macOS uses open",
			goos:      "darwin",
			available: has("open"),
			wantName:  "open",
			wantArgs:  []string{url},
			wantOK:    true,
		},
		{
			name:      "linux uses xdg-open",
			goos:      "linux",
			available: has("xdg-open", "wslview"),
			wantName:  "xdg-open",
			wantArgs:  []string{url},
			wantOK:    true,
		},
		{
			name:      "WSL without xdg-open uses wslview",
			goos:      "linux",
			available: has("wslview"),
			wantName:  "wslview",
			wantArgs:  []string{url},
			wantOK:    true,
		},
		{
			name:      "no opener leaves the printed URL as the way in",
			goos:      "linux",
			available: has(),
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, args, ok := browserCommand(tc.goos, tc.available, url)
			if ok != tc.wantOK || name != tc.wantName || !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("browserCommand = (%q, %q, %v), want (%q, %q, %v)",
					name, args, ok, tc.wantName, tc.wantArgs, tc.wantOK)
			}
		})
	}
}
