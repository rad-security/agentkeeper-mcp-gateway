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

	// The URL comes from the server. Only a web page is handed to the
	// operating system's opener, which would otherwise launch whatever
	// handler a file path or another scheme names.
	for _, unsafe := range []string{
		`\\files.example.test\share\run.exe`,
		"file:///C:/Windows/System32/calc.exe",
		"ms-settings:display",
		"javascript:alert(1)",
		"C:\\Windows\\System32\\calc.exe",
		"",
	} {
		for _, goos := range []string{"windows", "darwin", "linux"} {
			if name, args, ok := browserCommand(goos, has("open", "xdg-open"), unsafe); ok {
				t.Fatalf("browserCommand(%s, %q) = (%q, %q), want no command", goos, unsafe, name, args)
			}
		}
	}
	if _, _, ok := browserCommand("windows", has(), "http://localhost:3000/auth/device?code=ABCD-1234"); !ok {
		t.Fatalf("a local development URL over http must still open")
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
