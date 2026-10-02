package manualrouting

import (
	"os"
	"testing"
)

func TestManifestPrivacyCheckFollowsThePlatform(t *testing.T) {
	// Windows reports 0666 for every writable file; access there is governed
	// by the ACL of the user's profile, which a mode check cannot see.
	if !manifestModeIsPrivate("windows", os.FileMode(0o666)) {
		t.Fatal("a manifest on Windows must not be rejected for its reported mode")
	}
	if manifestModeIsPrivate("windows", os.ModeDir|0o700) || manifestModeIsPrivate("windows", os.ModeSymlink|0o600) {
		t.Fatal("a manifest must be a regular file on every platform")
	}
	for _, goos := range []string{"darwin", "linux"} {
		if !manifestModeIsPrivate(goos, os.FileMode(0o600)) {
			t.Fatalf("%s: a 0600 manifest is private", goos)
		}
		if manifestModeIsPrivate(goos, os.FileMode(0o644)) || manifestModeIsPrivate(goos, os.FileMode(0o660)) {
			t.Fatalf("%s: a group- or world-readable manifest must be rejected", goos)
		}
	}
}
