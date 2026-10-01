package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
)

// State that already exists beside a now read-only config may record an
// established Enforce assignment. Starting a fresh per-user directory would
// present that route as a first boot, so the fallback must not apply.
func TestExistingStateBesideReadOnlyConfigIsNotReplacedByUserDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home := t.TempDir()
	systemDir := filepath.Join(t.TempDir(), "etc", "agentkeeper-mcp-gateway")
	if err := os.MkdirAll(filepath.Join(systemDir, "receipts-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(systemDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"mode":"audit","servers":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(systemDir, "receipts-v2"), systemDir} {
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(systemDir, 0o755)
		_ = os.Chmod(filepath.Join(systemDir, "receipts-v2"), 0o755)
	})
	t.Setenv("HOME", home)
	t.Setenv("AGENTKEEPER_CONFIG", configPath)

	store, root, err := openReceiptStore(config.Config{}, "test")
	if err == nil || store != nil {
		t.Fatalf("opened a receipt store at %s despite unwritable existing state", root)
	}
	if root != filepath.Join(systemDir, "receipts-v2") {
		t.Fatalf("state root moved to %s", root)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "state")); !os.IsNotExist(statErr) {
		t.Fatalf("a fresh per-user state directory was created: %v", statErr)
	}
}

// Once state lives in the per-user directory it stays there. If the config
// directory later becomes writable, opening a fresh store beside it would
// present an established route as a first boot.
func TestStateStaysInUserDirectoryAfterConfigDirectoryBecomesWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home := t.TempDir()
	systemDir := filepath.Join(t.TempDir(), "etc", "agentkeeper-mcp-gateway")
	if err := os.MkdirAll(systemDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(systemDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"mode":"audit","servers":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(systemDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(systemDir, 0o755) })
	t.Setenv("HOME", home)
	t.Setenv("AGENTKEEPER_CONFIG", configPath)

	first, firstRoot, err := openReceiptStore(config.Config{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(systemDir, 0o755); err != nil {
		t.Fatal(err)
	}
	second, secondRoot, err := openReceiptStore(config.Config{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if secondRoot != firstRoot || second.SignerKeyID() != first.SignerKeyID() {
		t.Fatalf("state moved from %s to %s (signer %s -> %s)", firstRoot, secondRoot, first.SignerKeyID(), second.SignerKeyID())
	}
	if _, err := os.Stat(filepath.Join(systemDir, "receipts-v2")); !os.IsNotExist(err) {
		t.Fatalf("a second store was created beside the config: %v", err)
	}
}

// A second config must not pick up the default install's per-user state.
func TestFallbackStateIsScopedToItsConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	roots := map[string]bool{}
	for _, name := range []string{"fleet-a", "fleet-b"} {
		systemDir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(systemDir, 0o755); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(systemDir, "config.json")
		if err := os.WriteFile(configPath, []byte(`{"mode":"audit","servers":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(systemDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(systemDir, 0o755) })
		t.Setenv("AGENTKEEPER_CONFIG", configPath)
		_, root, err := openReceiptStore(config.Config{}, "test")
		if err != nil {
			t.Fatal(err)
		}
		roots[root] = true
	}
	if len(roots) != 2 {
		t.Fatalf("two configs share one fallback state directory: %v", roots)
	}
}

// State beside a shared config that this account cannot even read was made by
// another account (an admin who once ran the Gateway as root). It is not this
// user's state, and must not lock them out of their own.
func TestStateBesideConfigOwnedByAnotherAccountDoesNotLockOutTheUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home := t.TempDir()
	systemDir := filepath.Join(t.TempDir(), "etc", "agentkeeper-mcp-gateway")
	foreign := filepath.Join(systemDir, "receipts-v2")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(systemDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"mode":"audit","servers":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{foreign, 0o000}, {systemDir, 0o555}} {
		if err := os.Chmod(entry.path, entry.mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(systemDir, 0o755)
		_ = os.Chmod(foreign, 0o755)
	})
	t.Setenv("HOME", home)
	t.Setenv("AGENTKEEPER_CONFIG", configPath)

	for launch := 1; launch <= 2; launch++ {
		store, root, err := openReceiptStore(config.Config{}, "test")
		if err != nil || store == nil {
			t.Fatalf("launch %d: user was locked out by another account's state: %v", launch, err)
		}
		if !strings.HasPrefix(root, filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "state")) {
			t.Fatalf("launch %d: state root is %s", launch, root)
		}
	}
}

// `--config config.json` in two different directories is two configs.
func TestFallbackStateDirectoryUsesTheAbsoluteConfigPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	dirs := map[string]bool{}
	for i := 0; i < 2; i++ {
		if err := os.Chdir(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		dirs[userStateDirFor("config.json")] = true
	}
	if len(dirs) != 2 {
		t.Fatalf("relative config paths in two directories share state: %v", dirs)
	}
}
