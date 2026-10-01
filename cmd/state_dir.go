package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

// openReceiptStore opens the durable signer and receipt queue and returns the
// directory it lives in. Gateway state sits beside the event log when one is
// configured, otherwise beside the config file.
//
// A fleet-managed config lives in a directory the developer cannot write
// (/etc/agentkeeper-mcp-gateway/config.json). State then lives in a per-user
// directory reserved for that config, under the directory that already holds
// the default event log. The fallback applies only when the config directory
// holds no Gateway state: existing state there may record an Enforce
// assignment a fresh directory must not silently replace. Once made, it is
// kept even if the config directory later becomes writable, for the same
// reason in the other direction.
func openReceiptStore(cfg config.Config, artifactVersion string) (*receipt.Store, string, error) {
	if cfg.LogPath != "" {
		root := filepath.Join(filepath.Dir(cfg.LogPath), "receipts-v2")
		store, err := receipt.NewStore(root, artifactVersion)
		return store, root, err
	}
	configPath := config.CurrentConfigPath()
	configDir := filepath.Dir(configPath)
	root := filepath.Join(configDir, "receipts-v2")
	userDir := userStateDirFor(configPath)
	userRoot := filepath.Join(userDir, "receipts-v2")
	// State beside a shared config that this account cannot read was made by
	// another account (an admin who ran the Gateway once as root). It is not
	// this user's state and neither blocks nor replaces theirs.
	ownStateBesideConfig := holdsGatewayState(configDir) && !stateUnreadable(configDir)
	if userDir != "" && !ownStateBesideConfig && holdsGatewayState(userDir) {
		store, err := receipt.NewStore(userRoot, artifactVersion)
		return store, userRoot, err
	}
	store, err := receipt.NewStore(root, artifactVersion)
	if err == nil || userDir == "" || !stateDirNotWritable(err) || ownStateBesideConfig {
		return store, root, err
	}
	userStore, userErr := receipt.NewStore(userRoot, artifactVersion)
	if userErr != nil {
		return store, root, err
	}
	return userStore, userRoot, nil
}

// userStateDirFor returns the per-user state directory reserved for one
// config path, so two configs never share a signer or a route's assignment.
func userStateDirFor(configPath string) string {
	base := filepath.Dir(defaultEventLogPath(config.Config{}))
	if base == "" || base == "." {
		return ""
	}
	// --config and AGENTKEEPER_CONFIG may be relative; the same spelling in
	// two directories is two configs.
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	}
	sum := sha256.Sum256([]byte(filepath.Clean(configPath)))
	return filepath.Join(base, "state", hex.EncodeToString(sum[:])[:16])
}

func stateDirNotWritable(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)
}

// stateUnreadable reports that the signer beside the config belongs to an
// account this process cannot read as.
func stateUnreadable(dir string) bool {
	_, err := os.ReadFile(filepath.Join(dir, "receipts-v2", "signing-key.json"))
	return errors.Is(err, fs.ErrPermission)
}

func holdsGatewayState(dir string) bool {
	if _, err := os.Lstat(filepath.Join(dir, "receipts-v2")); err == nil {
		return true
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "policy-cache-v1*"))
	return len(matches) > 0
}
