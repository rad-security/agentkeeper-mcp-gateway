package configbackup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupSuffix = ".agentkeeper-backup-"

// Write stores a byte-for-byte backup of originalPath outside the source
// directory. Keeping backups under the gateway config directory prevents
// project .mcp.json rewrites from adding untracked files to customer repos.
func Write(originalPath string, data []byte) (string, error) {
	dir, err := backupDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	clean := filepath.Clean(originalPath)
	hash := sha256.Sum256([]byte(clean))
	name := sanitize(filepath.Base(clean))
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "config"
	}
	backup := filepath.Join(
		dir,
		fmt.Sprintf("%s%s%s-%d", name, backupSuffix, hex.EncodeToString(hash[:])[:12], time.Now().UnixNano()),
	)
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}

func backupDir() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("AGENTKEEPER_BACKUP_DIR")); explicit != "" {
		return filepath.Abs(expandHome(explicit))
	}
	if cfg := strings.TrimSpace(os.Getenv("AGENTKEEPER_CONFIG")); cfg != "" {
		abs, err := filepath.Abs(expandHome(cfg))
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Dir(abs), "backups"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "backups"), nil
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func sanitize(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
