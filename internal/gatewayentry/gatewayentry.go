package gatewayentry

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	BinaryName = "agentkeeper-mcp-gateway"
	EnvBinary  = "AGENTKEEPER_MCP_GATEWAY_BIN"
)

// Command returns the command path that client MCP configs should launch.
// Installers set EnvBinary so GUI apps do not depend on a shell PATH.
func Command() string {
	if configured := strings.TrimSpace(os.Getenv(EnvBinary)); configured != "" {
		return configured
	}
	if exe, err := os.Executable(); err == nil && filepath.Base(exe) == BinaryName {
		return exe
	}
	return BinaryName
}

func IsGatewayCommand(command string) bool {
	return filepath.Base(strings.TrimSpace(command)) == BinaryName
}

// IsCurrentGatewayCommand reports whether command is the canonical gateway
// command for this process. If the installer or process path gives us an
// absolute binary path, require that exact path so stale /usr/local or bare
// entries are repaired on the next configure-ide run. When no installed path is
// known, fall back to basename matching for compatibility.
func IsCurrentGatewayCommand(command string) bool {
	command = strings.TrimSpace(command)
	if !IsGatewayCommand(command) {
		return false
	}
	current := Command()
	if current == BinaryName {
		return true
	}
	return command == current
}
