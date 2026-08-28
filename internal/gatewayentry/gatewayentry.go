package gatewayentry

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

const (
	BinaryName          = "agentkeeper-mcp-gateway"
	EnvBinary           = "AGENTKEEPER_MCP_GATEWAY_BIN"
	EnvClientName       = "AGENTKEEPER_MCP_CLIENT"
	EnvConfigSourceHash = "AGENTKEEPER_MCP_CONFIG_SOURCE_HASH"
	EnvRouteRevision    = "AGENTKEEPER_MCP_ROUTE_REVISION"
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

// RouteIdentity binds a routed client process to the exact client
// configuration that was inspected before AgentKeeper rewrote it. The route
// revision also includes the installed Gateway command so an artifact/path
// replacement produces a new route instead of silently inheriting trust.
func RouteIdentity(clientName string, source []byte) (string, string) {
	sourceSum := sha256.Sum256(source)
	sourceHash := "sha256:" + hex.EncodeToString(sourceSum[:])
	routeSum := sha256.Sum256([]byte(clientName + "\x00" + sourceHash + "\x00" + Command()))
	return sourceHash, "route:" + hex.EncodeToString(routeSum[:])
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
