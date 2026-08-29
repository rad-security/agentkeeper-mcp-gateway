package gatewayentry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
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
	if exe, err := os.Executable(); err == nil && isGatewayBasename(filepath.Base(exe)) {
		return exe
	}
	return BinaryName
}

// ContentHash hashes exact bytes for compare-and-swap checks before a client
// configuration is changed.
func ContentHash(source []byte) string {
	sum := sha256.Sum256(source)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RouteIdentity binds a routed client process to the durable client
// configuration it launches from. The two embedded attestation values are
// removed before canonical JSON hashing to avoid a self-referential hash while
// retaining every behavior-affecting field, including the absolute command.
func RouteIdentity(clientName string, source []byte) (string, string) {
	canonical := canonicalRouteSource(source)
	sourceHash := ContentHash(canonical)
	routeSum := sha256.Sum256([]byte(clientName + "\x00" + sourceHash + "\x00" + Command()))
	return sourceHash, "route:" + hex.EncodeToString(routeSum[:])
}

func canonicalRouteSource(source []byte) []byte {
	var document interface{}
	if json.Unmarshal(source, &document) != nil {
		return source
	}
	walkRouteEntries(document, func(_ map[string]interface{}, env map[string]interface{}) {
		delete(env, EnvConfigSourceHash)
		delete(env, EnvRouteRevision)
	})
	canonical, err := json.Marshal(document)
	if err != nil {
		return source
	}
	return canonical
}

// AttestRoutes binds every AgentKeeper Gateway entry in a client document,
// including Claude Code project-scoped entries nested under `projects`, to the
// same final durable route identity. It deliberately does not modify other MCP
// servers or their environment variables.
func AttestRoutes(clientName string, source []byte) ([]byte, string, string, error) {
	var document interface{}
	if err := json.Unmarshal(source, &document); err != nil {
		return nil, "", "", fmt.Errorf("parsing client route document: %w", err)
	}
	found := false
	walkRouteEntries(document, func(entry map[string]interface{}, env map[string]interface{}) {
		found = true
		env[EnvClientName] = clientName
		delete(env, EnvConfigSourceHash)
		delete(env, EnvRouteRevision)
		entry["env"] = env
	})
	if !found {
		return nil, "", "", fmt.Errorf("client route document contains no AgentKeeper Gateway entry")
	}
	identityDocument, err := json.Marshal(document)
	if err != nil {
		return nil, "", "", fmt.Errorf("encoding client route identity document: %w", err)
	}
	sourceHash, routeRevision := RouteIdentity(clientName, identityDocument)
	walkRouteEntries(document, func(entry map[string]interface{}, env map[string]interface{}) {
		env[EnvConfigSourceHash] = sourceHash
		env[EnvRouteRevision] = routeRevision
		entry["env"] = env
	})
	bound, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, "", "", fmt.Errorf("encoding attested client route document: %w", err)
	}
	verifiedHash, verifiedRevision := RouteIdentity(clientName, bound)
	if verifiedHash != sourceHash || verifiedRevision != routeRevision {
		return nil, "", "", fmt.Errorf("client route identity changed while binding attestation")
	}
	return bound, sourceHash, routeRevision, nil
}

func walkRouteEntries(value interface{}, visit func(entry map[string]interface{}, env map[string]interface{})) {
	switch current := value.(type) {
	case map[string]interface{}:
		if servers, ok := current["mcpServers"].(map[string]interface{}); ok {
			for _, rawEntry := range servers {
				entry, ok := rawEntry.(map[string]interface{})
				if !ok {
					continue
				}
				command, _ := entry["command"].(string)
				if !IsGatewayCommand(command) {
					continue
				}
				env, _ := entry["env"].(map[string]interface{})
				if env == nil {
					env = make(map[string]interface{})
				}
				visit(entry, env)
			}
		}
		for _, child := range current {
			walkRouteEntries(child, visit)
		}
	case []interface{}:
		for _, child := range current {
			walkRouteEntries(child, visit)
		}
	}
}

func IsGatewayCommand(command string) bool {
	clean := strings.ReplaceAll(strings.TrimSpace(command), "\\", "/")
	if configured := strings.ReplaceAll(strings.TrimSpace(os.Getenv(EnvBinary)), "\\", "/"); configured != "" && clean == configured {
		return true
	}
	base := path.Base(clean)
	return isGatewayBasename(base) || filepath.Base(clean) == BinaryName
}

func isGatewayBasename(base string) bool {
	base = strings.TrimSuffix(base, ".exe")
	if base == BinaryName {
		return true
	}
	for _, suffix := range []string{"_darwin_amd64", "_darwin_arm64", "_linux_amd64", "_linux_arm64", "_windows_amd64", "_windows_arm64"} {
		if base == BinaryName+suffix {
			return true
		}
	}
	return false
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
	return strings.ReplaceAll(command, "\\", "/") == strings.ReplaceAll(current, "\\", "/")
}
