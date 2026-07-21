package cmd_test

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestEnterpriseCapabilitiesCommandMatchesPlatformContract(t *testing.T) {
	home := t.TempDir()
	stdout, stderr, code := run(t, home, "enterprise-capabilities", "--json")
	if code != 0 {
		t.Fatalf("enterprise-capabilities exited %d: %s", code, stderr)
	}
	var result struct {
		RuntimeSocketAuth struct {
			Supported          bool   `json:"supported"`
			Protocol           string `json:"protocol"`
			CredentialExposure string `json:"credential_exposure"`
		} `json:"runtime_socket_auth"`
		ManagedRouting struct {
			RemoveManagedFlag string `json:"remove_managed_flag"`
		} `json:"managed_routing"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.RuntimeSocketAuth.Supported != (runtime.GOOS == "linux") ||
		result.RuntimeSocketAuth.Protocol != "agentkeeper-runtime-gateway-v1" ||
		result.RuntimeSocketAuth.CredentialExposure != "none" ||
		result.ManagedRouting.RemoveManagedFlag != "--remove-managed-routing" {
		t.Fatalf("unexpected enterprise contract: %+v", result)
	}
}

func TestManagedRuntimeConfigRequiresNonInteractiveFlag(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := run(t, home, "configure-ide", "--managed-runtime-config", "/etc/agentkeeper/mcp-gateway.json")
	if code == 0 || !strings.Contains(stderr, "requires --non-interactive") {
		t.Fatalf("managed mode did not enforce non-interactive invocation: code=%d stderr=%q", code, stderr)
	}
}
