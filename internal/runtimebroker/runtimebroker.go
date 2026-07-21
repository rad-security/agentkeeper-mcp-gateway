package runtimebroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	Protocol                 = "agentkeeper-runtime-gateway-v1"
	CredentialMode           = "runtime_broker_only"
	ManagedRuntimeConfigPath = "/etc/agentkeeper/mcp-gateway.json"
	maxMessageBytes          = 1 << 20
)

type ManagedConfig struct {
	SchemaVersion  int    `json:"schema_version"`
	OwnershipID    string `json:"ownership_id"`
	Protocol       string `json:"protocol"`
	CredentialMode string `json:"credential_mode"`
	RuntimeSocket  string `json:"runtime_socket"`
}

type Capabilities struct {
	SchemaVersion     int                        `json:"schema_version"`
	RuntimeSocketAuth RuntimeSocketCapabilities  `json:"runtime_socket_auth"`
	ManagedRouting    ManagedRoutingCapabilities `json:"managed_routing"`
	Inventory         InventoryCapabilities      `json:"inventory"`
}

type RuntimeSocketCapabilities struct {
	Supported          bool   `json:"supported"`
	Protocol           string `json:"protocol"`
	CredentialExposure string `json:"credential_exposure"`
}

type ManagedRoutingCapabilities struct {
	Supported           bool   `json:"supported"`
	SafeStructuralMerge bool   `json:"safe_structural_merge"`
	RuntimeConfigFlag   string `json:"runtime_config_flag"`
	NonInteractiveFlag  string `json:"non_interactive_flag"`
	RemoveManagedFlag   string `json:"remove_managed_flag"`
}

type InventoryCapabilities struct {
	DryRun bool `json:"dry_run"`
}

func EnterpriseCapabilities() Capabilities {
	supported := runtime.GOOS == "linux"
	return Capabilities{
		SchemaVersion: 1,
		RuntimeSocketAuth: RuntimeSocketCapabilities{
			Supported: supported, Protocol: Protocol, CredentialExposure: "none",
		},
		ManagedRouting: ManagedRoutingCapabilities{
			Supported: supported, SafeStructuralMerge: true,
			RuntimeConfigFlag: "--managed-runtime-config", NonInteractiveFlag: "--non-interactive",
			RemoveManagedFlag: "--remove-managed-routing",
		},
		Inventory: InventoryCapabilities{DryRun: true},
	}
}

func LoadManagedConfig(path string) (ManagedConfig, error) {
	if runtime.GOOS != "linux" {
		return ManagedConfig{}, fmt.Errorf("managed runtime socket mode is supported only on Linux")
	}
	if !filepath.IsAbs(path) {
		return ManagedConfig{}, fmt.Errorf("managed runtime config path must be absolute")
	}
	if filepath.Clean(path) != ManagedRuntimeConfigPath {
		return ManagedConfig{}, fmt.Errorf("managed runtime config path must be %s", ManagedRuntimeConfigPath)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ManagedConfig{}, fmt.Errorf("stat managed runtime config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return ManagedConfig{}, fmt.Errorf("managed runtime config must be a regular file not writable by group or others")
	}
	if !managedConfigOwnedByRoot(info) {
		return ManagedConfig{}, fmt.Errorf("managed runtime config must be root-owned")
	}
	file, err := os.Open(path)
	if err != nil {
		return ManagedConfig{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return ManagedConfig{}, fmt.Errorf("managed runtime config exceeds 64 KiB")
	}
	return ParseManagedConfig(raw)
}

func ParseManagedConfig(raw []byte) (ManagedConfig, error) {
	var cfg ManagedConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse managed runtime config: %w", err)
	}
	if cfg.SchemaVersion != 1 || cfg.Protocol != Protocol || cfg.CredentialMode != CredentialMode {
		return cfg, fmt.Errorf("managed runtime config contract is incompatible")
	}
	if cfg.OwnershipID != "agentkeeper.universal.v1" {
		return cfg, fmt.Errorf("managed runtime config ownership is invalid")
	}
	if !filepath.IsAbs(cfg.RuntimeSocket) || strings.TrimSpace(cfg.RuntimeSocket) == "" {
		return cfg, fmt.Errorf("managed runtime socket path must be absolute")
	}
	return cfg, nil
}

type brokerRequest struct {
	RequestType string          `json:"request_type"`
	Operation   string          `json:"operation"`
	Payload     json.RawMessage `json:"payload"`
}

type brokerResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Error  string          `json:"error"`
}

func Post(ctx context.Context, socketPath, operation string, payload any, out any) (int, error) {
	switch operation {
	case "sync", "evaluate", "events":
	default:
		return 0, fmt.Errorf("unsupported runtime broker operation %q", operation)
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	if len(rawPayload) > maxMessageBytes {
		return 0, fmt.Errorf("runtime broker payload exceeds %d bytes", maxMessageBytes)
	}
	requestBody, err := json.Marshal(brokerRequest{
		RequestType: "gateway_api", Operation: operation, Payload: rawPayload,
	})
	if err != nil {
		return 0, err
	}
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return 0, fmt.Errorf("connect AgentKeeper runtime broker: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(1900 * time.Millisecond)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(append(requestBody, '\n')); err != nil {
		return 0, fmt.Errorf("send AgentKeeper runtime broker request: %w", err)
	}
	responseBytes, err := bufio.NewReader(io.LimitReader(conn, maxMessageBytes+1)).ReadBytes('\n')
	if err != nil && len(responseBytes) == 0 {
		return 0, fmt.Errorf("read AgentKeeper runtime broker response: %w", err)
	}
	if len(responseBytes) > maxMessageBytes {
		return 0, fmt.Errorf("runtime broker response exceeds %d bytes", maxMessageBytes)
	}
	var response brokerResponse
	if err := json.NewDecoder(bytes.NewReader(responseBytes)).Decode(&response); err != nil {
		return 0, fmt.Errorf("parse AgentKeeper runtime broker response: %w", err)
	}
	if response.Status < 200 || response.Status >= 300 {
		return response.Status, fmt.Errorf("AgentKeeper runtime broker returned %d (%s)", response.Status, response.Error)
	}
	if out != nil {
		if len(response.Body) == 0 || !json.Valid(response.Body) {
			return response.Status, fmt.Errorf("AgentKeeper runtime broker returned an invalid body")
		}
		if err := json.Unmarshal(response.Body, out); err != nil {
			return response.Status, err
		}
	}
	return response.Status, nil
}
