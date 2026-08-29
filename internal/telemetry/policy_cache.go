package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const policyCacheSchema = "mcp-policy-cache/1"

// policyCacheSnapshot is signed locally with the endpoint receipt key after a
// successful authenticated sync. The signature detects accidental or
// unprivileged cache modification; it does not replace transport authentication
// or a future control-plane-issued policy signature.
type policyCacheSnapshot struct {
	SchemaVersion               string     `json:"schema_version"`
	SignerKeyID                 string     `json:"signer_key_id"`
	GatewayID                   string     `json:"gateway_id,omitempty"`
	MachineID                   string     `json:"machine_id"`
	ClientName                  string     `json:"client_name,omitempty"`
	ConfigSourceHash            string     `json:"config_source_hash,omitempty"`
	RouteRevision               string     `json:"route_revision,omitempty"`
	EffectiveMode               string     `json:"effective_mode"`
	EffectiveAssignmentRevision int64      `json:"effective_assignment_revision,omitempty"`
	SyncedAt                    string     `json:"synced_at"`
	ExpiresAt                   string     `json:"expires_at"`
	Policy                      SyncPolicy `json:"policy"`
	SignatureBase64             string     `json:"signature_base64,omitempty"`
}

func (c *Client) loadPolicyCache() error {
	c.policyCacheMu.Lock()
	defer c.policyCacheMu.Unlock()

	info, err := os.Lstat(c.policyCachePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return c.rejectPolicyCache(fmt.Errorf("inspecting cache: %w", err))
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return c.rejectPolicyCache(fmt.Errorf("refusing non-regular cache path"))
	}
	data, err := os.ReadFile(c.policyCachePath)
	if err != nil {
		return c.rejectPolicyCache(fmt.Errorf("reading cache: %w", err))
	}
	var snapshot policyCacheSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return c.rejectPolicyCache(fmt.Errorf("parsing cache: %w", err))
	}
	if snapshot.SchemaVersion != policyCacheSchema {
		return c.rejectPolicyCache(fmt.Errorf("unsupported cache schema %q", snapshot.SchemaVersion))
	}
	if snapshot.SignerKeyID != c.receiptStore.SignerKeyID() {
		return c.rejectPolicyCache(fmt.Errorf("cache signer does not match endpoint key"))
	}
	if snapshot.MachineID == "" || snapshot.MachineID != c.machineID {
		return c.rejectPolicyCache(fmt.Errorf("cache machine identity does not match endpoint"))
	}
	if snapshot.ClientName != c.clientName || snapshot.ConfigSourceHash != c.configSourceHash || snapshot.RouteRevision != c.routeRevision {
		return c.rejectPolicyCache(fmt.Errorf("cache route identity does not match Gateway process"))
	}
	canonical, err := canonicalPolicySnapshot(snapshot)
	if err != nil || !c.receiptStore.VerifyBytes(canonical, snapshot.SignatureBase64) {
		return c.rejectPolicyCache(fmt.Errorf("cache signature is invalid"))
	}
	syncedAt, err := time.Parse(time.RFC3339Nano, snapshot.SyncedAt)
	if err != nil {
		return c.rejectPolicyCache(fmt.Errorf("cache sync time is invalid"))
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, snapshot.ExpiresAt)
	if err != nil || !expiresAt.After(syncedAt) {
		return c.rejectPolicyCache(fmt.Errorf("cache expiry is invalid"))
	}

	c.policyMu.Lock()
	c.cachedPolicy = cloneSyncPolicy(snapshot.Policy)
	c.policySyncedAt = syncedAt
	c.policyExpiresAt = expiresAt
	c.policyValid = true
	c.policyCacheBad = false
	c.policyMu.Unlock()
	if snapshot.GatewayID != "" {
		c.gatewayID = snapshot.GatewayID
	}
	currentMode, _ := c.currentMode()
	restoredMode := normalizePolicyMode(snapshot.EffectiveMode)
	if strings.EqualFold(currentMode, "enforce") {
		// Never let a cached Observe snapshot weaken an explicitly configured
		// Enforce startup.
		restoredMode = "enforce"
	}
	c.modeMu.Lock()
	if restoredMode == "enforce" {
		c.mode = "enforce"
	} else {
		c.mode = "audit"
	}
	c.modeRevision = snapshot.EffectiveAssignmentRevision
	c.modeMu.Unlock()
	if !c.now().Before(expiresAt) && c.logger != nil {
		c.logger.Warn("last-known-good policy expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func (c *Client) rejectPolicyCache(err error) error {
	c.policyMu.Lock()
	c.policyCacheBad = true
	c.policyValid = false
	c.cachedPolicy = SyncPolicy{}
	c.policyMu.Unlock()
	// A cache exists but cannot be trusted. Start the proxy in Enforce with the
	// wildcard fail-closed policy; a successful authenticated sync can replace
	// this state immediately.
	c.SetMode("enforce")
	return fmt.Errorf("last-known-good policy unavailable: %w", err)
}

func (c *Client) persistPolicyCache() error {
	if c.policyCachePath == "" || c.receiptStore == nil {
		return nil
	}
	c.policyCacheMu.Lock()
	defer c.policyCacheMu.Unlock()

	c.policyMu.RLock()
	valid := c.policyValid
	policy := cloneSyncPolicy(c.cachedPolicy)
	syncedAt := c.policySyncedAt
	expiresAt := c.policyExpiresAt
	c.policyMu.RUnlock()
	if !valid {
		return nil
	}
	mode, revision := c.currentMode()
	snapshot := policyCacheSnapshot{
		SchemaVersion:               policyCacheSchema,
		SignerKeyID:                 c.receiptStore.SignerKeyID(),
		GatewayID:                   c.gatewayID,
		MachineID:                   c.machineID,
		ClientName:                  c.clientName,
		ConfigSourceHash:            c.configSourceHash,
		RouteRevision:               c.routeRevision,
		EffectiveMode:               modeLabel(mode),
		EffectiveAssignmentRevision: revision,
		SyncedAt:                    syncedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                   expiresAt.UTC().Format(time.RFC3339Nano),
		Policy:                      policy,
	}
	canonical, err := canonicalPolicySnapshot(snapshot)
	if err != nil {
		return err
	}
	snapshot.SignatureBase64 = c.receiptStore.SignBytes(canonical)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(c.policyCachePath, append(data, '\n'))
}

func (c *Client) scopedPolicyCachePath(path string) string {
	if c.clientName == "" && c.configSourceHash == "" && c.routeRevision == "" {
		return path
	}
	scope := sha256.Sum256([]byte(c.clientName + "\x00" + c.configSourceHash + "\x00" + c.routeRevision))
	extension := filepath.Ext(path)
	root := strings.TrimSuffix(path, extension) + "-routes"
	return filepath.Join(root, hex.EncodeToString(scope[:])+".json")
}

func canonicalPolicySnapshot(snapshot policyCacheSnapshot) ([]byte, error) {
	snapshot.SignatureBase64 = ""
	return json.Marshal(snapshot)
}

func cloneSyncPolicy(policy SyncPolicy) SyncPolicy {
	cloned := policy
	cloned.BlockedServers = append([]string(nil), policy.BlockedServers...)
	cloned.CustomKeywords = append([]string(nil), policy.CustomKeywords...)
	if policy.BlockedTools != nil {
		cloned.BlockedTools = make(map[string][]string, len(policy.BlockedTools))
		for serverName, tools := range policy.BlockedTools {
			cloned.BlockedTools[serverName] = append([]string(nil), tools...)
		}
	}
	return cloned
}

func failClosedPolicy() SyncPolicy {
	return SyncPolicy{
		Mode:           "enforce",
		BlockedServers: []string{"*"},
		Detection: DetectionConfig{
			Threat:        "block",
			SensitiveData: "block",
		},
	}
}

func atomicWritePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular cache path")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".policy-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func normalizePolicyMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "enforce") {
		return "enforce"
	}
	return "observe"
}
