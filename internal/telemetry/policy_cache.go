package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	policyCacheSchema = "mcp-policy-cache/1"
	policyStateSchema = "mcp-policy-state/1"
)

// policyStateSnapshot is deliberately separate from the replaceable policy
// snapshot. It lets an offline restart distinguish a true first boot from a
// route that had already been assigned Enforce but lost its cached policy.
type policyStateSnapshot struct {
	SchemaVersion               string `json:"schema_version"`
	SignerKeyID                 string `json:"signer_key_id"`
	MachineID                   string `json:"machine_id"`
	ClientName                  string `json:"client_name,omitempty"`
	ConfigSourceHash            string `json:"config_source_hash,omitempty"`
	RouteRevision               string `json:"route_revision,omitempty"`
	EffectiveMode               string `json:"effective_mode"`
	EffectiveAssignmentRevision int64  `json:"effective_assignment_revision"`
	EstablishedAt               string `json:"established_at"`
	AssignmentOrigin            string `json:"assignment_origin,omitempty"`
	SignatureBase64             string `json:"signature_base64,omitempty"`
}

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
		c.policyMu.RLock()
		stateValid := c.policyStateValid
		c.policyMu.RUnlock()
		if stateValid {
			mode, _ := c.currentMode()
			if strings.EqualFold(mode, "enforce") {
				return c.rejectPolicyCache(fmt.Errorf("policy snapshot missing after an established Enforce assignment"))
			}
		}
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
	currentMode, currentRevision := c.currentMode()
	restoredMode := normalizePolicyMode(snapshot.EffectiveMode)
	restoredRevision := snapshot.EffectiveAssignmentRevision
	c.policyMu.RLock()
	stateValid := c.policyStateValid
	c.policyMu.RUnlock()
	if stateValid && currentRevision >= restoredRevision {
		// Assignment state is persisted before its replaceable policy cache.
		// A crash between those writes must not resurrect the older mode.
		restoredMode = normalizePolicyMode(currentMode)
		restoredRevision = currentRevision
	} else if strings.EqualFold(currentMode, "enforce") {
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
	c.modeRevision = restoredRevision
	c.modeMu.Unlock()
	if !c.now().Before(expiresAt) && c.logger != nil {
		c.logger.Warn("last-known-good policy expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	// Upgrade existing valid caches atomically into the independent assignment
	// state contract. A later cache loss will then fail closed.
	if snapshot.EffectiveAssignmentRevision > 0 {
		if err := c.persistPolicyState(); err != nil {
			return fmt.Errorf("persisting established policy state: %w", err)
		}
	}
	return nil
}

func (c *Client) loadPolicyState() error { return c.loadPolicyStateFrom(c.policyStatePath) }

func (c *Client) loadPolicyStateFrom(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return c.rejectPolicyCache(fmt.Errorf("inspecting established policy state: %w", err))
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return c.rejectPolicyCache(fmt.Errorf("refusing non-regular established policy state path"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c.rejectPolicyCache(fmt.Errorf("reading established policy state: %w", err))
	}
	var state policyStateSnapshot
	if err := json.Unmarshal(data, &state); err != nil {
		return c.rejectPolicyCache(fmt.Errorf("parsing established policy state: %w", err))
	}
	if state.SchemaVersion != policyStateSchema {
		return c.rejectPolicyCache(fmt.Errorf("unsupported established policy state schema %q", state.SchemaVersion))
	}
	if state.SignerKeyID != c.receiptStore.SignerKeyID() {
		return c.rejectPolicyCache(fmt.Errorf("established policy state signer does not match endpoint key"))
	}
	if state.MachineID == "" || state.MachineID != c.machineID {
		return c.rejectPolicyCache(fmt.Errorf("established policy state machine identity does not match endpoint"))
	}
	if state.ClientName != c.clientName || state.ConfigSourceHash != c.configSourceHash || state.RouteRevision != c.routeRevision {
		return c.rejectPolicyCache(fmt.Errorf("established policy state route identity does not match Gateway process"))
	}
	if state.EffectiveAssignmentRevision < 0 || state.EffectiveAssignmentRevision == 0 && (state.AssignmentOrigin != "initial_observe" || state.EffectiveMode != "observe") {
		return c.rejectPolicyCache(fmt.Errorf("established policy state assignment revision is invalid"))
	}
	if _, err := time.Parse(time.RFC3339Nano, state.EstablishedAt); err != nil {
		return c.rejectPolicyCache(fmt.Errorf("established policy state timestamp is invalid"))
	}
	canonical, err := canonicalPolicyState(state)
	if err != nil || !c.receiptStore.VerifyBytes(canonical, state.SignatureBase64) {
		return c.rejectPolicyCache(fmt.Errorf("established policy state signature is invalid"))
	}
	c.policyMu.RLock()
	established := c.policyStateValid
	c.policyMu.RUnlock()
	c.modeMu.Lock()
	if state.EffectiveMode != "observe" && state.EffectiveMode != "enforce" {
		c.modeMu.Unlock()
		return fmt.Errorf("invalid established mode")
	}
	if state.EffectiveAssignmentRevision < c.modeRevision || established && state.EffectiveAssignmentRevision == c.modeRevision {
		c.modeMu.Unlock()
		return nil
	}
	if normalizePolicyMode(state.EffectiveMode) == "enforce" || c.startupEnforce {
		c.mode = "enforce"
	} else {
		c.mode = "audit"
	}
	c.modeRevision = state.EffectiveAssignmentRevision
	c.modeMu.Unlock()
	c.policyMu.Lock()
	c.policyStateValid = true
	c.policyMu.Unlock()
	return nil
}

func (c *Client) rejectPolicyCache(err error) error {
	c.policyMu.Lock()
	c.policyCacheBad = true
	c.policyValid = false
	c.cachedPolicy = SyncPolicy{}
	c.policyMu.Unlock()
	// Corrupt classification data is not authority to change a route's mode.
	// Policy() still fails closed when verified/configured mode is Enforce.
	return fmt.Errorf("last-known-good policy unavailable: %w", err)
}

func (c *Client) persistPolicyState() error {
	if c.policyStatePath == "" || c.receiptStore == nil {
		return nil
	}
	mode, revision := c.currentMode()
	return c.persistPolicyStateValues(mode, revision)
}

func (c *Client) persistPolicyStateValues(mode string, revision int64) error {
	if c.policyStatePath == "" {
		return nil
	}
	if c.receiptStore == nil {
		return fmt.Errorf("cannot persist mode authority without durable signer")
	}
	if revision <= 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.policyStatePath), 0700); err != nil {
		return err
	}
	release, err := fslock.Acquire(c.policyStatePath + ".lock")
	if err != nil {
		return err
	}
	defer release()
	for _, path := range []string{c.policyStatePath + ".authority", c.policyStatePath} {
		if prior, err := c.verifiedAuthority(path); err == nil && (prior.EffectiveAssignmentRevision > revision || prior.EffectiveAssignmentRevision == revision && prior.EffectiveMode != modeLabel(mode)) {
			return fmt.Errorf("refusing stale/conflicting assignment revision %d; verified authority is %s revision %d", revision, prior.EffectiveMode, prior.EffectiveAssignmentRevision)
		}
	}
	state := policyStateSnapshot{
		SchemaVersion:               policyStateSchema,
		SignerKeyID:                 c.receiptStore.SignerKeyID(),
		MachineID:                   c.machineID,
		ClientName:                  c.clientName,
		ConfigSourceHash:            c.configSourceHash,
		RouteRevision:               c.routeRevision,
		EffectiveMode:               modeLabel(mode),
		EffectiveAssignmentRevision: revision,
		EstablishedAt:               c.now().UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalPolicyState(state)
	if err != nil {
		return err
	}
	state.SignatureBase64 = c.receiptStore.SignBytes(canonical)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// The independent authority is written before replaceable state/cache.
	if err := atomicWritePrivate(c.policyStatePath+".authority", append(data, '\n')); err != nil {
		return err
	}
	if err := atomicWritePrivate(c.policyStatePath, append(data, '\n')); err != nil {
		return err
	}
	c.policyMu.Lock()
	c.policyStateValid = true
	c.policyMu.Unlock()
	return nil
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

func canonicalPolicyState(state policyStateSnapshot) ([]byte, error) {
	state.SignatureBase64 = ""
	return json.Marshal(state)
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

var ErrModeAuthorityUnavailable = errors.New("Gateway route mode authority is unavailable")

// ModeAuthorityReady permits a fresh authenticated assignment to recover an
// ambiguous legacy route, but never serves traffic under a guessed mode.
func (c *Client) ModeAuthorityReady() bool {
	c.modeMu.RLock()
	defer c.modeMu.RUnlock()
	return !c.modeAuthorityUnavailable
}

func (c *Client) restoreModeAndPolicy() error {
	authorityPath := c.policyStatePath + ".authority"
	_, stateStat := os.Lstat(c.policyStatePath)
	_, authorityStat := os.Lstat(authorityPath)
	stateExists := !os.IsNotExist(stateStat) || !os.IsNotExist(authorityStat)
	authorityErr := c.loadPolicyStateFrom(authorityPath)
	stateErr := c.loadPolicyState()
	cacheErr := c.loadPolicyCache()
	c.policyMu.RLock()
	stateValid, cacheValid := c.policyStateValid, c.policyValid
	c.policyMu.RUnlock()
	c.modeMu.Lock()
	ambiguous := stateExists && !stateValid && !cacheValid && !c.startupEnforce
	c.modeAuthorityUnavailable = ambiguous
	c.modeMu.Unlock()
	if ambiguous {
		return fmt.Errorf("%w: neither persisted assignment nor cache can be verified; reconnect for an acknowledged assignment before retrying", ErrModeAuthorityUnavailable)
	}
	if !stateExists && !stateValid && !cacheValid {
		mode, _ := c.currentMode()
		if modeLabel(mode) == "observe" {
			if err := c.persistInitialObserveAuthority(authorityPath); err != nil {
				c.modeMu.Lock()
				c.modeAuthorityUnavailable = true
				c.modeMu.Unlock()
				return fmt.Errorf("%w: %v", ErrModeAuthorityUnavailable, err)
			}
		}
	}
	if cacheErr != nil {
		return cacheErr
	}
	if stateErr != nil {
		return stateErr
	}
	return authorityErr
}

func (c *Client) persistInitialObserveAuthority(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	release, err := fslock.Acquire(c.policyStatePath + ".lock")
	if err != nil {
		return err
	}
	defer release()
	// Another client process may have established an assignment since startup
	// inspected these files. Initial Observe must never overwrite that authority.
	for _, candidate := range []string{path, c.policyStatePath} {
		if _, err := os.Lstat(candidate); err == nil {
			if _, err := c.verifiedAuthority(candidate); err != nil {
				return fmt.Errorf("concurrent mode authority cannot be verified: %w", err)
			}
			return c.loadPolicyStateFrom(candidate)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	state := policyStateSnapshot{SchemaVersion: policyStateSchema, SignerKeyID: c.receiptStore.SignerKeyID(), MachineID: c.machineID, ClientName: c.clientName, ConfigSourceHash: c.configSourceHash, RouteRevision: c.routeRevision, EffectiveMode: "observe", EffectiveAssignmentRevision: 0, EstablishedAt: c.now().UTC().Format(time.RFC3339Nano), AssignmentOrigin: "initial_observe"}
	canonical, err := canonicalPolicyState(state)
	if err != nil {
		return err
	}
	state.SignatureBase64 = c.receiptStore.SignBytes(canonical)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := atomicWritePrivate(path, append(data, '\n')); err != nil {
		return fmt.Errorf("persisting initial Observe authority: %w", err)
	}
	c.policyMu.Lock()
	c.policyStateValid = true
	c.policyMu.Unlock()
	return nil
}

// Used under the process-shared assignment lock before replacing authority.
func (c *Client) verifiedAuthority(path string) (policyStateSnapshot, error) {
	var state policyStateSnapshot
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf("non-regular authority")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.SchemaVersion != policyStateSchema || state.SignerKeyID != c.receiptStore.SignerKeyID() || state.MachineID != c.machineID || state.ClientName != c.clientName || state.ConfigSourceHash != c.configSourceHash || state.RouteRevision != c.routeRevision || (state.EffectiveMode != "observe" && state.EffectiveMode != "enforce") || state.EffectiveAssignmentRevision < 0 || state.EffectiveAssignmentRevision == 0 && (state.EffectiveMode != "observe" || state.AssignmentOrigin != "initial_observe") {
		return state, fmt.Errorf("authority identity or assignment invalid")
	}
	if _, err = time.Parse(time.RFC3339Nano, state.EstablishedAt); err != nil {
		return state, err
	}
	canonical, err := canonicalPolicyState(state)
	if err != nil || !c.receiptStore.VerifyBytes(canonical, state.SignatureBase64) {
		return state, fmt.Errorf("authority signature invalid")
	}
	return state, nil
}
