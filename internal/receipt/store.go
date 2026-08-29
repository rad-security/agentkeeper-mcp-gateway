// Package receipt provides durable, signed MCP application receipts.
// Operational logs remain useful diagnostics, but only receipts from this
// package can prove what the Gateway applied to a routed call.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = "mcp-receipt/2"

type Input struct {
	CallID              string
	AttemptID           string
	DecisionID          string
	ClientName          string
	ConfigSourceHash    string
	Phase               string
	ServerName          string
	ToolName            string
	PolicyDecision      string
	EvaluationStatus    string
	RequiredDisposition string
	AppliedDisposition  string
	EffectiveMode       string
	RouteRevision       string
	PolicyHash          string
	RawSnapshotID       string
	EffectiveViewHash   string
	Dispatched          bool
	ResultReceived      bool
	ResultReturned      bool
	ResponseWithheld    bool
	Terminal            bool
	FailureReason       string
}

type Envelope struct {
	SchemaVersion       string `json:"schema_version"`
	ReceiptID           string `json:"receipt_id"`
	SignerKeyID         string `json:"signer_key_id"`
	BootID              string `json:"boot_id"`
	Sequence            uint64 `json:"sequence"`
	ArtifactVersion     string `json:"artifact_version"`
	CallID              string `json:"call_id"`
	AttemptID           string `json:"attempt_id"`
	DecisionID          string `json:"decision_id,omitempty"`
	ClientName          string `json:"client_name,omitempty"`
	ConfigSourceHash    string `json:"config_source_hash,omitempty"`
	Phase               string `json:"phase"`
	ServerName          string `json:"server_name"`
	ToolName            string `json:"tool_name"`
	PolicyDecision      string `json:"policy_decision"`
	EvaluationStatus    string `json:"evaluation_status"`
	RequiredDisposition string `json:"required_disposition"`
	AppliedDisposition  string `json:"applied_disposition"`
	EffectiveMode       string `json:"effective_mode"`
	RouteRevision       string `json:"route_revision,omitempty"`
	PolicyHash          string `json:"policy_hash,omitempty"`
	RawSnapshotID       string `json:"raw_snapshot_id,omitempty"`
	EffectiveViewHash   string `json:"effective_view_hash,omitempty"`
	Dispatched          bool   `json:"dispatched"`
	ResultReceived      bool   `json:"result_received"`
	ResultReturned      bool   `json:"result_returned"`
	ResponseWithheld    bool   `json:"response_withheld"`
	Terminal            bool   `json:"terminal"`
	FailureReason       string `json:"failure_reason,omitempty"`
	OccurredAt          string `json:"occurred_at"`
	SignatureBase64     string `json:"signature_base64,omitempty"`
}

type keyFile struct {
	Algorithm        string `json:"algorithm"`
	SignerKeyID      string `json:"signer_key_id"`
	PublicKeyBase64  string `json:"public_key_base64"`
	PrivateKeyBase64 string `json:"private_key_base64"`
}

type Store struct {
	mu              sync.Mutex
	root            string
	queueDir        string
	rejectedDir     string
	artifactVersion string
	bootID          string
	sequence        uint64
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	signerKeyID     string
}

func NewStore(root, artifactVersion string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("receipt store root is required")
	}
	store := &Store{
		root:            root,
		queueDir:        filepath.Join(root, "queue"),
		rejectedDir:     filepath.Join(root, "rejected"),
		artifactVersion: artifactVersion,
		bootID:          randomID("boot"),
	}
	for _, dir := range []string{root, store.queueDir, store.rejectedDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating receipt directory: %w", err)
		}
	}
	if err := store.loadOrCreateKey(); err != nil {
		return nil, err
	}
	store.sequence = store.loadSequence()
	return store, nil
}

func (s *Store) SignerKeyID() string     { return s.signerKeyID }
func (s *Store) PublicKeyBase64() string { return base64.StdEncoding.EncodeToString(s.publicKey) }

// SignBytes signs an auxiliary endpoint artifact with the same durable key
// used for application receipts. The key never leaves the Store; callers use
// this for owner-only local integrity checks such as the last-known-good
// policy cache.
func (s *Store) SignBytes(payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, payload))
}

// VerifyBytes verifies an auxiliary endpoint artifact against this Store's
// durable public key.
func (s *Store) VerifyBytes(payload []byte, signatureBase64 string) bool {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	return err == nil && ed25519.Verify(s.publicKey, payload, signature)
}

func (s *Store) Enqueue(input Input) (Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sequence++
	envelope := Envelope{
		SchemaVersion:       SchemaVersion,
		ReceiptID:           randomID("receipt"),
		SignerKeyID:         s.signerKeyID,
		BootID:              s.bootID,
		Sequence:            s.sequence,
		ArtifactVersion:     s.artifactVersion,
		CallID:              input.CallID,
		AttemptID:           input.AttemptID,
		DecisionID:          input.DecisionID,
		ClientName:          input.ClientName,
		ConfigSourceHash:    input.ConfigSourceHash,
		Phase:               input.Phase,
		ServerName:          input.ServerName,
		ToolName:            input.ToolName,
		PolicyDecision:      input.PolicyDecision,
		EvaluationStatus:    input.EvaluationStatus,
		RequiredDisposition: input.RequiredDisposition,
		AppliedDisposition:  input.AppliedDisposition,
		EffectiveMode:       input.EffectiveMode,
		RouteRevision:       input.RouteRevision,
		PolicyHash:          input.PolicyHash,
		RawSnapshotID:       input.RawSnapshotID,
		EffectiveViewHash:   input.EffectiveViewHash,
		Dispatched:          input.Dispatched,
		ResultReceived:      input.ResultReceived,
		ResultReturned:      input.ResultReturned,
		ResponseWithheld:    input.ResponseWithheld,
		Terminal:            input.Terminal,
		FailureReason:       input.FailureReason,
		OccurredAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	canonical, err := CanonicalBytes(envelope)
	if err != nil {
		return Envelope{}, err
	}
	envelope.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, canonical))
	data, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, err
	}
	filename := fmt.Sprintf("%020d-%s.json", envelope.Sequence, envelope.ReceiptID)
	if err := atomicWrite(filepath.Join(s.queueDir, filename), append(data, '\n'), 0o600); err != nil {
		return Envelope{}, fmt.Errorf("persisting receipt: %w", err)
	}
	if err := atomicWrite(filepath.Join(s.root, "sequence"), []byte(strconv.FormatUint(s.sequence, 10)+"\n"), 0o600); err != nil {
		return Envelope{}, fmt.Errorf("persisting receipt sequence: %w", err)
	}
	return envelope, nil
}

func (s *Store) Peek(limit int) ([]Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.queueDir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	receipts := make([]Envelope, 0, limit)
	for _, entry := range entries[:limit] {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.queueDir, entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		var envelope Envelope
		if decodeErr := json.Unmarshal(data, &envelope); decodeErr != nil {
			return nil, decodeErr
		}
		receipts = append(receipts, envelope)
	}
	return receipts, nil
}

// Resolve removes accepted/duplicate receipts and quarantines terminal rejects.
// Retryable receipts remain in the queue.
func (s *Store) Resolve(statusByReceiptID map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.queueDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		parts := strings.SplitN(strings.TrimSuffix(entry.Name(), ".json"), "-", 2)
		if len(parts) != 2 {
			continue
		}
		status := statusByReceiptID[parts[1]]
		source := filepath.Join(s.queueDir, entry.Name())
		switch status {
		case "accepted", "duplicate":
			if err := os.Remove(source); err != nil && !os.IsNotExist(err) {
				return err
			}
		case "rejected", "conflicted":
			if err := os.Rename(source, filepath.Join(s.rejectedDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func CanonicalBytes(envelope Envelope) ([]byte, error) {
	envelope.SignatureBase64 = ""
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	var value map[string]interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buffer.Bytes()), nil
}

func Verify(envelope Envelope, publicKey ed25519.PublicKey) bool {
	signature, err := base64.StdEncoding.DecodeString(envelope.SignatureBase64)
	if err != nil {
		return false
	}
	canonical, err := CanonicalBytes(envelope)
	return err == nil && ed25519.Verify(publicKey, canonical, signature)
}

func (s *Store) loadOrCreateKey() error {
	path := filepath.Join(s.root, "signing-key.json")
	if err := s.loadKey(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		// Another MCP client process can have exclusively created the key file
		// but not finished its durable write yet. Treat a present, temporarily
		// incomplete file as a concurrent create and wait for the complete key.
		return s.loadKeyAfterConcurrentCreate(path)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.publicKey = publicKey
	s.privateKey = privateKey
	s.signerKeyID = signerID(publicKey)
	saved := keyFile{
		Algorithm:        "ed25519",
		SignerKeyID:      s.signerKeyID,
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(publicKey),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	if err := exclusiveWrite(path, append(data, '\n'), 0o600); err != nil {
		if os.IsExist(err) {
			// MCP clients often start in parallel. The process that created the
			// endpoint key first is authoritative; every other process must load
			// that exact key instead of overwriting it with a second identity.
			return s.loadKeyAfterConcurrentCreate(path)
		}
		return err
	}
	return nil
}

func (s *Store) loadKeyAfterConcurrentCreate(path string) error {
	var lastErr error
	for attempt := 0; attempt < 100; attempt++ {
		if err := s.loadKey(path); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("loading concurrently created receipt signing key: %w", lastErr)
}

func (s *Store) loadKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var saved keyFile
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("parsing receipt signing key: %w", err)
	}
	publicKey, pubErr := base64.StdEncoding.DecodeString(saved.PublicKeyBase64)
	privateKey, privErr := base64.StdEncoding.DecodeString(saved.PrivateKeyBase64)
	if pubErr != nil || privErr != nil || len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("receipt signing key is invalid")
	}
	s.publicKey = ed25519.PublicKey(publicKey)
	s.privateKey = ed25519.PrivateKey(privateKey)
	s.signerKeyID = signerID(s.publicKey)
	if saved.SignerKeyID != s.signerKeyID {
		return fmt.Errorf("receipt signing key id does not match public key")
	}
	return nil
}

func (s *Store) loadSequence() uint64 {
	data, err := os.ReadFile(filepath.Join(s.root, "sequence"))
	if err != nil {
		return 0
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".receipt-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
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
	return os.Rename(tmpPath, path)
}

func exclusiveWrite(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func signerID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(sum[:])
}

func randomID(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}
