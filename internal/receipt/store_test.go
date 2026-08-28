package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStorePersistsAndVerifiesSignedReceipts(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Enqueue(Input{
		CallID: "call-1", AttemptID: "attempt-1", Phase: "terminal",
		ServerName: "atlas", ToolName: "delete_account",
		PolicyDecision: "block", EvaluationStatus: "evaluated",
		RequiredDisposition: "forward", AppliedDisposition: "result_returned",
		EffectiveMode: "observe", Dispatched: true, ResultReceived: true,
		ResultReturned: true, Terminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(store.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(receipt, ed25519.PublicKey(publicBytes)) {
		t.Fatal("receipt signature did not verify")
	}
	queued, err := store.Peek(100)
	if err != nil || len(queued) != 1 {
		t.Fatalf("queued=%d err=%v", len(queued), err)
	}
	if queued[0].AppliedDisposition != "result_returned" || queued[0].Sequence != 1 {
		t.Fatalf("unexpected queued receipt: %+v", queued[0])
	}
	if info, err := os.Stat(filepath.Join(root, "signing-key.json")); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode=%o, want 0600", info.Mode().Perm())
	}
}

func TestStoreSurvivesRestartAndResolvesPerItemAcknowledgments(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.Enqueue(Input{CallID: "call-1", AttemptID: "a-1", Phase: "terminal", Terminal: true})
	second, _ := store.Enqueue(Input{CallID: "call-2", AttemptID: "a-2", Phase: "terminal", Terminal: true})

	restarted, err := NewStore(root, "0.2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	queued, err := restarted.Peek(100)
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued after restart=%d err=%v", len(queued), err)
	}
	if restarted.SignerKeyID() != store.SignerKeyID() {
		t.Fatal("signer identity changed across restart")
	}
	if err := restarted.Resolve(map[string]string{
		first.ReceiptID:  "accepted",
		second.ReceiptID: "retryable",
	}); err != nil {
		t.Fatal(err)
	}
	queued, err = restarted.Peek(100)
	if err != nil || len(queued) != 1 || queued[0].ReceiptID != second.ReceiptID {
		t.Fatalf("partial ack queue=%+v err=%v", queued, err)
	}
	third, err := restarted.Enqueue(Input{CallID: "call-3", AttemptID: "a-3", Phase: "terminal", Terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	if third.Sequence != 3 {
		t.Fatalf("sequence=%d, want 3", third.Sequence)
	}
}

func TestConcurrentStoresShareOneSigningIdentity(t *testing.T) {
	root := t.TempDir()
	const count = 12
	stores := make([]*Store, count)
	errs := make([]error, count)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			stores[index], errs[index] = NewStore(root, "0.2.0-test")
		}(index)
	}
	close(start)
	wait.Wait()

	var signerID string
	for index := range stores {
		if errs[index] != nil {
			t.Fatalf("store %d failed: %v", index, errs[index])
		}
		if signerID == "" {
			signerID = stores[index].SignerKeyID()
		}
		if stores[index].SignerKeyID() != signerID {
			t.Fatalf("store %d signer=%s, want %s", index, stores[index].SignerKeyID(), signerID)
		}
	}
}
