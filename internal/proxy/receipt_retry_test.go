package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/receipt"
)

// Another Gateway process holding the shared receipt queue past one lock wait
// must not cost this call its signed receipt.
func TestTerminalReceiptWaitsOutABusyQueue(t *testing.T) {
	root := t.TempDir()
	store, err := receipt.NewStore(root, "test")
	if err != nil {
		t.Fatal(err)
	}
	release, err := fslock.Acquire(filepath.Join(root, "queue.lock"))
	if err != nil {
		t.Fatal(err)
	}
	// Held for longer than one lock wait, released well within three.
	go func() {
		time.Sleep(900 * time.Millisecond)
		release()
	}()

	p := &Proxy{config: Config{ReceiptStore: store}}
	err = p.enqueueReceipt(receipt.Input{
		CallID: "call-1", AttemptID: "attempt-1", DecisionID: "decision-1",
		ClientName: "claude-code", Phase: "terminal", ServerName: "notes", ToolName: "save_note",
		PolicyDecision: "pass", EvaluationStatus: "evaluated", RequiredDisposition: "dispatch",
		AppliedDisposition: "result_returned", EffectiveMode: "observe", Terminal: true,
	})
	if err != nil {
		t.Fatalf("receipt dropped while another process held the queue: %v", err)
	}
	queued, err := store.Peek(10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("want one queued receipt, got %d (%v)", len(queued), err)
	}
}
