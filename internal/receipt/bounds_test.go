package receipt

import (
	"fmt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/fslock"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestReceiptCapacityRetainsPendingAndRecoversAfterAck(t *testing.T) {
	s, err := NewStore(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureQueueLimits(1, 1024*1024)
	first, err := s.Enqueue(Input{CallID: "one", AttemptID: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(Input{CallID: "two", AttemptID: "two"}); err == nil {
		t.Fatal("capacity bypassed")
	}
	q, err := s.Peek(100)
	if err != nil || len(q) != 1 || q[0].ReceiptID != first.ReceiptID {
		t.Fatalf("pending receipt lost: %v %v", q, err)
	}
	if err := s.Resolve(map[string]string{first.ReceiptID: "accepted"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(Input{CallID: "three", AttemptID: "three"}); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedReceiptQuarantineDoesNotStallValidLaterReceipt(t *testing.T) {
	s, err := NewStore(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	good, err := s.Enqueue(Input{CallID: "good", AttemptID: "good"})
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(s.queueDir, "00000000000000000000-bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	q, err := s.Peek(1)
	if err != nil || len(q) != 1 || q[0].ReceiptID != good.ReceiptID {
		t.Fatalf("queue stalled: %v %v", q, err)
	}
	if _, err := os.Stat(filepath.Join(s.rejectedDir, filepath.Base(bad))); err != nil {
		t.Fatal("corrupt evidence not quarantined", err)
	}
}
func TestConcurrentReceiptStoresCannotOverrunCapacity(t *testing.T) {
	root := t.TempDir()
	stores := make([]*Store, 8)
	for i := range stores {
		var err error
		stores[i], err = NewStore(root, "test")
		if err != nil {
			t.Fatal(err)
		}
		stores[i].ConfigureQueueLimits(3, 1024*1024)
	}
	var wait sync.WaitGroup
	for _, s := range stores {
		wait.Add(1)
		go func(s *Store) {
			defer wait.Done()
			_, _ = s.Enqueue(Input{CallID: "synthetic", AttemptID: "synthetic"})
		}(s)
	}
	wait.Wait()
	q, err := stores[0].Peek(100)
	if err != nil || len(q) != 3 {
		t.Fatalf("shared capacity failed: count=%d err=%v", len(q), err)
	}
}

func TestReceiptLockContentionReturnsWithinBound(t *testing.T) {
	s, err := NewStore(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	release, err := fslock.Acquire(filepath.Join(s.root, "queue.lock"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = s.Enqueue(Input{CallID: "contention"})
	elapsed := time.Since(start)
	release()
	if err == nil || elapsed > 750*time.Millisecond {
		t.Fatalf("lock did not fail promptly: %s %v", elapsed, err)
	}
	if _, err := s.Enqueue(Input{CallID: "recovered"}); err != nil {
		t.Fatal(err)
	}
	t.Logf("contended receipt attempt returned in %s; next receipt recovered", elapsed)
}
func TestReceiptUnexpectedChangeRepairsUsageWithoutScanningActionPath(t *testing.T) {
	s, err := NewStore(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.queueDir, "external.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(Input{CallID: "stale"}); err == nil {
		t.Fatal("stale usage silently trusted")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := s.Enqueue(Input{CallID: "recovered"}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("usage did not recover")
		}
		time.Sleep(time.Millisecond)
	}
	usage, err := s.QueueStatus()
	if err != nil || usage.Events != 2 {
		t.Fatalf("wrong repaired usage %+v %v", usage, err)
	}
}
func TestReceiptLargeBacklogHotPath(t *testing.T) {
	if os.Getenv("AK_RUNTIME_BACKLOG_BENCH") != "1" {
		t.Skip("explicit filesystem backlog benchmark")
	}
	root := t.TempDir()
	s, err := NewStore(root, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100000; i++ {
		if err := os.WriteFile(filepath.Join(s.queueDir, fmt.Sprintf("%020d-seed.json", i)), []byte("synthetic backlog record"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	s, err = NewStore(root, "test")
	if err != nil {
		t.Fatal(err)
	}
	cold := time.Since(start)
	s.ConfigureQueueLimits(100100, 256*1024*1024)
	samples := make([]time.Duration, 50)
	for i := range samples {
		start := time.Now()
		if _, err := s.Enqueue(Input{CallID: "measured", AttemptID: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
		samples[i] = time.Since(start)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("100000-file backlog: startup reconciliation=%s enqueue p50=%s p95=%s max=%s", cold, samples[25], samples[47], samples[49])
	if samples[49] > 500*time.Millisecond {
		t.Fatalf("hot path unexpectedly slow: %s", samples[49])
	}
	usage, err := s.QueueStatus()
	if err != nil || usage.Events != 100050 {
		t.Fatalf("usage %+v err %v", usage, err)
	}
}
