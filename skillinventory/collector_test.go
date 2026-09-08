package skillinventory_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/skillinventory"
)

func TestNativeConsumerCanCollectAndChunkWithoutCommandInitialization(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure collection unsupported")
	}
	root := t.TempDir()
	dir := filepath.Join(root, ".claude/skills/example")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Example"), 0600); err != nil {
		t.Fatal(err)
	}
	collection, err := skillinventory.Collect(context.Background(), skillinventory.ScanOptions{Home: root}, 0)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := skillinventory.Chunk(collection, "36de3ba8-1c8a-44a8-bc5a-73b02b66fcdc", 1, "de23e665-3cd3-44ca-9071-ea34b754db22")
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || len(chunks[0].Observations) != 1 || chunks[0].Observations[0].Assessment.Status != "complete" {
		t.Fatal("collector adapter lost package evidence")
	}
}
