//go:build darwin || linux

package skillinventory

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAssessmentSkipsFIFOWithoutBlocking(t *testing.T) {
	root := assessmentFixture(t, map[string]string{"SKILL.md": "example"})
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	a := AssessPackage(context.Background(), root, DefaultAssessmentLimits())
	if a.Status != "partial" || a.DigestStatus != "incomplete" || a.FilesScanned != 1 {
		t.Fatalf("special file was not skipped: %+v", a)
	}
}

func TestAssessmentDirectoryHandleSurvivesSymlinkSwap(t *testing.T) {
	root := assessmentFixture(t, map[string]string{"SKILL.md": "original harmless content"})
	outside := assessmentFixture(t, map[string]string{"SKILL.md": "private outside content"})
	dir, err := openAssessmentRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(moved) })
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	file, err := openAssessmentChild(dir, "SKILL.md", false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original harmless content" {
		t.Fatal("descriptor traversal escaped the original root")
	}
}
