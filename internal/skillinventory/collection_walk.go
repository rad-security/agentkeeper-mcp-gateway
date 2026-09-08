package skillinventory

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Only metadata is inspected here. Pattern matching never descends into an
// unrelated chat/upload directory. Handles remain bound across path replacement.
func enumerateSource(ctx context.Context, dir *os.File, rel, pattern []string, recursive bool, source *SourceV2, entries *int, visit func([]string, *os.File)) {
	if ctx.Err() != nil {
		markSource(source, "scan_deadline")
		return
	}
	if !recursive && len(pattern) == 0 {
		visit(rel, dir)
		return
	}
	if recursive && source.SourceClass == "persistent_standalone" && len(rel) > 0 {
		file, err := openAssessmentChild(dir, "SKILL.md", false)
		if err == nil {
			file.Close()
			visit(rel, dir)
			return // Package resources are assessed, never inventoried as skills.
		}
		if !os.IsNotExist(err) {
			markSource(source, "skill_file_unavailable")
			return
		}
	}
	if recursive && source.SourceClass != "persistent_standalone" && len(rel) >= 2 && rel[len(rel)-2] == "skills" {
		visit(rel, dir)
		return
	}
	if len(rel) >= 8 {
		markSource(source, "depth_limit")
		return
	}
	before, err := dir.Stat()
	if err != nil {
		markSource(source, "directory_unavailable")
		return
	}
	if !recursive && pattern[0] != "*" && pattern[0] != "local_*" {
		// Known components do not require listing unrelated files in a session.
		child, err := openAssessmentChild(dir, pattern[0], true)
		if err == nil {
			enumerateSource(ctx, child, append(append([]string{}, rel...), pattern[0]), pattern[1:], false, source, entries, visit)
			child.Close()
		} else if !os.IsNotExist(err) {
			markSource(source, "unreadable_or_changed_entry")
		}
		after, err := dir.Stat()
		if err != nil || !before.ModTime().Equal(after.ModTime()) {
			markSource(source, "changed_during_scan")
		}
		return
	}
	for {
		if ctx.Err() != nil {
			markSource(source, "scan_deadline")
			return
		}
		batch, readErr := dir.ReadDir(100)
		for _, entry := range batch {
			if ctx.Err() != nil {
				markSource(source, "scan_deadline")
				return
			}
			*entries++
			if *entries > 12000 {
				markSource(source, "entry_limit")
				return
			}
			name := entry.Name()
			if !recursive && !matchComponent(name, pattern[0]) {
				continue
			}
			if !validAssessmentRelativePath(name) || len(name) > 256 {
				markSource(source, "invalid_filename")
				continue
			}
			info, err := entry.Info()
			if err != nil {
				markSource(source, "unreadable_entry")
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				markSource(source, "symlink_skipped")
				continue
			}
			if !info.IsDir() {
				continue
			}
			child, err := openAssessmentChild(dir, name, true)
			if err != nil {
				markSource(source, "unreadable_or_changed_entry")
				continue
			}
			opened, err := child.Stat()
			if err != nil || !os.SameFile(info, opened) {
				child.Close()
				markSource(source, "changed_during_scan")
				continue
			}
			next := pattern
			if !recursive {
				next = pattern[1:]
			}
			enumerateSource(ctx, child, append(append([]string{}, rel...), name), next, recursive, source, entries, visit)
			child.Close()
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			markSource(source, "unreadable_directory")
			break
		}
	}
	after, err := dir.Stat()
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		markSource(source, "changed_during_scan")
	}
}

func openCollectionRoot(path, home, cwd string) (*os.File, error) {
	anchor, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	if cwd != "" {
		project, err := filepath.Abs(cwd)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(path, project+string(filepath.Separator)) {
			anchor = project
		}
	}
	rel, err := filepath.Rel(anchor, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("source outside authorized root")
	}
	dir, err := openAssessmentRoot(anchor)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "." {
			continue
		}
		child, err := openAssessmentChild(dir, component, true)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = child
	}
	return dir, nil
}

func matchComponent(name, pattern string) bool {
	return pattern == "*" || name == pattern || (pattern == "local_*" && strings.HasPrefix(name, "local_") && len(name) > 6)
}

func openCandidate(root *os.File, candidate packageCandidate) (*os.File, error) {
	dir, err := reopenAssessmentDir(root)
	if err != nil {
		return nil, err
	}
	for _, component := range candidate.rel {
		child, err := openAssessmentChild(dir, component, true)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = child
	}
	info, err := dir.Stat()
	if err != nil || !os.SameFile(candidate.info, info) {
		dir.Close()
		return nil, fmt.Errorf("package replaced during enumeration")
	}
	return dir, nil
}

// Upload directories also contain unrelated user files. Only the named SKILL.md
// is read; its digest cannot stand in for an immutable full package identity.
func assessUploadedSkill(ctx context.Context, opener func() (*os.File, error), limits AssessmentLimits) (PackageAssessment, string) {
	a := notAssessed("unverified_upload_package_boundary")
	dir, err := opener()
	if err != nil {
		return a, ""
	}
	defer dir.Close()
	f, err := openAssessmentChild(dir, "SKILL.md", false)
	if err != nil {
		return a, ""
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || before.Size() > limits.MaxFileBytes || before.Size() > limits.MaxTotalBytes {
		return a, ""
	}
	bound := limits.MaxFileBytes
	if limits.MaxTotalBytes < bound {
		bound = limits.MaxTotalBytes
	}
	data, err := io.ReadAll(io.LimitReader(f, bound+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(data)) > bound || after.Size() != int64(len(data)) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || ctx.Err() != nil {
		return a, ""
	}
	a.Status = "partial"
	a.FilesScanned, a.BytesScanned = 1, int64(len(data))
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		a.Reasons = append(a.Reasons, "binary_content_unassessed")
		return a, opaqueID(string(data))
	}
	a.Findings, _ = assessSkillText(ctx, "SKILL.md", string(data), limits.MaxFindings)
	for _, finding := range a.Findings {
		if finding.Severity == "high" {
			a.Risk = "high"
			break
		}
		if finding.Severity == "medium" {
			a.Risk = "medium"
		}
	}
	return a, opaqueID(string(data))
}
